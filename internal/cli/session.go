package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MIERAI/security-platform/internal/cli/explain"
	"github.com/MIERAI/security-platform/internal/cli/flags"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Read limits: inputs are read through these bounds (docs/go.md, "Bounded reads").
const (
	maxInstance = 4 << 20   // instance config
	maxLedger   = 512 << 20 // ledger.json, tracker/items.json (100k findings are well below)
	maxDocument = 64 << 20  // scorecard, job states, latest findings documents
	maxSecret   = 64 << 10  // a secret file (token, webhook URL)
)

// session is one command's view of the data directory (cli/sp.py Ctx).
type session struct {
	env          Env
	texts        *explain.Texts
	args         *flags.Result
	data         string // absolute
	instancePath string
	inst         *pyvalue.Map // loaded on first use
}

// locate finds the data directory and the instance config (contract §1).
func (s *session) locate() error {
	d := s.args.String("data")
	if d == "" {
		d = s.env.Getenv("SP_DATA")
	}
	if d == "" {
		return die(ExitUsage, "where is your data directory? pass --data DIR or set SP_DATA (create one with `sp init DIR`)")
	}
	abs, err := filepath.Abs(expandUser(d, s.env.Getenv))
	if err != nil {
		return die(ExitUsage, "%s: %v", d, err)
	}
	s.data = abs
	if fi, err := os.Stat(abs); err != nil || !fi.IsDir() {
		return die(ExitUsage, "%s does not exist (create it with `sp init %s`)", abs, d)
	}
	inst := s.args.String("instance")
	if inst == "" {
		inst = s.env.Getenv("SP_INSTANCE")
	}
	if inst == "" {
		inst = filepath.Join(abs, "instance.yaml")
		for _, f := range []string{"instance.yaml", "instance.yml", "instance.json"} {
			if _, err := os.Stat(filepath.Join(abs, f)); err == nil {
				inst = filepath.Join(abs, f)
				break
			}
		}
	}
	s.instancePath = inst
	return nil
}

// instance returns the instance config, a mapping (an empty document is an empty one).
func (s *session) instance() (*pyvalue.Map, error) {
	if s.inst != nil {
		return s.inst, nil
	}
	b, err := readLimited(expandUser(s.instancePath, s.env.Getenv), maxInstance)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, die(ExitUsage, "no instance config at %s (sp init writes a starter one)", s.instancePath)
	}
	if err != nil {
		return nil, die(ExitUsage, "%s: %v", s.instancePath, err)
	}
	v, err := pyvalue.DecodeYAML(b)
	if err != nil {
		return nil, die(ExitUsage, "%s: not a valid YAML or JSON document: %v", s.instancePath, oneLine(err))
	}
	switch m := v.(type) {
	case nil:
		s.inst = pyvalue.NewMap()
	case *pyvalue.Map:
		s.inst = m
	default:
		return nil, die(ExitUsage, "%s: the instance config must be a mapping, not a %s", s.instancePath, pyvalue.TypeName(v))
	}
	return s.inst, nil
}

// readJSON reads a JSON document; ok is false when the file does not exist.
func (s *session) readJSON(path string, limit int64) (any, bool, error) {
	b, err := readLimited(path, limit)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, die(ExitUsage, "%s: %v", path, err)
	}
	v, err := pyvalue.DecodeJSON(b)
	if err != nil {
		return nil, true, die(ExitUsage, "%s: not valid JSON: %v", path, oneLine(err))
	}
	return v, true, nil
}

// ledgerDoc is ledger.json: the entries in file order, the SLIs and whether any collector ran.
type ledgerDoc struct {
	entries    []*pyvalue.Map
	byID       map[string]*pyvalue.Map
	keys       []string // entry keys in file order
	sli        *pyvalue.Map
	collectors bool
}

func (s *session) ledger() (*ledgerDoc, error) {
	p := filepath.Join(s.data, "ledger.json")
	v, found, err := s.readJSON(p, maxLedger)
	led := &ledgerDoc{byID: map[string]*pyvalue.Map{}, sli: pyvalue.NewMap()}
	if err != nil || !found {
		return led, err
	}
	m, ok := v.(*pyvalue.Map)
	if !ok {
		return nil, die(ExitUsage, "%s: not a ledger (a JSON object)", p)
	}
	if ents, ok := m.Value("entries").(*pyvalue.Map); ok {
		for _, k := range ents.Keys() {
			e, ok := ents.Value(k).(*pyvalue.Map)
			if !ok {
				return nil, die(ExitUsage, "%s: entry %s is not an object", p, k)
			}
			led.entries = append(led.entries, e)
			led.keys = append(led.keys, k)
			led.byID[k] = e
		}
	}
	if sli, ok := m.Value("sli").(*pyvalue.Map); ok {
		led.sli = sli
	}
	led.collectors = pyvalue.Truthy(m.Value("collectors"))
	return led, nil
}

// items returns tracker/items.json by finding id (a mapping {"items": {...}}, the mapping itself, or a list).
func (s *session) items() (map[string]*pyvalue.Map, error) {
	p := filepath.Join(s.data, "tracker", "items.json")
	v, found, err := s.readJSON(p, maxLedger)
	if err != nil || !found {
		return map[string]*pyvalue.Map{}, err
	}
	if d, ok := v.(*pyvalue.Map); ok && d.Has("items") {
		v = d.Value("items")
	}
	switch d := v.(type) {
	case *pyvalue.Map:
		return itemsByKey(d), nil
	case []any:
		return itemsByID(d), nil
	}
	return nil, die(ExitUsage, "%s: not a tracker document", p)
}

func itemsByKey(d *pyvalue.Map) map[string]*pyvalue.Map {
	out := map[string]*pyvalue.Map{}
	for _, k := range d.Keys() {
		if it, ok := d.Value(k).(*pyvalue.Map); ok {
			out[k] = it
		}
	}
	return out
}

func itemsByID(d []any) map[string]*pyvalue.Map {
	out := map[string]*pyvalue.Map{}
	for _, x := range d {
		if it, ok := x.(*pyvalue.Map); ok {
			out[pyvalue.Str(it.Value("id"))] = it
		}
	}
	return out
}

// scorecard returns the newest scorecard document, nil when there is none or it is unreadable.
func (s *session) scorecard() *pyvalue.Map {
	for _, rel := range []string{"scorecard/latest.json", "scorecard.json", "reports/scorecard.json"} {
		v, found, err := s.readJSON(filepath.Join(s.data, filepath.FromSlash(rel)), maxDocument)
		if !found && err == nil {
			continue
		}
		m, _ := v.(*pyvalue.Map) // unreadable or not an object: no scorecard (as the reference)
		return m
	}
	return nil
}

// jobStates returns state/runner/<job>.json by job name (unreadable files are left out, as by the reference).
func (s *session) jobStates() map[string]*pyvalue.Map {
	out := map[string]*pyvalue.Map{}
	paths, err := filepath.Glob(filepath.Join(s.data, "state", "runner", "*.json"))
	if err != nil {
		return out
	}
	for _, p := range paths {
		n := strings.TrimSuffix(filepath.Base(p), ".json")
		if n == "sinks" {
			continue
		}
		if v, _, err := s.readJSON(p, maxDocument); err == nil {
			if m, ok := v.(*pyvalue.Map); ok {
				out[n] = m
			}
		}
	}
	return out
}

// jobs returns runner.jobs of the instance: names in config order and each job's mapping (empty for a null job).
func jobsOf(inst *pyvalue.Map) ([]string, map[string]*pyvalue.Map) {
	runner, _ := inst.Value("runner").(*pyvalue.Map)
	jobs := map[string]*pyvalue.Map{}
	if runner == nil {
		return nil, jobs
	}
	jm, _ := runner.Value("jobs").(*pyvalue.Map)
	if jm == nil {
		return nil, jobs
	}
	for _, n := range jm.Keys() {
		j, _ := jm.Value(n).(*pyvalue.Map)
		if j == nil {
			j = pyvalue.NewMap()
		}
		jobs[n] = j
	}
	return jm.Keys(), jobs
}

// readLimited reads a file through a size limit.
func readLimited(path string, limit int64) (b []byte, err error) {
	f, err := os.Open(path) // #nosec G304 -- the user's own data directory and config
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close: %w", cerr)
		}
	}()
	b, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return b, nil
}

// expandUser replaces a leading ~ or ~/ with $HOME (Python's os.path.expanduser for the current user).
func expandUser(p string, getenv func(string) string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") && !strings.HasPrefix(p, `~\`) {
		return p
	}
	home := getenv("HOME")
	if home == "" {
		home = getenv("USERPROFILE")
	}
	if home == "" {
		return p
	}
	return home + p[1:]
}

func oneLine(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
