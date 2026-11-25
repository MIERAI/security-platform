package events

import (
	"context"
	"crypto/sha1" // #nosec G505 -- the edge hash only tells shipped lines apart (as the reference's state), not a security use
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/execad"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const maxSecretFile = 64 << 10

// durRx is ship.py parse_dur's form. Never written after initialisation.
var durRx = regexp.MustCompile(`^(\d+)([smhd])$`)

// fiScript prints a file of the target (or __absent__), "~/" resolved on the target. The reference's one use of a
// shell: a fixed script, the path is its first argument ("$1"), never part of the script text.
const fiScript = `p="$1"; case "$p" in "~/"*) p="$HOME/${p#\~/}";; esac; ` +
	`if [ -f "$p" ]; then cat -- "$p"; else echo __absent__; fi`

// deps are what a source reads from the process.
type deps struct {
	getenv    func(string) string
	home      string
	loc       *time.Location
	transport http.RoundTripper // nil: the default
}

// client is an HTTP client that may POST only to posts.
func (d *deps) client(posts ...string) *http.Client { return newHTTP(d.transport, posts...) }

// source is one configured source of a run.
type source struct {
	cfg, state *pyvalue.Map
	now        float64
	first      bool
	host       any
	label      string
	d          *deps
	collect    func(ctx context.Context) ([]*event, *pyvalue.Map, error)
}

func newSource(cfg, state *pyvalue.Map, now float64, d *deps) (*source, error) {
	s := &source{cfg: cfg, state: state, now: now, first: state.Len() == 0, host: cfg.Value("name"), d: d}
	if cfg.Has("host") {
		s.host = cfg.Value("host")
	}
	typ := cfg.Value("type")
	if !cfg.Has("type") {
		return nil, keyError("type")
	}
	switch typ {
	case "command":
		s.label, s.collect = "auth", s.command
	case "file-integrity":
		s.label, s.collect = "auth", s.fileIntegrity
	case "github-account":
		s.label, s.collect = "codehost", s.github
	case "tailscale-audit":
		s.label, s.collect = "overlay-network", s.tailscale
	default:
		return nil, pyErr("KeyError", pyvalue.Repr(typ))
	}
	return s, nil
}

// parseDur is ship.py parse_dur: "<n>[smhd]" in seconds.
func parseDur(v any) (float64, error) {
	m := durRx.FindStringSubmatch(pyvalue.Str(v))
	if m == nil {
		return 0, pyErr("ValueError", "duration "+pyvalue.Repr(v))
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, pyErr("ValueError", "duration "+pyvalue.Repr(v))
	}
	return n * map[string]float64{"s": 1, "m": 60, "h": 3600, "d": 86400}[m[2]], nil
}

func (s *source) getOr(key string, def any) any { return s.cfg.GetOr(key, def) }

func (s *source) intOr(key string, def int64) (int64, error) {
	n, err := pyvalue.ToInt(s.getOr(key, def))
	if err != nil {
		return 0, pyErr("ValueError", err.Error())
	}
	return n, nil
}

func (s *source) executor() (*execad.Executor, error) {
	cfg := s.cfg.Value("exec")
	if !pyvalue.Truthy(cfg) {
		cfg = nil
	}
	e, err := execad.FromConfig(cfg)
	if err != nil {
		return nil, pyErr("NotImplementedError", err.Error())
	}
	return e, nil
}

// readSecret is ship.py read_secret: a file readable by group or others is refused; the secret, stripped.
func readSecret(p, home string) (string, error) {
	p = rundoc.ExpandUser(p, home)
	st, err := os.Stat(filepath.Clean(p))
	if err != nil {
		return "", osError(err, p)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", pyErr("PermissionError", p+": readable by group/others (chmod 600)")
	}
	return readSmall(p)
}

func readSmall(p string) (secret string, err error) {
	f, err := os.Open(filepath.Clean(p))
	if err != nil {
		return "", osError(err, p)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			secret, err = "", osError(cerr, p)
		}
	}()
	data, err := io.ReadAll(io.LimitReader(f, maxSecretFile+1))
	if err != nil || len(data) > maxSecretFile {
		return "", pyErr("OSError", p+": unreadable or too large for a secret")
	}
	return pyStrip(string(data)), nil
}

// command runs argv (local or over ssh) and parses every output line, from the cursor on.
func (s *source) command(ctx context.Context) ([]*event, *pyvalue.Map, error) {
	pname := s.getOr("parser", "syslog")
	parse, ok := parsers()[pyvalue.Str(pname)]
	if _, isText := pname.(string); !ok || !isText {
		return nil, nil, pyErr("KeyError", pyvalue.Repr(pname))
	}
	cursor, hasCursor := pyvalue.ToFloat64(s.state.Value("cursor"))
	since := cursor
	if !hasCursor {
		look, err := parseDur(s.getOr("lookback", "1h"))
		if err != nil {
			return nil, nil, err
		}
		since = s.now - look
	}
	out, err := s.runCommand(ctx, since)
	if err != nil {
		return nil, nil, err
	}
	edge := stringSet(s.state.Value("edge"))
	evs, err := s.parseOutput(out, parse, cursor, hasCursor, edge)
	if err != nil {
		return nil, nil, err
	}
	next := s.state.Copy()
	switch {
	case len(evs) > 0:
		advance(next, evs, cursor, hasCursor, edge)
	case !hasCursor:
		next.Set("cursor", since)
	}
	s.markNovel(evs, next)
	return evs, next, nil
}

func (s *source) runCommand(ctx context.Context, since float64) (string, error) {
	argvCfg, ok := s.cfg.Get("argv")
	if !ok {
		return "", keyError("argv")
	}
	var argv []string
	for _, a := range rundoc.List(argvCfg) {
		a := pyvalue.Str(a)
		a = strings.ReplaceAll(a, "{since_epoch}", strconv.FormatFloat(since, 'f', 3, 64))
		argv = append(argv, strings.ReplaceAll(a, "{since_local}", fmtLocal(since, s.d.loc)))
	}
	timeout, err := s.intOr("timeout", 120)
	if err != nil {
		return "", err
	}
	ex, err := s.executor()
	if err != nil {
		return "", err
	}
	res := ex.Run(ctx, argv, nil, time.Duration(timeout)*time.Second, false)
	if res.RC != 0 {
		return "", pyErr("RuntimeError", fmt.Sprintf("command rc=%d: %s", res.RC, lastChars(pyStrip(res.Err), 200)))
	}
	return universalNewlines(res.Out), nil
}

// universalNewlines is what a text-mode pipe reads: \r\n and \r become \n.
func universalNewlines(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

// lastChars is s[-n:].
func lastChars(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[len(r)-n:])
}

func (s *source) parseOutput(out string, parse parser, cursor float64, hasCursor bool, edge map[string]bool) ([]*event, error) {
	var evs []*event
	for _, line := range splitLines(out) {
		if pyStrip(line) == "" {
			continue
		}
		e, err := parse(line, s.now, s.cfg, s.d.loc)
		if err != nil {
			return nil, err
		}
		if e == nil {
			continue
		}
		sum := sha1.Sum([]byte(e.line)) // #nosec G401 -- see the import
		e.hash = hex.EncodeToString(sum[:])[:16]
		if hasCursor && (e.ts < cursor || e.ts == cursor && edge[e.hash]) {
			continue
		}
		evs = append(evs, e)
	}
	return evs, nil
}

// markNovel marks successful logins from a source address not seen before for (host, user); the first run of a
// source records the addresses and marks nothing novel.
func (s *source) markNovel(evs []*event, next *pyvalue.Map) {
	seen := map[string]map[string]bool{}
	var order []string
	old := rundoc.MapOr(s.state.Value("seen"))
	for _, k := range old.Keys() {
		seen[k] = stringSet(old.Value(k))
		order = append(order, k)
	}
	byTime := append([]*event(nil), evs...)
	sort.SliceStable(byTime, func(i, j int) bool { return byTime[i].ts < byTime[j].ts })
	for _, e := range byTime {
		ip, _ := e.get("src_ip").(string)
		if e.get("event") != "ssh_login_success" || ip == "" {
			continue
		}
		key := pyvalue.Str(s.host) + "|" + pyvalue.Str(e.meta.GetOr("user", ""))
		if seen[key] == nil {
			seen[key] = map[string]bool{}
			order = append(order, key)
		}
		novel := "true"
		if s.first || seen[key][ip] {
			novel = "false"
		}
		e.meta.Set("novel", novel)
		seen[key][ip] = true
	}
	out := pyvalue.NewMap()
	for _, k := range order {
		out.Set(k, sortedStrings(seen[k]))
	}
	next.Set("seen", out)
}

func stringSet(v any) map[string]bool {
	out := map[string]bool{}
	for _, x := range rundoc.List(v) {
		if s, ok := x.(string); ok {
			out[s] = true
		}
	}
	return out
}

func sortedStrings(set map[string]bool) []any {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]any, len(keys))
	for i, k := range keys {
		out[i] = k
	}
	return out
}

// fileIntegrity hashes authorized_keys-style files on the target; a changed hash is an event (never the content).
func (s *source) fileIntegrity(ctx context.Context) ([]*event, *pyvalue.Map, error) {
	ex, err := s.executor()
	if err != nil {
		return nil, nil, err
	}
	hashes := rundoc.MapOr(s.state.Value("hashes")).Copy()
	paths, ok := s.cfg.Get("paths")
	if !ok {
		return nil, nil, keyError("paths")
	}
	var evs []*event
	for _, p := range rundoc.List(paths) {
		path, user, err := fiPath(p)
		if err != nil {
			return nil, nil, err
		}
		res := ex.Run(ctx, []string{"sh", "-c", fiScript, "_", path}, nil, 60*time.Second, false)
		if res.RC != 0 {
			return nil, nil, pyErr("RuntimeError", fmt.Sprintf("%s: rc=%d: %s", path, res.RC, lastChars(pyStrip(res.Err), 160)))
		}
		out := universalNewlines(res.Out)
		h, nkeys := fileHash(out)
		if old, had := hashes.Get(path); had && old != nil && pyvalue.Str(old) != h {
			o := pyvalue.Str(old)
			meta := pyvalue.NewMap()
			meta.Set("event", "authorized_keys_changed")
			meta.Set("user", user)
			evs = append(evs, &event{ts: s.now, meta: meta, line: fmt.Sprintf(
				"authorized_keys changed: %s sha256 %s -> %s (%d keys)", path, cutRunes(o, 12), cutRunes(h, 12), nkeys)})
		}
		hashes.Set(path, h)
	}
	next := s.state.Copy()
	next.Set("hashes", hashes)
	return evs, next, nil
}

func fiPath(p any) (path string, user any, err error) {
	m, ok := p.(*pyvalue.Map)
	if !ok {
		return pyvalue.Str(p), "", nil
	}
	if !m.Has("path") {
		return "", nil, keyError("path")
	}
	return pyvalue.Str(m.Value("path")), m.GetOr("user", ""), nil
}

// fileHash is the sha256 of the file text ("absent" for none) and its number of key lines.
func fileHash(out string) (string, int) {
	if pyStrip(out) == "__absent__" {
		return "absent", 0
	}
	sum := sha256.Sum256([]byte(out))
	n := 0
	for _, ln := range splitLines(out) {
		if pyStrip(ln) != "" && !strings.HasPrefix(strings.TrimLeftFunc(ln, isSpace), "#") {
			n++
		}
	}
	return hex.EncodeToString(sum[:]), n
}

func cutRunes(s string, n int) string { return rundoc.Cut(s, n) }

// advance moves the cursor to the newest event and keeps the hashes of the lines at that instant (edge), so that a
// line at the cursor's own time is neither lost nor shipped twice.
func advance(next *pyvalue.Map, evs []*event, cursor float64, hasCursor bool, edge map[string]bool) {
	top := evs[0].ts
	for _, e := range evs {
		top = max(top, e.ts)
	}
	hashes := map[string]bool{}
	for _, e := range evs {
		if e.ts == top {
			hashes[e.hash] = true
		}
	}
	if hasCursor && cursor == top {
		for h := range edge {
			hashes[h] = true
		}
	}
	next.Set("cursor", top)
	next.Set("edge", sortedStrings(hashes))
}
