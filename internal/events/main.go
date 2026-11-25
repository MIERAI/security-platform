// Package events is the events shipper (events/ship.py, contract events/1.0): security events from hosts and SaaS
// control planes, pushed to a Loki-compatible log store. For every source: read what is new since its cursor,
// normalise it, push it, and only then store the new cursor (at-least-once). One failing source never stops the
// others; the exit status is 1 if any failed. A source's first run records a baseline and reports nothing as new.
package events

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
	"github.com/MIERAI/security-platform/internal/textsafe"
)

// Version is the component's version (events/VERSION; TestVersionMatchesTree keeps them equal).
const Version = "0.2.0"

const (
	usage         = "usage: sp events ship --config FILE --state DIR [--summary FILE] [--now EPOCH] [--dry-run]"
	maxConfigFile = 16 << 20
	maxStateFile  = 256 << 20
)

// nameRx is the form of a source name (it names the state file). Never written after initialisation.
var nameRx = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// Env is what the shipper reads from its process.
type Env struct {
	Getenv    func(string) string
	Stdout    io.Writer
	Stderr    io.Writer
	Now       func() time.Time
	Location  *time.Location    // local time (TZ): BSD syslog times without an offset, {since_local}
	Transport http.RoundTripper // tests; nil: the default
}

type options struct {
	config, state, summary string
	now                    float64
	dryRun                 bool
}

// Main is `sp events ship ...` and returns the exit status: 0 every source shipped, 1 a source (or the run)
// failed, 2 usage error.
func Main(ctx context.Context, env Env, args []string) int {
	if len(args) == 0 || args[0] != "ship" {
		_, _ = fmt.Fprintln(env.Stderr, usage) // the status says it too
		return 2
	}
	o, err := parseArgs(args[1:])
	if err != nil {
		_, _ = fmt.Fprintf(env.Stderr, "%s\nsp events ship: error: %v\n", usage, err) // the status says it too
		return 2
	}
	if o.now == 0 {
		o.now = float64(env.Now().UnixNano()) / 1e9
	}
	code, err := ship(ctx, env, o)
	if err != nil {
		_, _ = fmt.Fprintln(env.Stderr, "sp events ship: "+textsafe.Line(err.Error())) // the status says it too
		return 1
	}
	return code
}

func parseArgs(args []string) (options, error) {
	var o options
	seen := map[string]bool{}
	for len(args) > 0 {
		arg := args[0]
		args = args[1:]
		name, val, hasVal := strings.Cut(arg, "=")
		if name == "--dry-run" && !hasVal {
			o.dryRun = true
			continue
		}
		if !slices.Contains([]string{"--config", "--state", "--summary", "--now"}, name) {
			return o, fmt.Errorf("unrecognized arguments: %s", arg)
		}
		if !hasVal {
			if len(args) == 0 {
				return o, fmt.Errorf("argument %s: expected one argument", name)
			}
			val, args = args[0], args[1:]
		}
		seen[name] = true
		if err := o.set(name, val); err != nil {
			return o, err
		}
	}
	if !seen["--config"] || !seen["--state"] {
		return o, errors.New("the following arguments are required: --config, --state")
	}
	return o, nil
}

func (o *options) set(name, val string) error {
	switch name {
	case "--config":
		o.config = val
	case "--state":
		o.state = val
	case "--summary":
		o.summary = val
	default:
		f, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
		if err != nil {
			return fmt.Errorf("argument --now: invalid float value: %q", val)
		}
		o.now = f
	}
	return nil
}

// loadConfig reads the config (JSON) and checks every source name before any source runs.
func loadConfig(p string) (*pyvalue.Map, []*pyvalue.Map, error) {
	data, err := rundoc.ReadLimited(p, maxConfigFile)
	if err != nil {
		return nil, nil, fmt.Errorf("config %s: %w", p, err)
	}
	v, err := pyvalue.DecodeJSON(data)
	cfg, ok := v.(*pyvalue.Map)
	if err != nil || !ok {
		return nil, nil, fmt.Errorf("config %s: not a JSON object", p)
	}
	var sources []*pyvalue.Map
	for _, x := range rundoc.List(cfg.GetOr("sources", []any{})) {
		sc, ok := x.(*pyvalue.Map)
		if !ok || !sc.Has("name") {
			return nil, nil, errors.New("every source needs a name")
		}
		name, isText := sc.Value("name").(string)
		if !isText || !nameRx.MatchString(name) {
			return nil, nil, fmt.Errorf("source name %s: letters, digits, . _ - only", pyvalue.Repr(sc.Value("name")))
		}
		sources = append(sources, sc)
	}
	return cfg, sources, nil
}

func ship(ctx context.Context, env Env, o options) (int, error) {
	cfg, sources, err := loadConfig(o.config)
	if err != nil {
		return 1, err
	}
	if err := os.MkdirAll(o.state, 0o700); err != nil {
		return 1, fmt.Errorf("create the state directory: %w", err)
	}
	loc := env.Location
	if loc == nil {
		loc = time.Local
	}
	r := &runner{env: env, cfg: cfg, o: o, d: &deps{getenv: env.Getenv, home: home(env.Getenv), loc: loc,
		transport: env.Transport}, summary: map[string]any{}}
	failed := 0
	for _, sc := range sources {
		if !r.source(ctx, sc) {
			failed++
		}
	}
	if o.summary != "" {
		data, err := pyjson.Marshal(rundoc.JSON(map[string]any{"version": Version, "sources": r.summary}),
			pyjson.Options{Indent: 1, SortKeys: true, EnsureASCII: true})
		if err != nil {
			return 1, fmt.Errorf("encode the summary: %w", err)
		}
		if err := os.WriteFile(o.summary, data, 0o600); err != nil {
			return 1, fmt.Errorf("write the summary: %w", err)
		}
	}
	if failed > 0 {
		return 1, nil
	}
	return 0, nil
}

func home(getenv func(string) string) string {
	if h := getenv("HOME"); h != "" {
		return h
	}
	return getenv("USERPROFILE")
}

type runner struct {
	env     Env
	cfg     *pyvalue.Map
	o       options
	d       *deps
	summary map[string]any
}

// source collects, pushes and records one source; false when it failed (its cursor is kept).
func (r *runner) source(ctx context.Context, sc *pyvalue.Map) bool {
	name, _ := sc.Value("name").(string) // checked by loadConfig
	got, err := r.collect(ctx, sc)
	if err == nil {
		err = r.deliver(ctx, name, sc, got)
	}
	src, evs, next := got.src, got.evs, got.next
	if err != nil {
		msg := describe(err)
		r.summary[name] = map[string]any{"ok": false, "error": msg}
		r.log(name + ": FAILED " + msg + " (cursor kept)")
		return false
	}
	counts, order := eventCounts(evs)
	r.summary[name] = map[string]any{"ok": true, "shipped": len(evs), "events": counts, "baseline": src.first,
		"unsupported": rundoc.Loose(rundoc.MapOr(next.GetOr("unsupported", pyvalue.NewMap())))}
	r.log(fmt.Sprintf("%s: shipped %d %s%s", name, len(evs), countsRepr(order, counts), map[bool]string{true: " (baseline)"}[src.first]))
	return true
}

// collected is what one source read: the source, its new events and its next state.
type collected struct {
	src  *source
	evs  []*event
	next *pyvalue.Map
}

func (r *runner) collect(ctx context.Context, sc *pyvalue.Map) (collected, error) {
	name, _ := sc.Value("name").(string) // checked by loadConfig
	state, err := loadState(filepath.Join(r.o.state, name+".json"))
	if err != nil {
		return collected{}, err
	}
	src, err := newSource(sc, state, r.o.now, r.d)
	if err != nil {
		return collected{}, err
	}
	evs, next, err := src.collect(ctx)
	return collected{src, evs, next}, err
}

// eventCounts counts the events by name ("-" for none), in the order the names first appear.
func eventCounts(evs []*event) (counts map[string]any, order []string) {
	n := map[string]int64{}
	for _, e := range evs {
		k := textOf(e.get("event"))
		if k == "" {
			k = "-"
		}
		if _, ok := n[k]; !ok {
			order = append(order, k)
		}
		n[k]++
	}
	counts = map[string]any{}
	for k, v := range n {
		counts[k] = v
	}
	return counts, order
}

func loadState(p string) (*pyvalue.Map, error) {
	if _, err := os.Stat(p); err != nil {
		return pyvalue.NewMap(), nil //nolint:nilerr // no state yet: the first run (as os.path.exists)
	}
	data, err := rundoc.ReadLimited(p, maxStateFile)
	if err != nil {
		return nil, osError(err, p)
	}
	v, err := pyvalue.DecodeJSON(data)
	if err != nil {
		return nil, pyErr("JSONDecodeError", err.Error())
	}
	m, ok := v.(*pyvalue.Map)
	if !ok {
		return nil, pyErr("AttributeError", "'"+pyvalue.TypeName(v)+"' object has no attribute 'get'")
	}
	return m, nil
}

// deliver pushes the events and a heartbeat (or prints them with --dry-run) and then stores the new state.
func (r *runner) deliver(ctx context.Context, name string, sc *pyvalue.Map, got collected) error {
	src, evs, next := got.src, got.evs, got.next
	var streams []*pyvalue.Map
	if len(evs) > 0 {
		streams = append(streams, toStream(src.label, src.host, evs))
	}
	if pyvalue.Truthy(sc.GetOr("heartbeat", r.cfg.GetOr("heartbeat", true))) {
		hb, err := heartbeat(name, len(evs), r.o.now)
		if err != nil {
			return err
		}
		streams = append(streams, toStream(src.label, src.host, []*event{hb}))
	}
	if r.o.dryRun {
		return r.printStreams(streams)
	}
	loki, ok := r.cfg.Get("loki")
	if !ok {
		return keyError("loki")
	}
	if len(streams) > 0 {
		p, err := newPusher(rundoc.MapOr(loki), r.d)
		if err != nil {
			return err
		}
		if err := p.push(ctx, streams); err != nil {
			return err
		}
	}
	return writeState(filepath.Join(r.o.state, name+".json"), next)
}

// heartbeat is one line per successful run: the source is collected even when nothing happened.
func heartbeat(name string, n int, now float64) (*event, error) {
	line := pyvalue.NewMap()
	line.Set("heartbeat", name)
	line.Set("events", int64(n))
	text, err := dumps(line, defaultJSON())
	if err != nil {
		return nil, fmt.Errorf("encode heartbeat: %w", err)
	}
	meta := pyvalue.NewMap()
	meta.Set("event", "heartbeat")
	return &event{ts: now, line: text, meta: meta}, nil
}

func (r *runner) printStreams(streams []*pyvalue.Map) error {
	all := make([]any, len(streams))
	for i, s := range streams {
		all[i] = s
	}
	doc := pyvalue.NewMap()
	doc.Set("streams", all)
	text, err := dumps(doc, dryRunJSON())
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	if _, err := fmt.Fprintln(r.env.Stdout, text); err != nil {
		return fmt.Errorf("print: %w", err)
	}
	return nil
}

// writeState stores a source's state: a 0600 file written in one step (temporary file, rename).
func writeState(p string, next *pyvalue.Map) error {
	text, err := dumps(next, sortedJSON())
	if err != nil {
		return pyErr("TypeError", err.Error())
	}
	tmp := p + ".tmp"
	f, err := os.OpenFile(filepath.Clean(tmp), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return osError(err, tmp)
	}
	if err := f.Chmod(0o600); err != nil { // a leftover temporary file keeps its old mode otherwise
		return errors.Join(osError(err, tmp), f.Close())
	}
	if _, err := f.WriteString(text); err != nil {
		return errors.Join(osError(err, tmp), f.Close())
	}
	if err := f.Close(); err != nil {
		return osError(err, tmp)
	}
	if err := os.Rename(tmp, p); err != nil {
		return osError(err, p)
	}
	return nil
}

func (r *runner) log(msg string) {
	t := time.Now().In(r.d.loc).Format("2006-01-02T15:04:05-0700")
	_, _ = fmt.Fprintln(r.env.Stderr, t+" events: "+textsafe.Line(msg)) // a lost log line changes nothing shipped
}

// countsRepr is the dict repr the reference logs ({'sudo': 2}); "" when empty.
func countsRepr(order []string, counts map[string]any) string {
	if len(order) == 0 {
		return ""
	}
	parts := make([]string, len(order))
	for i, k := range order {
		parts[i] = pyvalue.Repr(k) + ": " + pyvalue.Str(counts[k])
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
