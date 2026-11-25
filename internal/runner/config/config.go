package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"

	"github.com/MIERAI/security-platform/internal/runner/cron"
)

// MaxFile bounds how much of an instance file is read.
const MaxFile = 4 << 20

// Job types (contract §2).
const (
	TypeCollector    = "collector"
	TypeCommand      = "command"
	TypeIngest       = "ingest"
	TypeDigest       = "digest"
	TypeRemediation  = "remediation"
	TypeExport       = "export"
	TypeSnapshot     = "snapshot"
	TypePush         = "push"
	TypePullSnapshot = "pull-snapshot"
	TypeEvents       = "events"
	TypeNotify       = "notify"
)

// defaultTimeouts are the per-type timeouts of the reference (collector and command: 1h). A fresh map per call.
func defaultTimeouts() map[string]string {
	return map[string]string{TypeCollector: "1h", TypeCommand: "1h", TypeEvents: "10m", TypeDigest: "10m",
		TypeNotify: "5m", TypeRemediation: "10m", TypeExport: "15m"}
}

// knownTypes lists the job types. A fresh map per call.
func knownTypes() map[string]bool {
	m := map[string]bool{}
	for _, t := range []string{TypeCollector, TypeCommand, TypeIngest, TypeDigest, TypeRemediation, TypeExport,
		TypeSnapshot, TypePush, TypePullSnapshot, TypeEvents, TypeNotify} {
		m[t] = true
	}
	return m
}

// jobName is what a job may be called: it becomes a file name (state, lock, run directory).
var jobName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// ErrConfig is the error class of an unusable instance configuration.
var ErrConfig = errors.New("bad runner configuration")

// Job is one entry of runner.jobs.
type Job struct {
	Name       string
	Type       string
	Collector  string // collector and command jobs: the collector's directory (default: the job name)
	As         string
	Argv       []string
	Schedule   *cron.Schedule
	Jitter     int64
	Timeout    int64
	Retries    int64
	RetryDelay int64
	MaxDelay   int64
	Env        map[string]string // values as Python's str()
	// SiteCollectors are an ingest job's declared site schedules, in configuration order.
	SiteCollectors []NamedSchedule
	Raw            *Map
}

// NamedSchedule is a collector's schedule declared by a hub for a site.
type NamedSchedule struct {
	Collector string
	Schedule  *cron.Schedule
}

// Report is the collector name a job reports under (`as:`, else `collector:`).
func (j *Job) Report() string {
	if j.As != "" {
		return j.As
	}
	return j.Collector
}

// Instance is the parts of an instance configuration the runner uses.
type Instance struct {
	Path           string
	Name           string
	Site           string
	Role           string
	TickStaleAfter int64
	Retention      int64
	Jobs           []*Job
	Runner         *Map // the whole runner block, for adapters configured there
	Scorecard      bool // scorecard.enabled is not false
	EnvPassthrough []string
}

// Job returns the job of that name.
func (in *Instance) Job(name string) (*Job, bool) {
	for _, j := range in.Jobs {
		if j.Name == name {
			return j, true
		}
	}
	return nil, false
}

// Load reads and checks an instance file.
func Load(path string) (*Instance, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator names the instance file
	if err != nil {
		return nil, fmt.Errorf("open instance: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxFile+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("read instance: %w", err)
	}
	if len(data) > MaxFile {
		return nil, fmt.Errorf("%w: instance file larger than %d bytes", ErrConfig, MaxFile)
	}
	in, err := FromBytes(data)
	if err != nil {
		return nil, err
	}
	in.Path = path
	return in, nil
}

// FromBytes parses an instance document.
func FromBytes(data []byte) (*Instance, error) {
	doc, err := Parse(data)
	if err != nil {
		return nil, err
	}
	top, ok := doc.(*Map)
	if !ok {
		return nil, fmt.Errorf("%w: the instance is not a mapping", ErrConfig)
	}
	r, ok := orEmpty(top.Get("runner"))
	if !ok {
		return nil, fmt.Errorf("%w: runner is not a mapping", ErrConfig)
	}
	in := &Instance{Name: String(top.Get("name"), ""), Runner: r, Scorecard: true}
	if sc, ok := top.Get("scorecard").(*Map); ok {
		if b, isBool := sc.Get("enabled").(bool); isBool && !b {
			in.Scorecard = false
		}
	}
	if err := in.readRunner(r); err != nil {
		return nil, err
	}
	return in, nil
}

// orEmpty treats null as an empty mapping (`runner:` with nothing under it), as the reference's `or {}`.
func orEmpty(v any) (*Map, bool) {
	if !Truthy(v) {
		return &Map{Vals: map[string]any{}}, true
	}
	m, ok := v.(*Map)
	return m, ok
}

func (in *Instance) readRunner(r *Map) error {
	in.Site = String(r.Get("site"), "hub")
	in.Role = String(r.Get("role"), "hub")
	if in.Role != "hub" && in.Role != "site" {
		return fmt.Errorf("%w: role %q (hub or site)", ErrConfig, in.Role)
	}
	var err error
	if in.TickStaleAfter, err = Duration(orDefault(r, "tick_stale_after", "1h")); err != nil {
		return fmt.Errorf("%w: tick_stale_after: %w", ErrConfig, err)
	}
	if in.Retention, err = Duration(r.Get("retention")); err != nil {
		return fmt.Errorf("%w: retention: %w", ErrConfig, err)
	}
	if in.EnvPassthrough, err = stringList(r.Get("env_passthrough")); err != nil {
		return fmt.Errorf("%w: env_passthrough: %w", ErrConfig, err)
	}
	jobs, ok := orEmpty(r.Get("jobs"))
	if !ok {
		return fmt.Errorf("%w: runner.jobs is not a mapping", ErrConfig)
	}
	for _, name := range jobs.Keys {
		j, err := readJob(name, jobs.Get(name))
		if err != nil {
			return fmt.Errorf("%w: job %q: %w", ErrConfig, name, err)
		}
		in.Jobs = append(in.Jobs, j)
	}
	return nil
}

func orDefault(m *Map, key string, def any) any {
	if m.Has(key) {
		return m.Get(key)
	}
	return def
}

func stringList(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	l, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: want a list of strings", ErrValue)
	}
	out := make([]string, 0, len(l))
	for _, e := range l {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("%w: want a list of strings", ErrValue)
		}
		out = append(out, s)
	}
	return out, nil
}

func readJob(name string, v any) (*Job, error) {
	if !jobName.MatchString(name) {
		return nil, fmt.Errorf("%w: a job name is letters, digits, '.', '_' and '-'", ErrValue)
	}
	raw, ok := orEmpty(v)
	if !ok {
		return nil, fmt.Errorf("%w: not a mapping", ErrValue)
	}
	j := &Job{Name: name, Raw: raw, Type: String(raw.Get("type"), TypeCollector)}
	if !knownTypes()[j.Type] {
		return nil, fmt.Errorf("%w: unknown type %q", ErrValue, j.Type)
	}
	if j.Type == TypeCollector || j.Type == TypeCommand {
		j.Collector = String(raw.Get("collector"), name)
	}
	j.As = String(raw.Get("as"), "")
	if err := j.readSchedule(raw); err != nil {
		return nil, err
	}
	if err := j.readDurations(raw); err != nil {
		return nil, err
	}
	err := j.readLists(raw)
	return j, err
}

func (j *Job) readSchedule(raw *Map) error {
	expr, ok := raw.Get("schedule").(string)
	if !ok {
		return fmt.Errorf("%w: schedule (a 5-field cron string) is required", ErrValue)
	}
	s, err := cron.Parse(expr)
	if err != nil {
		return fmt.Errorf("schedule: %w", err)
	}
	j.Schedule = s
	return nil
}

func (j *Job) readDurations(raw *Map) error {
	fields := []struct {
		key string
		dst *int64
		def any
	}{{"jitter", &j.Jitter, nil}, {"timeout", &j.Timeout, defaultTimeouts()[j.Type]},
		{"retry_delay", &j.RetryDelay, "15m"}, {"max_delay", &j.MaxDelay, nil}}
	for _, f := range fields {
		v, err := Duration(orDefault(raw, f.key, f.def))
		if err != nil {
			return fmt.Errorf("%s: %w", f.key, err)
		}
		*f.dst = v
	}
	r, err := Int(raw.Get("retries"), 0)
	if err != nil {
		return fmt.Errorf("retries: %w", err)
	}
	j.Retries = r
	return nil
}

func (j *Job) readLists(raw *Map) error {
	if raw.Has("argv") {
		argv, err := stringList(raw.Get("argv"))
		if err != nil || len(argv) == 0 {
			return fmt.Errorf("argv: %w", errors.Join(ErrValue, err))
		}
		j.Argv = argv
	} else if j.Type == TypeCommand {
		return fmt.Errorf("%w: a command job needs argv", ErrValue)
	}
	j.Env = map[string]string{}
	if env, ok := raw.Get("env").(*Map); ok {
		for _, k := range env.Keys {
			j.Env[k] = Str(env.Get(k))
		}
	}
	if sc, ok := raw.Get("site_collectors").(*Map); ok {
		for _, col := range sc.Keys {
			expr, _ := sc.Get(col).(string) // not a string: Parse refuses ""
			s, err := cron.Parse(expr)
			if err != nil {
				return fmt.Errorf("site_collectors.%s: %w", col, err)
			}
			j.SiteCollectors = append(j.SiteCollectors, NamedSchedule{Collector: col, Schedule: s})
		}
	}
	return nil
}

// EnvKeys returns the job's environment variable names, sorted.
func (j *Job) EnvKeys() []string {
	keys := make([]string, 0, len(j.Env))
	for k := range j.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
