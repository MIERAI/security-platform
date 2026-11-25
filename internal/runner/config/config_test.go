package config

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestResolve checks PyYAML's (YAML 1.1) reading of unquoted scalars, which the reference runner uses.
func TestResolve(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want any
	}{
		{"yes", true}, {"No", false}, {"ON", true}, {"off", false}, {"true", true}, {"y", "y"}, {"~", nil},
		{"null", nil}, {"", nil}, {"42", int64(42)}, {"-7", int64(-7)}, {"0755", int64(493)}, {"0x1F", int64(31)},
		{"0b101", int64(5)}, {"1_000", int64(1000)}, {"1:30", int64(90)}, {"1.5", 1.5}, {"1e3", "1e3"},
		{"1.0e+3", 1000.0}, {".inf", math.Inf(1)}, {"-.inf", math.Inf(-1)}, {"30m", "30m"}, {"2026-01-01", "2026-01-01"},
		{"0", int64(0)}, {"+5", int64(5)}, {"99999999999999999999", "99999999999999999999"}, {"0:30:00", "0:30:00"}, {"08", "08"}, {"1.", 1.0}, {".5", 0.5}, {"1__0", int64(10)},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			if got := Resolve(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Resolve(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
	if v, ok := Resolve(".nan").(float64); !ok || !math.IsNaN(v) {
		t.Errorf(".nan = %v", Resolve(".nan"))
	}
}

func TestParseKeepsOrderQuotesAndMerges(t *testing.T) {
	t.Parallel()
	doc := `
base: &b {timeout: 1h, retries: 2}
jobs:
  zeta: {schedule: "0 * * * *", flag: yes, quoted: "yes", <<: *b, retries: 5}
  alpha: {schedule: '30 3 * * *'}
  mid:
    schedule: "*/5 * * * *"
`
	v, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	jobs := mustMap(t, mustMap(t, v).Get("jobs"))
	if want := []string{"zeta", "alpha", "mid"}; !reflect.DeepEqual(jobs.Keys, want) {
		t.Errorf("order %v, want %v", jobs.Keys, want)
	}
	z := mustMap(t, jobs.Get("zeta"))
	if z.Get("flag") != true || z.Get("quoted") != "yes" || z.Get("timeout") != "1h" || z.Get("retries") != int64(5) {
		t.Errorf("zeta = %#v", z.Plain())
	}
}

func mustMap(t *testing.T, v any) *Map {
	t.Helper()
	m, ok := v.(*Map)
	if !ok {
		t.Fatalf("%#v is not a mapping", v)
	}
	return m
}

func TestParseRejects(t *testing.T) {
	t.Parallel()
	bomb := "a: &a [x, x, x, x, x, x, x, x, x, x]\n"
	prev := "a"
	for i := 0; i < 9; i++ {
		n := string(rune('b' + i))
		bomb += n + ": &" + n + " [*" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev +
			", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + "]\n"
		prev = n
	}
	for name, doc := range map[string]string{"syntax": "a: [", "alias bomb": bomb,
		"deep": strings.Repeat("[", 100) + strings.Repeat("]", 100)} {
		if _, err := Parse([]byte(doc)); !errors.Is(err, ErrYAML) {
			t.Errorf("%s: err = %v, want ErrYAML", name, err)
		}
	}
}

func TestDuration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   any
		want int64
		ok   bool
	}{
		{"90s", 90, true}, {"30m", 1800, true}, {"2h", 7200, true}, {"1d", 86400, true}, {"1w", 604800, true},
		{int64(45), 45, true}, {nil, 0, true}, {"", 0, true}, {"1.5m", 90, true}, {" 2h ", 7200, true},
		{"90", 90, true}, {2.9, 2, true}, {true, 1, true}, {json.Number("60"), 60, true},
		{"1.5", 0, false}, {"x", 0, false}, {"  ", 0, false}, {"m", 0, false}, {"1e40s", 0, false},
		{"nanm", 0, false}, {[]any{}, 0, false},
	}
	for _, tt := range tests {
		got, err := Duration(tt.in)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("Duration(%#v) = %d, %v; want %d ok=%v", tt.in, got, err, tt.want, tt.ok)
		}
	}
}

func TestInt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   any
		want int64
		ok   bool
	}{
		{nil, 9, true}, {int64(2), 2, true}, {2.7, 2, true}, {"3", 3, true}, {false, 0, true},
		{json.Number("4"), 4, true}, {json.Number("4.5"), 4, true}, {"x", 0, false}, {math.Inf(1), 0, false},
	}
	for _, tt := range tests {
		got, err := Int(tt.in, 9)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("Int(%#v) = %d, %v", tt.in, got, err)
		}
	}
}

func TestStrAndTruthy(t *testing.T) {
	t.Parallel()
	for in, want := range map[any]string{true: "True", nil: "None", int64(3): "3", 2.0: "2.0", 0.1: "0.1", "x": "x"} {
		if got := Str(in); got != want {
			t.Errorf("Str(%#v) = %q, want %q", in, got, want)
		}
	}
	for _, v := range []any{nil, false, int64(0), 0.0, "", []any{}, &Map{}} {
		if Truthy(v) {
			t.Errorf("Truthy(%#v)", v)
		}
	}
}

func TestFromBytes(t *testing.T) {
	t.Parallel()
	in, err := FromBytes([]byte(`
name: lab
scorecard: {enabled: no}
runner:
  site: s1
  role: site
  env_passthrough: [GH_TOKEN]
  implementations: {ledger: go}
  tick_stale_after: 2h
  jobs:
    host: {schedule: "15 2 * * *", jitter: 30m, retries: 2, env: {A: yes, B: 1.50, C: x}}
    cmd: {type: command, argv: [/bin/true], schedule: "0 * * * *", as: cmd-b}
    ingest-x: {type: ingest, schedule: "*/30 * * * *", site_collectors: {exposure: "30 3 * * *"}}
`))
	if err != nil {
		t.Fatal(err)
	}
	host, _ := in.Job("host")
	cmd, _ := in.Job("cmd")
	ing, _ := in.Job("ingest-x")
	checks := []struct {
		name      string
		got, want any
	}{
		{"name", in.Name, "lab"}, {"site", in.Site, "s1"}, {"role", in.Role, "site"}, {"scorecard", in.Scorecard, false},
		{"stale", in.TickStaleAfter, int64(7200)}, {"passthrough", in.EnvPassthrough, []string{"GH_TOKEN"}},
		{"impl", in.Impl["ledger"], "go"}, {"jobs", len(in.Jobs), 3}, {"collector", host.Collector, "host"},
		{"jitter", host.Jitter, int64(1800)}, {"retries", host.Retries, int64(2)}, {"retry_delay", host.RetryDelay, int64(900)},
		{"timeout", host.Timeout, int64(3600)}, {"env yes", host.Env["A"], "True"}, {"env float", host.Env["B"], "1.5"},
		{"report", host.Report(), "host"}, {"as", cmd.Report(), "cmd-b"}, {"argv", cmd.Argv, []string{"/bin/true"}},
		{"ingest collector", ing.Collector, ""}, {"ingest timeout", ing.Timeout, int64(0)},
		{"site collectors", len(ing.SiteCollectors), 1},
	}
	for _, c := range checks {
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("%s = %#v, want %#v", c.name, c.got, c.want)
		}
	}
}

func TestFromBytesRejects(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"not a mapping":   "[1]",
		"runner list":     "runner: [1]",
		"bad role":        "runner: {role: edge}",
		"no schedule":     "runner: {jobs: {a: {}}}",
		"bad cron":        `runner: {jobs: {a: {schedule: "61 * * * *"}}}`,
		"bad type":        `runner: {jobs: {a: {schedule: "* * * * *", type: magic}}}`,
		"bad duration":    `runner: {jobs: {a: {schedule: "* * * * *", timeout: soon}}}`,
		"command no argv": `runner: {jobs: {a: {schedule: "* * * * *", type: command}}}`,
		"argv not list":   `runner: {jobs: {a: {schedule: "* * * * *", argv: "/bin/sh -c x"}}}`,
		"bad job name":    `runner: {jobs: {"../x": {schedule: "* * * * *"}}}`,
		"bad retries":     `runner: {jobs: {a: {schedule: "* * * * *", retries: many}}}`,
		"bad passthrough": `runner: {env_passthrough: GH_TOKEN}`,
		"bad site sched":  `runner: {jobs: {a: {schedule: "* * * * *", site_collectors: {x: 5}}}}`,
	}
	for name, doc := range tests {
		if _, err := FromBytes([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if in, err := FromBytes([]byte("runner:\n")); err != nil || len(in.Jobs) != 0 || in.Site != "hub" {
		t.Errorf("empty runner block: %+v, %v", in, err)
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "instance.json")
	if err := os.WriteFile(p, []byte(`{"name": "j", "runner": {"jobs": {"a": {"schedule": "0 * * * *"}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := Load(p)
	if err != nil || in.Path != p || in.Name != "j" {
		t.Fatalf("Load = %+v, %v", in, err)
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("missing file loaded")
	}
}

// FuzzFromBytes: no input makes the instance reader panic or hang; whatever it accepts has jobs with schedules.
func FuzzFromBytes(f *testing.F) {
	for _, s := range []string{"runner: {jobs: {a: {schedule: \"0 * * * *\", env: {A: yes}}}}", "{}", "runner:\n  jobs:\n",
		"a: &x [1]\nb: *x\n", "runner: {jobs: {a: {schedule: \"* * * * *\", <<: {retries: 2}}}}"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		in, err := FromBytes(data)
		if err != nil {
			return
		}
		for _, j := range in.Jobs {
			if j.Schedule == nil || j.Name == "" || j.Type == "" {
				t.Fatalf("accepted a job without schedule/name/type: %+v", j)
			}
		}
	})
}

// FuzzDuration: durations either fail or are bounded.
func FuzzDuration(f *testing.F) {
	for _, s := range []string{"90s", "1.5h", "7d", "12", " 3w ", "x", "1e9w"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if d, err := Duration(s); err == nil && (d > maxSeconds || d < -maxSeconds) {
			t.Fatalf("Duration(%q) = %d out of bounds", s, d)
		}
	})
}

// FuzzResolve: resolving a plain scalar never panics, and text that is not a number, boolean or null stays itself.
func FuzzResolve(f *testing.F) {
	for _, s := range []string{"yes", "0755", "1:30", "1_0", ".inf", "-0b1", "0x_", "+", "1:60"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if v, ok := Resolve(s).(string); ok && v != s {
			t.Fatalf("Resolve(%q) changed the text to %q", s, v)
		}
	})
}
