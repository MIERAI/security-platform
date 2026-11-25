package flags

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func findingsSpec() *Spec {
	return &Spec{Prog: "sp findings", Options: []Option{
		{Name: "data", Kind: String, Help: "private data directory (default $SP_DATA)"},
		{Name: "instance", Kind: String, Help: "instance config (default DATA/instance.yaml)"},
		{Name: "open", Kind: Bool, Help: "only open findings"},
		{Name: "severity", Kind: String, Choices: []string{"critical", "high", "medium", "low", "info"}, Help: "this severity or worse"},
		{Name: "layer", Kind: String},
		{Name: "check", Kind: String, Help: "check name or prefix"},
		{Name: "overdue", Kind: Bool, Help: "past the remediation SLO"},
		{Name: "json", Kind: Bool},
		{Name: "ids", Kind: Bool, Help: "only the ids"},
		{Name: "days", Kind: Int, Default: 1},
	}, Positionals: []Positional{{Name: "jobs", Variadic: true}}}
}

func TestParse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		args  []string
		check func(r *Result) bool
	}{
		{"options and positionals mixed", []string{"a", "--open", "b", "--data", "/d"},
			func(r *Result) bool {
				return r.Bool("open") && r.String("data") == "/d" && slices.Equal(r.Args("jobs"), []string{"a", "b"})
			}},
		{"--opt=value", []string{"--data=/x=y"}, func(r *Result) bool { return r.String("data") == "/x=y" }},
		{"empty value", []string{"--data="}, func(r *Result) bool { return r.String("data") == "" && r.set["data"] }},
		{"unique prefix", []string{"--sev", "high", "--js"}, func(r *Result) bool { return r.String("severity") == "high" && r.Bool("json") }},
		{"exact name wins over prefix", []string{"--open"}, func(r *Result) bool { return r.Bool("open") && !r.Bool("overdue") }},
		{"-- ends options", []string{"--", "--open", "-x"}, func(r *Result) bool {
			return !r.Bool("open") && slices.Equal(r.Args("jobs"), []string{"--open", "-x"})
		}},
		{"negative number value", []string{"--days", "-3"}, func(r *Result) bool { return r.Int("days") == -3 }},
		{"python int syntax", []string{"--days", " 1_000 "}, func(r *Result) bool { return r.Int("days") == 1000 }},
		{"default int", nil, func(r *Result) bool { return r.Int("days") == 1 }},
		{"negative number positional", []string{"-5"}, func(r *Result) bool { return slices.Equal(r.Args("jobs"), []string{"-5"}) }},
		{"lone dash is a positional", []string{"-"}, func(r *Result) bool { return slices.Equal(r.Args("jobs"), []string{"-"}) }},
		{"-h anywhere", []string{"--open", "-h", "--bogus"}, func(r *Result) bool { return r.Help }},
		{"--he abbreviates --help", []string{"--he"}, func(r *Result) bool { return r.Help }},
		{"--h: only --help starts so", []string{"--h"}, func(r *Result) bool { return r.Help }},
		{"last value wins", []string{"--layer", "a", "--layer", "b"}, func(r *Result) bool { return r.String("layer") == "b" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r, err := Parse(findingsSpec(), tc.args)
			if err != nil || !tc.check(r) {
				t.Fatalf("Parse(%q) = %+v, %v", tc.args, r, err)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	t.Parallel()
	explain := &Spec{Prog: "sp explain", Options: []Option{{Name: "data", Kind: String}}, Positionals: []Positional{{Name: "id"}}}
	tests := []struct {
		spec *Spec
		args []string
		want string
	}{
		{findingsSpec(), []string{"--severity", "bogus"}, "argument --severity: invalid choice: 'bogus' (choose from critical, high, medium, low, info)"},
		{findingsSpec(), []string{"--days", "x"}, "argument --days: invalid int value: 'x'"},
		{findingsSpec(), []string{"--data"}, "argument --data: expected one argument"},
		{findingsSpec(), []string{"--data", "--open"}, "argument --data: expected one argument"},
		{findingsSpec(), []string{"--open=1"}, "argument --open: ignored explicit argument '1'"},
		{findingsSpec(), []string{"--o"}, "ambiguous option: --o could match --open, --overdue"},
		{findingsSpec(), []string{"--nope"}, "unrecognized arguments: --nope"},
		{findingsSpec(), []string{"-x"}, "unrecognized arguments: -x"},
		{explain, nil, "the following arguments are required: id"},
		{explain, []string{"a", "b"}, "unrecognized arguments: b"},
	}
	for _, tc := range tests {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			t.Parallel()
			_, err := Parse(tc.spec, tc.args)
			var ue *UsageError
			if !errors.As(err, &ue) || ue.Msg != tc.want {
				t.Fatalf("Parse(%q) error %v, want %q", tc.args, err, tc.want)
			}
		})
	}
}

// TestUsageMatchesArgparse: the synopsis and help are laid out as Python's argparse lays them out (outputs of the
// reference cli/sp.py under Python 3.12, 80 columns).
func TestUsageMatchesArgparse(t *testing.T) {
	t.Parallel()
	s := findingsSpec()
	s.Options = s.Options[:9]
	s.Positionals = nil
	want := "usage: sp findings [-h] [--data DATA] [--instance INSTANCE] [--open]\n" +
		"                   [--severity {critical,high,medium,low,info}]\n" +
		"                   [--layer LAYER] [--check CHECK] [--overdue] [--json]\n" +
		"                   [--ids]"
	if got := s.Usage(); got != want {
		t.Errorf("usage:\n%s\nwant:\n%s", got, want)
	}
	help := s.Help()
	for _, line := range []string{
		"  -h, --help            show this help message and exit\n",
		"  --data DATA           private data directory (default $SP_DATA)\n",
		"  --severity {critical,high,medium,low,info}\n                        this severity or worse\n",
		"  --layer LAYER\n",
	} {
		if !strings.Contains(help, line) {
			t.Errorf("help lacks %q:\n%s", line, help)
		}
	}
	init := &Spec{Prog: "sp init", Options: []Option{{Name: "name", Kind: String}, {Name: "force", Kind: Bool}},
		Positionals: []Positional{{Name: "dir"}}}
	wantInit := "usage: sp init [-h] [--name NAME] [--force] dir\n\npositional arguments:\n  dir\n\noptions:\n" +
		"  -h, --help   show this help message and exit\n  --name NAME\n  --force\n"
	if got := init.Help(); got != wantInit {
		t.Errorf("init help:\n%q\nwant:\n%q", got, wantInit)
	}
	top := FormatUsage("sp", []string{"[-h]", "[--version]"},
		[]string{"{init,doctor,run,status,findings,explain,digest,notify}", "..."}, DefaultWidth)
	if want := "usage: sp [-h] [--version]\n          {init,doctor,run,status,findings,explain,digest,notify} ..."; top != want {
		t.Errorf("top usage %q", top)
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"--open\x00--sev\x00high", "--data=\x00x", "--\x00-y", "-h", "--days\x00-1", "--o", "\x00", "--=x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, joined string) {
		args := strings.Split(joined, "\x00")
		r, err := Parse(findingsSpec(), args)
		var ue *UsageError
		switch {
		case err != nil && !errors.As(err, &ue):
			t.Fatalf("%q: error of another kind: %v", args, err)
		case err == nil && r == nil:
			t.Fatalf("%q: no result and no error", args)
		case err == nil && !r.Help && r.String("severity") != "" &&
			!slices.Contains([]string{"critical", "high", "medium", "low", "info"}, r.String("severity")):
			t.Fatalf("%q: severity %q accepted", args, r.String("severity"))
		}
		_ = findingsSpec().Help() // never panics
	})
}
