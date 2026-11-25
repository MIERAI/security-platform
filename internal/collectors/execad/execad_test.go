package execad

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

func config(t *testing.T, yaml string) any {
	t.Helper()
	v, err := pyvalue.DecodeYAML([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestFromConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		yaml string
		argv []string
		err  error
	}{
		{"", []string{"nmap", "-sT"}, nil},
		{"{type: local}", []string{"nmap", "-sT"}, nil},
		{"{type: ssh, host: vantage, options: [-p, '2222']}", append(append([]string{"ssh"}, sshBase()...), "-p", "2222",
			"vantage", "nmap -sT"), nil},
		{"{type: ssh, host: '-oProxyCommand=x'}", nil, errors.New("not a host name")},
		{"{type: ssh}", nil, errors.New("not a host name")},
		{"{type: ssm}", nil, ErrUnsupported},
		{"{type: carrier-pigeon}", nil, ErrUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.yaml, func(t *testing.T) {
			t.Parallel()
			e, err := FromConfig(config(t, tt.yaml))
			if tt.err != nil || err != nil {
				wantErr(t, err, tt.err)
				return
			}
			if got := e.Argv([]string{"nmap", "-sT"}); !slices.Equal(got, tt.argv) {
				t.Fatalf("Argv = %q, want %q", got, tt.argv)
			}
		})
	}
}

func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if err == nil || want == nil || (!errors.Is(err, want) && !strings.Contains(err.Error(), want.Error())) {
		t.Fatalf("err %v, want %v", err, want)
	}
}

func TestQuoting(t *testing.T) {
	t.Parallel()
	argv := []string{"curl", "-sf", "http://h/q?a=1&b=2", "it's", "", "a b"}
	if got, want := QuotePOSIX(argv), `curl -sf 'http://h/q?a=1&b=2' 'it'"'"'s' '' 'a b'`; got != want {
		t.Errorf("QuotePOSIX = %s, want %s", got, want)
	}
	if got, want := QuoteWindows([]string{`a b`, `c"d`, `e\`, `f\ g\`, ""}), `"a b" c\"d e\ "f\ g\\" ""`; got != want {
		t.Errorf("QuoteWindows = %s, want %s", got, want)
	}
}

func TestRunLocal(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell programs")
	}
	e, err := FromConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r := e.Run(ctx, []string{"sh", "-c", `cat; echo err >&2; printf '\377'; exit 3`}, []byte("in\n"), 10*time.Second, false)
	if r.RC != 3 || r.Out != "in\n�" || r.Err != "err\n" {
		t.Errorf("run: %+v", r)
	}
	start := time.Now()
	r = e.Run(ctx, []string{"sh", "-c", `echo partial; sleep 30 & wait`}, nil, 300*time.Millisecond, true)
	if r.RC != RCTimeout || r.Err != "timeout" || r.Out != "partial\n" {
		t.Errorf("timeout: %+v", r)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("the process group was not killed (took %s)", time.Since(start))
	}
	if r = e.Run(ctx, []string{"/nonexistent/program"}, nil, time.Second, false); r.RC != RCNotFound {
		t.Errorf("missing program: %+v", r)
	}
	if r = e.Run(ctx, nil, nil, time.Second, false); r.RC != RCNotFound {
		t.Errorf("empty argv: %+v", r)
	}
}

func FuzzQuotePOSIX(f *testing.F) {
	for _, s := range []string{"", "a", "it's", "$(id)", "`x`", "a b\nc", "--opt=1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		q := shQuote(s)
		if s == "" {
			if q != "''" {
				t.Fatal(q)
			}
			return
		}
		if q != s && (!strings.HasPrefix(q, "'") || !strings.HasSuffix(q, "'")) {
			t.Fatalf("unsafe text left unquoted: %q -> %q", s, q)
		}
		if q == s && strings.ContainsAny(s, " \t\n'\"$`\\;&|<>(){}*?[]~#!") {
			t.Fatalf("shell syntax left unquoted: %q", s)
		}
	})
}
