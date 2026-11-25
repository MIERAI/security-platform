package execadapter

import (
	"reflect"
	"strings"
	"testing"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

func cfg(t *testing.T, yaml string) any {
	t.Helper()
	v, err := pyvalue.DecodeYAML([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func sshArgv(tail ...string) []string {
	return append(append([]string{"ssh"}, sshBase()...), tail...)
}

func TestSSHCommand(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, cfg string
		argv      []string
		want      []string
	}{
		{"posix quoting", "{type: ssh, host: h}", []string{"sh", "-s"}, sshArgv("h", "sh -s")},
		{"options after the fixed ones (ssh takes the first value)",
			"{type: ssh, host: h, options: [-o, StrictHostKeyChecking=no, -i, /k]}", []string{"a b", "it's"},
			sshArgv("-o", "StrictHostKeyChecking=no", "-i", "/k", "h", `'a b' 'it'"'"'s'`)},
		{"cmd.exe quoting", "{type: ssh, host: w, shell: windows}", []string{`C:\P\python.exe`, "-c", "import x", `{"a": 1}`},
			sshArgv("w", `C:\P\python.exe -c "import x" "{\"a\": 1}"`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e, err := New(cfg(t, tt.cfg), nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := e.Command(tt.argv); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Command = %q\nwant      %q", got, tt.want)
			}
		})
	}
}

func TestNewRejects(t *testing.T) {
	t.Parallel()
	tests := []struct{ cfg, want string }{
		{"[local]", "not a mapping"},
		{"{type: telnet}", "unknown exec adapter type 'telnet'"},
		{"{type: ssm}", "documented future adapter"},
		{"{type: ssh}", "needs host"},
		{"{type: ssh, host: 7}", "needs host"},
		{"{type: ssh, host: -oProxyCommand=x}", "read as an option"},
		{"{type: ssh, host: h, options: -v}", "list of arguments"},
		{"{type: ssh, host: h, options: [1]}", "not text"},
	}
	for _, tt := range tests {
		if _, err := New(cfg(t, tt.cfg), nil); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("New(%s) = %v, want an error with %q", tt.cfg, err, tt.want)
		}
	}
	for _, c := range []any{nil, cfg(t, "{}"), cfg(t, "{type: local}")} {
		e, err := New(c, nil)
		if err != nil || !e.Local() {
			t.Errorf("New(%v): local %v, %v", c, e != nil && e.Local(), err)
		}
	}
	if e, err := New(cfg(t, "{type: ssh, host: h}"), nil); err != nil || e.Local() {
		t.Errorf("ssh: %v", err)
	}
}

// TestPowerShellArgv: the bootstrap is byte for byte the Python adapter's (adapters/exec.py PS_BOOTSTRAP).
func TestPowerShellArgv(t *testing.T) {
	t.Parallel()
	want := []string{"powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand",
		"WwBDAG8AbgBzAG8AbABlAF0AOgA6AE8AdQB0AHAAdQB0AEUAbgBjAG8AZABpAG4AZwA9AFsAVABlAHgAdAAuAEUAbgBjAG8AZABpAG4AZwBdADoAOgBVAFQARgA4ADsAJABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAGMAZQA9ACcAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAnADsAJABzAD0AQAAoACQAaQBuAHAAdQB0ACkAIAAtAGoAbwBpAG4AIABbAGMAaABhAHIAXQAxADAAOwBJAG4AdgBvAGsAZQAtAEUAeABwAHIAZQBzAHMAaQBvAG4AIAAkAHMA"}
	if got := PowerShellArgv(); !reflect.DeepEqual(got, want) {
		t.Fatalf("PowerShellArgv = %q", got)
	}
}
