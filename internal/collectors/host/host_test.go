package host

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/collkit"
	"github.com/MIERAI/security-platform/internal/collectors/execadapter"
	"github.com/MIERAI/security-platform/internal/collectors/spdoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

func TestVersionMatchesTree(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "collectors", "host", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(b)); got != Version {
		t.Fatalf("collectors/host/VERSION %s, Version %s", got, Version)
	}
}

func TestParse(t *testing.T) {
	t.Parallel()
	o := parse("a=1\n  b = two  \nlisten=0.0.0.0:22 sshd\nno equals\nprobe.timeout= x \na=3\r\nlisten= *:5432 pg\n")
	if !reflect.DeepEqual(o.kv.keys, []string{"a", "b "}) || o.kv.vals["a"] != "3" || o.kv.vals["b "] != "two" {
		t.Errorf("kv %v %v", o.kv.keys, o.kv.vals)
	}
	if !reflect.DeepEqual(o.listen, []string{"0.0.0.0:22 sshd", " *:5432 pg"}) || !reflect.DeepEqual(o.timeouts, []string{"x"}) {
		t.Errorf("listen %q timeouts %q", o.listen, o.timeouts)
	}
}

// TestEveryProfileProbeIsKnown: every probe key of every profile feeds a part (a narrow gap when unread) or is
// one of the informational keys no check reads (tests/test_host_probes.py keeps the same list).
func TestEveryProfileProbeIsKnown(t *testing.T) {
	t.Parallel()
	informational := map[string]bool{"os.name": true, "uptime_days": true, "ssh.remote_login": true, "pkg.auto_install_os": true,
		"pkg.auto_security": true, "disk.crypt_devices": true, "audit.auditd": true, "audit.fail2ban": true, "pkg.count": true}
	for _, prof := range []string{"linux", "macos", "termux", "busybox", "windows"} {
		script, err := scriptFor(prof, 20, 90)
		if err != nil {
			t.Fatal(err)
		}
		keys := planned(script)
		if len(keys) == 0 {
			t.Errorf("%s: no probes", prof)
		}
		for _, k := range keys {
			miss := newOrdered()
			miss.set(k, "x")
			if !informational[k] && len(narrowGaps(miss)) == 0 {
				t.Errorf("%s: probe %s feeds no part", prof, k)
			}
		}
	}
	if _, err := scriptFor("probe", 1, 1); err == nil {
		t.Error("the probe helper is not a profile")
	}
	if _, err := scriptFor("../../secrets-files/remote/scan", 1, 1); err == nil {
		t.Error("a path is not a profile")
	}
}

func TestUnreadAndNarrowGaps(t *testing.T) {
	t.Parallel()
	script, err := scriptFor("macos", 20, 90)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, out string
		rc        int
		parts     []string
	}{
		{"complete", "disk.filevault=on\nprobe.end=1\n", 0, nil},
		{"one probe timed out", "pkg.os_updates_pending=unknown\nprobe.timeout=pkg.os_updates_pending\nprobe.end=1\n", 0,
			[]string{"os-updates"}},
		{"stopped after sip", "os.name=x\ndisk.filevault=off\nfw.app_firewall=off\nfw.stealth=on\nsip=on\n", 124,
			[]string{"brew", "gatekeeper", "listeners", "os-updates"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got []string
			for _, g := range narrowGaps(unread(parse(tt.out), script, tt.rc)) {
				got = append(got, g.part)
			}
			if !reflect.DeepEqual(got, tt.parts) {
				t.Errorf("parts %v, want %v", got, tt.parts)
			}
		})
	}
	miss := newOrdered()
	miss.set("disk.filevault", "a")
	miss.set("disk.bitlocker", "b")
	g := narrowGaps(miss)
	if len(g) != 1 || g[0].why != "disk.filevault: a; disk.bitlocker: b" ||
		!reflect.DeepEqual(g[0].checks, []string{"macos.disk_filevault_off", "win.disk_unencrypted"}) {
		t.Errorf("one part from two keys: %+v", g)
	}
}

func TestParseDate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in string
		ok bool
	}{
		{"2020-01-14", true}, {"2020-1-4", true}, {"2020-02-29", true}, {"2021-02-29", false}, {"2020-13-01", false},
		{"2020-00-10", false}, {"2020-01- 5", true}, {"2020-01- 15", false}, {"2020-01-05x", false}, {"20-01-05", false},
		{"0000-01-01", false}, {"last Tuesday", false}, {"", false}, {"2020-01-001", false},
	}
	for _, tt := range tests {
		if _, ok := parseDate(tt.in); ok != tt.ok {
			t.Errorf("parseDate(%q) ok=%v, want %v", tt.in, ok, tt.ok)
		}
	}
}

func TestNum(t *testing.T) {
	t.Parallel()
	tests := map[string]float64{"3": 3, "\t7\n": 7, "2.9": 2, "-2.9": -2, "1_000": 1000, "1e3": 1000, "inf": 0, "nan": 0,
		"0x10": 0, "": 0, "x": 0, "1e20": 1e20}
	for in, want := range tests {
		if got := num(in); got != want {
			t.Errorf("num(%q) = %v, want %v", in, got, want)
		}
	}
}

func newRun(tb testing.TB, now time.Time) *collkit.Run {
	tb.Helper()
	return &collkit.Run{Env: collkit.Env{Stderr: &bytes.Buffer{}, Now: func() time.Time { return now }},
		Inst: pyvalue.NewMap(), Dir: tb.TempDir(), Doc: spdoc.New("host", Version, "", func() time.Time { return now })}
}

func evaluateText(tb testing.TB, profile, out string, rc int, now time.Time) map[string]any {
	tb.Helper()
	r := newRun(tb, now)
	script, err := scriptFor(profile, 20, 90)
	if err != nil {
		tb.Fatal(err)
	}
	tg := &target{name: "m", asset: "host:m", profile: profile, script: script}
	if err := evaluate(r, tg, execadapter.Result{RC: rc, Out: out}); err != nil {
		tb.Fatal(err)
	}
	return r.Doc.Doc(now)
}

func checksOf(doc map[string]any) []string {
	var out []string
	findings, _ := doc["findings"].([]any)
	for _, f := range findings {
		m, _ := f.(map[string]any)
		c, _ := m["check"].(string)
		out = append(out, c)
	}
	return out
}

// TestChecks: the dates are compared in UTC; a value meant as a date that is not one is a narrow gap.
func TestChecks(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name, profile, out string
		want               []string
	}{
		{"hotfix 46 days old", "windows", "pkg.last_hotfix=2026-10-10\nprobe.end=1\n", []string{"patch.windows_stale"}},
		{"hotfix 44.5 days old", "windows", "pkg.last_hotfix=2026-10-12\nprobe.end=1\n", nil},
		{"hotfix not a date", "windows", "pkg.last_hotfix=yesterday\nsmb.v1=True\nprobe.end=1\n", []string{"win.smb1_enabled"}},
		{"android patch", "termux", "os.security_patch=2026-08-01\nprobe.end=1\n", []string{"patch.android_security_patch_old"}},
		{"android patch unknown", "termux", "os.security_patch=unknown\nprobe.end=1\n", nil},
		{"firewall: ufw inactive, nft drop", "linux", "fw.ufw=inactive\nfw.nft_input_policy=drop\nprobe.end=1\n", nil},
		{"firewall: ufw missing, iptables empty", "linux", "fw.ufw=\nfw.iptables_input_policy=\nprobe.end=1\n", []string{"fw.host_firewall_off"}},
		{"listeners", "linux", "listen=0.0.0.0:5432 pg\nlisten=::1:6379 r\nlisten=[::]:27017 m\nlisten=*:x y\nprobe.end=1\n",
			[]string{"listen.db_wildcard.5432", "listen.db_wildcard.27017"}},
		{"security updates win over pending", "linux", "pkg.upgradable=9\npkg.security_upgradable=2.5\nprobe.end=1\n",
			[]string{"patch.security_pending"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := checksOf(evaluateText(t, tt.profile, tt.out, 0, now)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("checks %v, want %v", got, tt.want)
			}
		})
	}
	doc := evaluateText(t, "windows", "pkg.last_hotfix=yesterday\nprobe.end=1\n", 0, now)
	data, err := json.Marshal(doc["coverage"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"asset":"host:m/windows-updates","checks":["patch.windows_stale"]`) {
		t.Errorf("no narrow gap for an unreadable date: %s", data)
	}
}

// FuzzEvaluate runs arbitrary profile output (POSIX and PowerShell profiles, finished or stopped) through parsing,
// gaps and checks: no panic, no error, and a check reported never belongs to a part that is a gap.
func FuzzEvaluate(f *testing.F) {
	f.Add("macos", "disk.filevault=off\nprobe.timeout=sip\nprobe.end=1\n", 0)
	f.Add("windows", "fw.profile_public=off\r\nav.signature_age_days=9\r\npkg.last_hotfix=2001-02-30\r\n", 124)
	f.Add("linux", "listen=0.0.0.0:5432 x\nfw.ufw=inactive\nsshd.passwordauthentication=yes\n", 1)
	f.Add("termux", "os.security_patch=2020-99-99\nproc.secret_in_argv_suspects=1e400\n", 0)
	f.Fuzz(func(t *testing.T, profile, out string, rc int) {
		if _, err := scriptFor(profile, 20, 90); err != nil {
			return
		}
		doc := evaluateText(t, profile, out, rc, time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC))
		cov, _ := doc["coverage"].([]any)
		var blocked []string
		for _, c := range cov {
			m, _ := c.(map[string]any)
			if checks, ok := m["checks"].([]string); ok {
				blocked = append(blocked, checks...)
			}
		}
		for _, c := range checksOf(doc) {
			if matchAny(c, blocked) {
				t.Fatalf("finding %s although its part is a gap (%v)", c, blocked)
			}
		}
		if _, err := spdoc.Marshal(doc, 1, true); err != nil {
			t.Fatal(err)
		}
	})
}
