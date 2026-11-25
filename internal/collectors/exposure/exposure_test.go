package exposure

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/execad"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

func TestValidTarget(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want bool
	}{
		{"127.0.0.1", true}, {"2001:db8::1", true}, {"fe80::1%eth0", true}, {"web-1.example.org", true}, {"web", true},
		{"-iL/etc/hosts", false}, {"--script=x", false}, {"-", false}, {"", false}, {"a b", false}, {"10.0.0.0/8", false},
		{"web-", false}, {"*.example.org", false}, {"x;rm", false}, {"fe80::1%-x", false}, {strings.Repeat("a.", 130), false},
	}
	for _, tt := range tests {
		if got := ValidTarget(tt.in); got != tt.want {
			t.Errorf("ValidTarget(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestValidPorts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want bool
	}{
		{"80", true}, {"8443,9000-9010", true}, {"1-65535", true}, {"0", false}, {"65536", false}, {"10-5", false},
		{"80,", false}, {"80 81", false}, {"T:80", false}, {"--script", false}, {"", false},
	}
	for _, tt := range tests {
		if got := ValidPorts(tt.in); got != tt.want {
			t.Errorf("ValidPorts(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

const sampleXML = `<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun>
<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="80"><state state="filtered"/><service name="http"/></port>
<port protocol="tcp" portid="81"><state state="closed"/></port>
<port protocol="tcp" portid="9000"><state state="open"/><service method="table"/></port>
<port protocol="tcp" portid="9001"><state state="open"/></port>
<port protocol="tcp" portid="x"><state state="open"/></port></ports></host>
<host timedout="true"><status state="up"/><address addr="10.0.0.2"/></host>
<host><status state="down"/><address addr="10.0.0.3"/></host>
<host><status state="up"/></host></nmaprun>`

func TestParseNmapXML(t *testing.T) {
	t.Parallel()
	s, err := ParseNmapXML([]byte(sampleXML))
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]any{22: "ssh", 9000: nil, 9001: ""}
	if len(s.Open) != 1 || len(s.Open["10.0.0.1"]) != len(want) {
		t.Fatalf("open %v", s.Open)
	}
	for k, v := range want {
		if got, ok := s.Open["10.0.0.1"][k]; !ok || got != v {
			t.Errorf("port %d: %v, want %v", k, got, v)
		}
	}
	if !s.TimedOut["10.0.0.2"] || s.TimedOut["10.0.0.1"] {
		t.Errorf("timed out %v", s.TimedOut)
	}
	for _, bad := range []string{"", "<nmaprun>", `<!DOCTYPE x [<!ENTITY a "b">]><nmaprun>&a;</nmaprun>`} {
		if _, err := ParseNmapXML([]byte(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestExpandCIDR(t *testing.T) {
	t.Parallel()
	tests := []struct {
		cidr  string
		first string
		n     int
	}{
		{"10.0.0.0/30", "10.0.0.1", 2}, {"10.0.0.5/31", "10.0.0.4", 2}, {"10.0.0.7", "10.0.0.7", 1},
		{"2001:db8::/126", "2001:db8::1", 3}, {"2001:db8::/127", "2001:db8::", 2}, {"10.0.0.0/22", "10.0.0.1", 1022},
	}
	for _, tt := range tests {
		devs, err := expandCIDR(tt.cidr, 1024, map[string]bool{})
		if err != nil || len(devs) != tt.n || devs[0].Address != tt.first {
			t.Errorf("%s: %d devices, first %v, err %v", tt.cidr, len(devs), devs, err)
		}
	}
	if _, err := expandCIDR("10.0.0.0/16", 1024, map[string]bool{}); err == nil ||
		err.Error() != "ValueError: CIDR 10.0.0.0/16 has 65536 addresses (max_hosts 1024)" {
		t.Errorf("large range: %v", err)
	}
	if _, err := expandCIDR("2001:db8::/32", 1024, map[string]bool{}); err == nil ||
		!strings.Contains(err.Error(), "has 79228162514264337593543950336 addresses") {
		t.Errorf("huge range: %v", err)
	}
	if _, err := expandCIDR("nope", 1024, map[string]bool{}); err == nil ||
		err.Error() != "ValueError: 'nope' does not appear to be an IPv4 or IPv6 network" {
		t.Errorf("bad range: %v", err)
	}
}

func TestParseTailscale(t *testing.T) {
	t.Parallel()
	devs, err := ParseTailscale([]byte(`{"Peer": {"a": {"HostName": "nas", "TailscaleIPs": ["fd7a::1", "100.64.0.1"], "Online": true},
		"b": {"HostName": "p", "TailscaleIPs": ["fd7a::2"], "KeyExpiry": "2030-01-01T00:00:00Z"}},
		"Self": {"HostName": "me", "TailscaleIPs": ["100.64.0.9"]}}`))
	if err != nil || len(devs) != 3 {
		t.Fatalf("%v %v", devs, err)
	}
	wants := []struct {
		addr          any
		online, noExp bool
	}{{"100.64.0.1", true, true}, {nil, false, false}, {"100.64.0.9", true, false}}
	for i, w := range wants {
		if d := devs[i]; d.Address != w.addr || d.Online != w.online || d.Attrs["key_expiry_disabled"] != w.noExp {
			t.Errorf("device %d %+v", i, d)
		}
	}
	if devs[2].Attrs["self"] != true {
		t.Errorf("self %+v", devs[2])
	}
	if _, err := ParseTailscale([]byte(`[]`)); err == nil {
		t.Error("a list parsed")
	}
}

func TestClassify(t *testing.T) {
	t.Parallel()
	ok := func(snip string) map[string]any {
		return map[string]any{"status": int64(200), "auth": false, "snippet": snip}
	}
	tests := []struct {
		name string
		port int
		e    map[string]any
		want []string
	}{
		{"telnet by port", 23, map[string]any{"nmap_service": "x"}, []string{"telnet.open"}},
		{"db by name", 1234, map[string]any{"nmap_service": "redis"}, []string{"db.reachable"}},
		{"db null name", 6379, map[string]any{"nmap_service": nil}, []string{"db.reachable"}},
		{"smb", 445, map[string]any{"nmap_service": "microsoft-ds"}, []string{"smb.reachable"}},
		{"ssh", 22, map[string]any{"nmap_service": "ssh"}, nil},
		{"root only", 80, map[string]any{"paths": map[string]any{"/": ok("x")}}, []string{"http.unauth_root"}},
		{"root behind auth api", 80, map[string]any{"paths": map[string]any{"/": ok("x"), "/api": map[string]any{"status": int64(401)}}}, nil},
		{"metrics", 80, map[string]any{"paths": map[string]any{"/metrics": ok("x"), "/": ok("y")}}, []string{"metrics.unauth"}},
		{"loki", 80, map[string]any{"paths": map[string]any{"/loki/api/v1/labels": ok(`{"status": "success"}`)}}, []string{"loki.unauth"}},
		{"auth header", 80, map[string]any{"paths": map[string]any{"/": map[string]any{"status": int64(200), "auth": true}}}, nil},
		{"blackbox", 9115, map[string]any{"paths": map[string]any{"/probe": map[string]any{"status": int64(400)}, "/": ok("Blackbox")}},
			[]string{"blackbox.open_probe"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got []string
			for _, v := range Classify(tt.port, tt.e) {
				got = append(got, v.Check)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("%v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecodeReplace(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"abc", "abc"}, {"a\xffb", "a�b"}, {"a\xe2\x82", "a�"}, {"\xf0\x9f\x98", "�"},
		{"\xed\xa0\x80", "���"}, {"\xc3", "�"},
	}
	for _, tt := range tests {
		if got := DecodeReplace([]byte(tt.in)); got != tt.want {
			t.Errorf("DecodeReplace(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestResultRoundTrip(t *testing.T) {
	t.Parallel()
	r := &Result{Targets: []string{"10.0.0.2", "10.0.0.1"}, Tools: map[string]any{"nmap": "Nmap 7"}, TimedOut: []string{"10.0.0.1"},
		Hosts: []Host{{IP: "10.0.0.2", Ports: []Port{{Key: "9", Num: 9, Entry: map[string]any{"nmap_service": "a"}},
			{Key: "10", Num: 10, Entry: map[string]any{"nmap_service": nil}}}}, {IP: "10.0.0.1"}}}
	data, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseResult(data)
	if err != nil {
		t.Fatal(err)
	}
	if back.Hosts[0].IP != "10.0.0.2" || back.Hosts[0].Ports[1].Key != "10" || back.Hosts[1].IP != "10.0.0.1" ||
		!slices.Equal(back.TimedOut, r.TimedOut) {
		t.Errorf("order lost: %s", data)
	}
	for _, bad := range []string{`[]`, `{}`, `{"hosts": []}`, `{"hosts": {"a": {"x": {}}}}`, `{"hosts": {"a": {"1": 2}}}`} {
		if _, err := ParseResult([]byte(bad)); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

// fakeNmap answers like nmap for one open port and records every argument vector.
type fakeNmap struct {
	mu    sync.Mutex
	argvs [][]string
	port  int
}

func (f *fakeNmap) run(_ context.Context, argv []string, _ time.Duration) execad.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.argvs = append(f.argvs, argv)
	if slices.Contains(argv, "--version") {
		return execad.Result{Out: "Nmap version 7.95\nmore"}
	}
	return execad.Result{Out: `<nmaprun><host><address addr="127.0.0.1"/><ports><port portid="` + strconv.Itoa(f.port) +
		`"><state state="open"/><service name="http"/></port></ports></host></nmaprun>`}
}

// TestProbeIsReadOnly: every request the probe sends is a GET without credentials, redirects are not followed
// (the redirect target, which would receive the canary, is never asked) and the answers are described.
func TestProbeIsReadOnly(t *testing.T) {
	t.Parallel()
	canary := "probe-canary-" + "8d1f"
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization")+r.Header.Get("Cookie"))
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/followed?"+canary, http.StatusFound)
		case "/api/v1/status/flags":
			_, _ = w.Write([]byte(`{"data": {"web.enable-admin-api": "true", "other": "` + canary + `"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	port, err := strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	if err != nil {
		t.Fatal(err)
	}
	fn := &fakeNmap{port: port}
	p := &Prober{Run: fn.run, Client: probeClient()}
	res, err := p.Probe(context.Background(), []string{"127.0.0.1"}, "9000-9001")
	if err != nil {
		t.Fatal(err)
	}
	onlyPlainGets(t, seen)
	checkProbeAnswers(t, res, canary)
	if res.Tools["nmap"] != "Nmap version 7.95" || len(fn.argvs) != 3 || !slices.Contains(fn.argvs[1], knownPorts+",9000-9001") {
		t.Errorf("nmap runs %v tools %v", fn.argvs, res.Tools)
	}
	if _, err := p.Probe(context.Background(), []string{"-iL", "x"}, ""); err == nil {
		t.Error("an option as a target was accepted")
	}
	if _, err := p.Probe(context.Background(), []string{"127.0.0.1"}, "1,--script"); err == nil {
		t.Error("an option in the port list was accepted")
	}
}

func TestRemoteArgv(t *testing.T) {
	t.Parallel()
	got := remoteArgv("/opt/sp", "8443", []string{"10.0.0.1"})
	if !slices.Equal(got, []string{"/opt/sp", "exposure", "probe", "--ports", "8443", "10.0.0.1"}) {
		t.Error(got)
	}
}

func TestApplyScope(t *testing.T) {
	t.Parallel()
	scope, err := pyvalue.DecodeJSON([]byte(`[{"names": ["a"], "scope": ["host"]}, {"names": ["b"], "scope": ["exposure"], "offline": "expected"},
		{"names": ["c"], "scope": ["exposure"]}]`))
	if err != nil {
		t.Fatal(err)
	}
	devs := []Device{{Name: "a", Online: true, Attrs: map[string]any{}}, {Name: "b", Attrs: map[string]any{}},
		{Name: "c", Attrs: map[string]any{}}, {Name: "d", Online: true, Attrs: map[string]any{}}}
	var names []any
	for _, d := range applyScope(devs, scope) {
		names = append(names, d.Name)
	}
	if !slices.Equal(names, []any{"c", "d"}) {
		t.Error(names)
	}
}

func TestCollectRefusesInjectedTarget(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	raw := filepath.Join(dir, "probe.json")
	inst := filepath.Join(dir, "instance.json")
	writeFile(t, raw, `{"targets": [], "hosts": {}, "tools": {}}`)
	writeFile(t, inst, `{"exposure": {"discovery": [{"type": "static", "targets": [{"name": "e", "address": "-oN/tmp/x"},
		{"name": "ok", "address": "192.0.2.1"}]}, {"type": "netbox"}]}}`)
	vars := map[string]string{"SP_INSTANCE": inst, "SP_RUN_DIR": filepath.Join(dir, "run"), "SP_EXPOSURE_RAW": raw}
	var stderr bytes.Buffer
	env := &rundoc.Env{Getenv: func(k string) string { return vars[k] }, Stderr: &stderr, Now: time.Now}
	if code := Main(context.Background(), env, []string{"collect"}, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	data, err := os.ReadFile(filepath.Join(dir, "run", "exposure.findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"reason": "refused as a scan target: '-oN/tmp/x' is not an IP address or host name"`,
		`"asset": "discovery:netbox"`, `"reason": "KeyError: 'netbox'"`} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("missing %s in %s", want, data)
		}
	}
}

func writeFile(t *testing.T, p, text string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestProbeUsage(t *testing.T) {
	t.Parallel()
	var out, errb bytes.Buffer
	env := &rundoc.Env{Getenv: func(string) string { return "" }, Stderr: &errb, Now: time.Now}
	if code := Main(context.Background(), env, []string{"probe"}, &out); code != 2 {
		t.Errorf("exit %d", code)
	}
	if code := Main(context.Background(), env, []string{"probe", "--script=x"}, &out); code != 1 || out.Len() != 0 {
		t.Errorf("exit %d, out %q", code, out.String())
	}
}

func TestVersionMatchesTree(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "collectors", "exposure", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != Version {
		t.Fatalf("collectors/exposure/VERSION %s, Go %s", got, Version)
	}
}

// onlyPlainGets: every request was a GET without credentials, and the redirect target was never asked.
func onlyPlainGets(t *testing.T, seen []string) {
	t.Helper()
	for _, s := range seen {
		if !strings.HasPrefix(s, "GET ") || strings.HasPrefix(s, "GET /followed") || !strings.HasSuffix(s, " ") {
			t.Errorf("request %q", s)
		}
	}
}

// checkProbeAnswers: the redirect is described, not followed; only the named flag fields are kept.
func checkProbeAnswers(t *testing.T, res *Result, canary string) {
	t.Helper()
	e := res.Hosts[0].Ports[0].Entry
	paths, _ := e["paths"].(map[string]any)                    // checked through its fields below
	root, _ := paths["/"].(map[string]any)                     // idem
	flags, _ := paths["/api/v1/status/flags"].(map[string]any) // idem
	loc, _ := root["location"].(string)                        // absent: ""
	if root["status"] != int64(302) || !strings.Contains(loc, "/followed") {
		t.Errorf("root %v", root)
	}
	data, err := json.Marshal(flags)
	if err != nil || !bytes.Contains(data, []byte(`"web.enable-admin-api":"true"`)) || bytes.Contains(data, []byte(canary)) {
		t.Errorf("flags keep only the named fields: %s", data)
	}
}
