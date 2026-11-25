package exposure

import (
	"slices"
	"strings"
	"testing"
)

func FuzzParseNmapXML(f *testing.F) {
	f.Add([]byte(sampleXML))
	f.Add([]byte(`<nmaprun><host timedout="true"><address addr="::1"/><ports><port portid="65535"><state state="open"/></port></ports></host></nmaprun>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := ParseNmapXML(data)
		if err != nil {
			return
		}
		for _, ports := range s.Open {
			checkPorts(t, ports)
		}
	})
}

func checkPorts(t *testing.T, ports map[int]any) {
	t.Helper()
	for p, svc := range ports {
		if p < 0 || p > 65535 {
			t.Fatalf("port %d", p)
		}
		if _, ok := svc.(string); svc != nil && !ok {
			t.Fatalf("service %T", svc)
		}
	}
}

func FuzzParseTailscale(f *testing.F) {
	f.Add([]byte(`{"Peer": {"a": {"HostName": "n", "TailscaleIPs": ["100.64.0.1"], "Online": true}}, "Self": {}}`))
	f.Add([]byte(`{"Self": {"TailscaleIPs": [1, "x.y"], "KeyExpiry": null}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		devs, err := ParseTailscale(data)
		if err != nil {
			return
		}
		if len(devs) == 0 || devs[len(devs)-1].Attrs["self"] != true {
			t.Fatalf("the node itself is always last: %v", devs)
		}
	})
}

func FuzzParseResult(f *testing.F) {
	f.Add([]byte(`{"targets": ["10.0.0.1"], "hosts": {"10.0.0.1": {"80": {"nmap_service": "http", "paths": {"/": {"status": 200}}}}}, "tools": {"nmap": "x"}}`))
	f.Add([]byte(`{"hosts": {"a": {}}, "timed_out": ["a"]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseResult(data)
		if err != nil {
			return
		}
		for _, h := range r.Hosts {
			for _, p := range h.Ports {
				_ = Classify(p.Num, p.Entry) // never panics on any probe document
			}
		}
		enc, err := r.Encode()
		if err != nil {
			return // a value JSON cannot encode (NaN read from the input)
		}
		back, err := ParseResult(enc)
		if err != nil || len(back.Hosts) != len(r.Hosts) {
			t.Fatalf("round trip: %v %s", err, enc)
		}
	})
}

func FuzzValidTarget(f *testing.F) {
	for _, s := range []string{"127.0.0.1", "-iL", "web-1.example", "fe80::1%eth0", "::ffff:1.2.3.4"} {
		f.Add(s, "80,90-99")
	}
	f.Fuzz(func(t *testing.T, target, ports string) {
		if ValidTarget(target) && (target == "" || target[0] == '-' || slices.Contains([]byte(target), ' ')) {
			t.Fatalf("accepted %q", target)
		}
		if ValidPorts(ports) && !portListShape(ports) {
			t.Fatalf("accepted %q", ports)
		}
	})
}

// portListShape: digits, commas and dashes only, never a leading dash.
func portListShape(ports string) bool {
	if ports == "" || ports[0] == '-' {
		return false
	}
	return strings.Trim(ports, "0123456789,-") == ""
}
