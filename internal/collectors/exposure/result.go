package exposure

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Result is what the probe saw from the vantage point (the JSON document vantage_probe.py prints): per target,
// its open ports in port order, each with nmap's service name and, for an HTTP(S) service, the answers to the
// fingerprint GETs. TimedOut lists the addresses nmap gave up on (only present when there is one).
type Result struct {
	Targets  []string
	Hosts    []Host
	Tools    map[string]any
	TimedOut []string
}

// Host is one probed address.
type Host struct {
	IP    string
	Ports []Port
}

// Port is one open port: Key is its text as the document spells it, Entry {nmap_service, scheme?, paths?}.
type Port struct {
	Key   string
	Num   int
	Entry map[string]any
}

// errResult is the error class of a probe document that is not one.
var errResult = errors.New("not a probe result")

// maxResult bounds a probe document read from a file or a remote probe.
const maxResult = 64 << 20

// ParseResult reads a probe document (SP_EXPOSURE_RAW, or the output of `sp exposure probe` on a vantage host),
// keeping the order of its hosts and ports.
func ParseResult(data []byte) (*Result, error) {
	v, err := pyvalue.DecodeJSON(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errResult, err)
	}
	root, ok := v.(*pyvalue.Map)
	if !ok {
		return nil, fmt.Errorf("%w: not an object", errResult)
	}
	hosts, ok := root.Value("hosts").(*pyvalue.Map)
	if !ok {
		return nil, fmt.Errorf("%w: no hosts object", errResult)
	}
	r := &Result{Targets: rundoc.Texts(root.Value("targets")), Tools: map[string]any{}}
	if t, ok := root.Value("tools").(*pyvalue.Map); ok {
		for _, k := range t.Keys() {
			r.Tools[k] = rundoc.Loose(t.Value(k))
		}
	}
	r.TimedOut = rundoc.Texts(root.Value("timed_out"))
	for _, ip := range hosts.Keys() {
		h, err := parseHost(ip, hosts.Value(ip))
		if err != nil {
			return nil, err
		}
		r.Hosts = append(r.Hosts, h)
	}
	return r, nil
}

func parseHost(ip string, v any) (Host, error) {
	ports, ok := v.(*pyvalue.Map)
	if !ok {
		return Host{}, fmt.Errorf("%w: hosts[%q] is not an object", errResult, ip)
	}
	h := Host{IP: ip}
	for _, k := range ports.Keys() {
		n, err := strconv.Atoi(k)
		if err != nil || n < 0 || n > 65535 {
			return Host{}, fmt.Errorf("%w: hosts[%q]: port %q", errResult, ip, k)
		}
		e, ok := rundoc.Loose(ports.Value(k)).(map[string]any)
		if !ok {
			return Host{}, fmt.Errorf("%w: hosts[%q][%q] is not an object", errResult, ip, k)
		}
		h.Ports = append(h.Ports, Port{Key: k, Num: n, Entry: e})
	}
	return h, nil
}

// Value is the document as a JSON value (evidence probe.json).
func (r *Result) Value() map[string]any {
	hosts := map[string]any{}
	for _, h := range r.Hosts {
		ports := map[string]any{}
		for _, p := range h.Ports {
			ports[p.Key] = p.Entry
		}
		hosts[h.IP] = ports
	}
	targets := make([]any, len(r.Targets))
	for i, t := range r.Targets {
		targets[i] = t
	}
	v := map[string]any{"targets": targets, "hosts": hosts, "tools": r.Tools}
	if len(r.TimedOut) > 0 {
		t := make([]any, len(r.TimedOut))
		for i, x := range r.TimedOut {
			t[i] = x
		}
		v["timed_out"] = t
	}
	return v
}

// Encode writes the document as JSON with hosts and ports in their order (the collector reads them in it).
func (r *Result) Encode() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(`{"targets": `)
	if err := writeJSON(&b, r.Targets); err != nil {
		return nil, err
	}
	b.WriteString(`, "hosts": {`)
	for i, h := range r.Hosts {
		if i > 0 {
			b.WriteString(", ")
		}
		if err := writeHost(&b, h); err != nil {
			return nil, err
		}
	}
	b.WriteString(`}, "tools": `)
	if err := writeJSON(&b, r.Tools); err != nil {
		return nil, err
	}
	if len(r.TimedOut) > 0 {
		b.WriteString(`, "timed_out": `)
		if err := writeJSON(&b, r.TimedOut); err != nil {
			return nil, err
		}
	}
	b.WriteString("}")
	return b.Bytes(), nil
}

func writeHost(b *bytes.Buffer, h Host) error {
	if err := writeJSON(b, h.IP); err != nil {
		return err
	}
	b.WriteString(": {")
	for j, p := range h.Ports {
		if j > 0 {
			b.WriteString(", ")
		}
		if err := writeJSON(b, p.Key); err != nil {
			return err
		}
		b.WriteString(": ")
		if err := writeJSON(b, p.Entry); err != nil {
			return err
		}
	}
	b.WriteString("}")
	return nil
}

func writeJSON(b *bytes.Buffer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode probe result: %w", err)
	}
	b.Write(data)
	return nil
}
