package exposure

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/cloud"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const (
	defaultMaxHosts  = 1024
	tailscaleTimeout = 30 * time.Second
	maxDiscovery     = 16 << 20
)

// Device is one discovered asset (adapters/discovery.py: {name, address, os, online, attrs}). Name, Address and
// OS keep the values the source gave (Address nil when the asset has none); Attrs is a JSON object.
type Device struct {
	Name, Address, OS any
	Online            bool
	Attrs             map[string]any
}

func (d *Device) value() map[string]any {
	return map[string]any{"name": rundoc.Loose(d.Name), "address": rundoc.Loose(d.Address), "os": rundoc.Loose(d.OS),
		"online": d.Online, "attrs": d.Attrs}
}

// pyError is a discovery failure as the reference names it in the coverage gap: "<exception class>: <message>".
type pyError struct{ class, msg string }

func (e *pyError) Error() string { return e.class + ": " + e.msg }

func newPyError(class, format string, args ...any) error {
	return &pyError{class: class, msg: fmt.Sprintf(format, args...)}
}

// discoverer is what discovery adapters need from the run.
type discoverer struct {
	run  RunFunc
	env  rundoc.Env
	home string
}

// discover runs one discovery config.
func (dc *discoverer) discover(ctx context.Context, cfg *pyvalue.Map) ([]Device, error) {
	if !cfg.Has("type") {
		return nil, newPyError("KeyError", "'type'")
	}
	switch t := cfg.Value("type"); t {
	case "static":
		return discoverStatic(cfg)
	case "tailscale":
		return dc.tailscale(ctx)
	case "file":
		return dc.file(cfg)
	case "gcp":
		return dc.gcp(ctx, cfg)
	case "aws-vpc", "azure":
		return nil, newPyError("NotImplementedError", "discovery adapter %s is a documented future adapter", pyvalue.Repr(t))
	default:
		return nil, newPyError("KeyError", "%s", pyvalue.Repr(t))
	}
}

func intOr(v any, def int64) (int64, error) {
	if v == nil {
		return def, nil
	}
	n, err := pyvalue.ToInt(v)
	if err != nil {
		return 0, newPyError("ValueError", "%v", err)
	}
	return n, nil
}

// discoverStatic is the `static` adapter: listed targets, then the host addresses of CIDR ranges.
func discoverStatic(cfg *pyvalue.Map) ([]Device, error) {
	var out []Device
	seen := map[string]bool{}
	for _, t := range rundoc.List(cfg.Value("targets")) {
		m := rundoc.Map(t)
		if !m.Has("address") {
			return nil, newPyError("KeyError", "'address'")
		}
		addr := m.Value("address")
		out = append(out, Device{Name: m.GetOr("name", addr), Address: addr, OS: m.GetOr("os", ""), Online: true,
			Attrs: map[string]any{}})
		seen[pyvalue.Str(addr)] = true
	}
	for _, x := range rundoc.List(cfg.Value("exclude")) {
		seen[pyvalue.Str(x)] = true
	}
	limit, err := intOr(cfg.GetOr("max_hosts", nil), defaultMaxHosts)
	if err != nil {
		return nil, err
	}
	for _, c := range rundoc.List(cfg.Value("cidrs")) {
		devs, err := expandCIDR(c, limit, seen)
		if err != nil {
			return nil, err
		}
		out = append(out, devs...)
	}
	return out, nil
}

func parseNetwork(c any) (netip.Prefix, bool) {
	s, ok := c.(string)
	if !ok {
		return netip.Prefix{}, false
	}
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	p, err := netip.ParsePrefix(s)
	return p.Masked(), err == nil
}

// expandCIDR lists a range's host addresses as ipaddress does: an IPv4 range of more than two addresses without
// its network and broadcast address, an IPv6 one without its first (subnet-router anycast) address.
func expandCIDR(c any, limit int64, seen map[string]bool) ([]Device, error) {
	p, ok := parseNetwork(c)
	if !ok {
		return nil, newPyError("ValueError", "%s does not appear to be an IPv4 or IPv6 network", pyvalue.Repr(c))
	}
	size := new(big.Int).Lsh(big.NewInt(1), uint(p.Addr().BitLen()-p.Bits())) // #nosec G115 -- 0..128
	if size.Cmp(big.NewInt(limit+2)) > 0 {
		return nil, newPyError("ValueError", "CIDR %s has %s addresses (max_hosts %d)", pyvalue.Str(c), size, limit)
	}
	n := size.Int64()
	first, count := p.Addr(), n
	if n > 2 {
		first = first.Next()
		count = n - 1
		if p.Addr().Is4() {
			count = n - 2
		}
	}
	var out []Device
	a := first
	for i := int64(0); i < count; i++ {
		s := a.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, Device{Name: s, Address: s, OS: "", Online: true, Attrs: map[string]any{"cidr": p.String()}})
		}
		a = a.Next()
	}
	return out, nil
}

func (dc *discoverer) tailscale(ctx context.Context) ([]Device, error) {
	res := dc.run(ctx, []string{"tailscale", "status", "--json"}, tailscaleTimeout)
	switch res.RC {
	case 127:
		return nil, newPyError("FileNotFoundError", "[Errno 2] No such file or directory: 'tailscale'")
	case 124:
		return nil, newPyError("TimeoutExpired", "Command '['tailscale', 'status', '--json']' timed out after 30 seconds")
	}
	return ParseTailscale([]byte(res.Out))
}

// ParseTailscale reads `tailscale status --json`: every peer, then the node itself. A peer's address is its first
// IPv4 overlay address; a node whose key never expires is flagged (key_expiry_disabled).
func ParseTailscale(data []byte) ([]Device, error) {
	v, err := pyvalue.DecodeJSON(data)
	if err != nil {
		return nil, newPyError("JSONDecodeError", "%v", err)
	}
	st, ok := v.(*pyvalue.Map)
	if !ok {
		return nil, newPyError("AttributeError", "'%s' object has no attribute 'get'", pyvalue.TypeName(v))
	}
	var out []Device
	peers := rundoc.Map(st.Value("Peer"))
	for _, k := range peers.Keys() {
		p, isMap := peers.Value(k).(*pyvalue.Map)
		if !isMap {
			return nil, newPyError("AttributeError", "'%s' object has no attribute 'get'", pyvalue.TypeName(peers.Value(k)))
		}
		out = append(out, tailscaleDevice(p, false))
	}
	self, ok := st.GetOr("Self", pyvalue.NewMap()).(*pyvalue.Map)
	if !ok {
		return nil, newPyError("AttributeError", "Self is not an object")
	}
	return append(out, tailscaleDevice(self, true)), nil
}

func tailscaleDevice(p *pyvalue.Map, isSelf bool) Device {
	var addr any
	for _, a := range rundoc.List(p.Value("TailscaleIPs")) {
		if s, ok := a.(string); ok && strings.Contains(s, ".") {
			addr = s
			break
		}
	}
	_, hasExpiry := p.Get("KeyExpiry")
	return Device{Name: p.Value("HostName"), Address: addr, OS: p.Value("OS"),
		Online: pyvalue.Truthy(p.Value("Online")) || isSelf,
		Attrs: map[string]any{"self": isSelf, "exit_node_option": pyvalue.Truthy(p.Value("ExitNodeOption")),
			"online_verified": true, "key_expiry_disabled": (!hasExpiry || p.Value("KeyExpiry") == nil) && !isSelf}}
}

// file is the `file` adapter: a JSON list of devices, refused when older than max_age seconds.
func (dc *discoverer) file(cfg *pyvalue.Map) ([]Device, error) {
	if !cfg.Has("path") {
		return nil, newPyError("KeyError", "'path'")
	}
	p := rundoc.ExpandUser(pyvalue.Str(cfg.Value("path")), dc.home)
	st, err := os.Stat(p)
	if err != nil {
		return nil, newPyError("FileNotFoundError", "[Errno 2] No such file or directory: %s", pyvalue.Repr(p))
	}
	age := dc.env.Now().Sub(st.ModTime()).Seconds()
	if maxAge := cfg.Value("max_age"); pyvalue.Truthy(maxAge) {
		limit, ferr := pyvalue.ToFloat(maxAge)
		if ferr != nil {
			return nil, newPyError("ValueError", "%v", ferr)
		}
		if age > limit {
			return nil, newPyError("RuntimeError", "asset list is %ds old (max_age %s)", int64(age), pyvalue.Str(maxAge))
		}
	}
	data, err := rundoc.ReadLimited(p, maxDiscovery)
	if err != nil {
		return nil, newPyError("OSError", "%v", err)
	}
	return parseDeviceList(data)
}

func parseDeviceList(data []byte) ([]Device, error) {
	v, err := pyvalue.DecodeJSON(data)
	if err != nil {
		return nil, newPyError("JSONDecodeError", "%v", err)
	}
	var out []Device
	for _, x := range rundoc.List(v) {
		d, ok := x.(*pyvalue.Map)
		if !ok || !d.Has("name") {
			return nil, newPyError("KeyError", "'name'")
		}
		attrs, ok := rundoc.Loose(d.GetOr("attrs", pyvalue.NewMap())).(map[string]any)
		if !ok {
			return nil, newPyError("AttributeError", "attrs is not an object")
		}
		out = append(out, Device{Name: d.Value("name"), Address: d.Value("address"), OS: d.GetOr("os", ""),
			Online: pyvalue.Truthy(d.GetOr("online", true)), Attrs: attrs})
	}
	return out, nil
}

// gcp is the `gcp` adapter through the Go cloud adapter (internal/cloud): the same login and refusal rules.
func (dc *discoverer) gcp(ctx context.Context, cfg *pyvalue.Map) ([]Device, error) {
	acct, ok := numbersAsJSON(cfg).(map[string]any)
	if !ok {
		return nil, newPyError("ValueError", "gcp discovery config is not an object")
	}
	devs, err := cloud.DiscoverGCP(ctx, cloud.Account(acct), cloud.Deps{Getenv: dc.env.Getenv, Now: dc.env.Now})
	if err != nil {
		return nil, newPyError("CloudAuthError", "%s", cloud.Reason(err))
	}
	out := make([]Device, len(devs))
	for i, d := range devs {
		var addr any
		if d.Address != nil {
			addr = *d.Address
		}
		out[i] = Device{Name: d.Name, Address: addr, OS: d.OS, Online: d.Online, Attrs: d.Attrs}
	}
	return out, nil
}

// numbersAsJSON is the loose JSON shape the cloud adapter reads: mappings as maps, numbers as json.Number.
func numbersAsJSON(v any) any {
	switch x := v.(type) {
	case *pyvalue.Map:
		m := map[string]any{}
		for _, k := range x.Keys() {
			m[k] = numbersAsJSON(x.Value(k))
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = numbersAsJSON(e)
		}
		return out
	case int64:
		return json.Number(strconv.FormatInt(x, 10))
	case float64:
		return json.Number(rundoc.FloatRepr(x))
	default:
		return rundoc.Loose(v)
	}
}

// applyScope is discovery.apply_scope plus the collector's own filter: an asset the instance limits to other
// collectors is dropped, so is an offline asset whose offline state is expected.
func applyScope(devs []Device, scope any) []Device {
	var out []Device
	for _, d := range devs {
		if s := scopeOf(d.Name, scope); s != nil {
			d.Attrs = withScope(d.Attrs, s)
			if !d.Online && s.Value("offline") == "expected" {
				continue
			}
		}
		if inExposureScope(d.Attrs) {
			out = append(out, d)
		}
	}
	return out
}

func scopeOf(name, scope any) *pyvalue.Map {
	for _, x := range rundoc.List(scope) {
		s := rundoc.Map(x)
		if in, err := pyvalue.In(name, rundoc.List(s.Value("names"))); err == nil && in {
			return s
		}
	}
	return nil
}

func withScope(attrs map[string]any, s *pyvalue.Map) map[string]any {
	out := map[string]any{}
	for k, v := range attrs {
		out[k] = v
	}
	out["scope"] = rundoc.Loose(append([]any{}, rundoc.List(s.Value("scope"))...))
	return out
}

// inExposureScope: an asset without a scope is everyone's; one with a scope must name this collector.
func inExposureScope(attrs map[string]any) bool {
	sc, has := attrs["scope"]
	if !has {
		return true
	}
	in, err := pyvalue.In("exposure", sc)
	return err == nil && in
}
