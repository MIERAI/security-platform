package exposure

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/MIERAI/security-platform/internal/collectors/execad"
	"github.com/MIERAI/security-platform/internal/collectors/roclient"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// knownPorts are scanned on top of nmap's top 1000 (remote/vantage_probe.py KNOWN).
const knownPorts = "22,53,80,139,443,445,2379,3000,3080,3100,3200,4317,4318,5335,5432,6443,8022,8080,8085,8384,8443,8770," +
	"8888,9090,9091,9093,9100,9115,9195,10250,10255,11434,11435,18080-18082,19090,30080-30090,30115"

const (
	nmapTimeout    = 30 * time.Minute
	hostTimeout    = "30m" // nmap --host-timeout: a host nmap gives up on is reported, not waited for
	versionTimeout = time.Minute
	getTimeout     = 4 * time.Second
	snippetBytes   = 160
	bodyBytes      = 2048
	keepBodyBytes  = 65536
	userAgent      = "security-platform-probe/0"
)

// probePaths are the GETs sent to an HTTP(S) port: "/" first. GET only; write endpoints show as a 405 to GET.
func probePaths() []string {
	return []string{"/", "/metrics", "/api/v1/status/buildinfo", "/api/v2/status", "/api/tags", "/api/v1/applications",
		"/api/search", "/status", "/api/v1/write", "/loki/api/v1/labels", "/loki/api/v1/push", "/v1/traces",
		"/probe", "/api/health", "/api/v1/status/flags"}
}

// keepFields: the fields kept from specific JSON answers (everything else is dropped).
func keepFields(path string) []string {
	if path == "/api/v1/status/flags" {
		return []string{"web.enable-remote-write-receiver", "web.enable-admin-api", "web.enable-lifecycle"}
	}
	return nil
}

// noHTTPPorts are not fingerprinted over HTTP (ssh, dns, smb, postgres, etcd).
func noHTTPPorts() []int { return []int{22, 8022, 53, 139, 445, 5432, 2379} }

// RunFunc runs a program (nmap) with a timeout.
type RunFunc func(ctx context.Context, argv []string, timeout time.Duration) execad.Result

// Prober is the probe: nmap from this host, then GETs.
type Prober struct {
	Run    RunFunc
	Client *http.Client
}

// NewProber is the probe with local programs and the fingerprinting client.
func NewProber() (*Prober, error) {
	local, err := execad.FromConfig(nil)
	if err != nil {
		return nil, err
	}
	run := func(ctx context.Context, argv []string, timeout time.Duration) execad.Result {
		return local.Run(ctx, argv, nil, timeout, false)
	}
	return &Prober{Run: run, Client: probeClient()}, nil
}

// probeClient sends GETs only, follows no redirect, uses no proxy and accepts any certificate: it asks what
// answers on an address, it sends no credential and trusts nothing it reads.
func probeClient() *http.Client {
	t := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: getTimeout}).DialContext,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- fingerprinting what answers, no credential is sent
		TLSHandshakeTimeout: getTimeout,
		DisableKeepAlives:   true,
	}
	return &http.Client{Transport: roclient.ReadOnly(t),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func nmapArgv(targets []string, ports ...string) []string {
	argv := []string{"nmap", "-sT", "-Pn", "-n", "-T3", "--max-rate", "60", "--max-retries", "1", "--host-timeout",
		hostTimeout, "--open", "-oX", "-"}
	argv = append(argv, ports...)
	return append(argv, targets...)
}

func (p *Prober) nmap(ctx context.Context, targets []string, ports ...string) (Scan, error) {
	res := p.Run(ctx, nmapArgv(targets, ports...), nmapTimeout)
	scan, err := ParseNmapXML([]byte(res.Out))
	if err != nil {
		return Scan{}, fmt.Errorf("nmap rc=%d: %w: %s", res.RC, err, tail(res.Err, 200))
	}
	return scan, nil
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// Probe scans the targets (validated: addresses or host names) and fingerprints the HTTP(S) ports.
func (p *Prober) Probe(ctx context.Context, targets []string, extra string) (*Result, error) {
	for _, t := range targets {
		if !ValidTarget(t) {
			return nil, fmt.Errorf("refused target %q: not an address or host name", t)
		}
	}
	ports := knownPorts
	if extra != "" {
		if !ValidPorts(extra) {
			return nil, fmt.Errorf("refused port list %q", extra)
		}
		ports += "," + extra
	}
	top, err := p.nmap(ctx, targets, "--top-ports", "1000")
	if err != nil {
		return nil, err
	}
	known, err := p.nmap(ctx, targets, "-p", ports)
	if err != nil {
		return nil, err
	}
	ver := strings.SplitN(p.Run(ctx, []string{"nmap", "--version"}, versionTimeout).Out, "\n", 2)[0]
	r := &Result{Targets: targets, Tools: map[string]any{"nmap": ver}}
	seen := map[string]bool{}
	for _, ip := range targets {
		if seen[ip] {
			continue
		}
		seen[ip] = true
		r.Hosts = append(r.Hosts, p.host(ctx, ip, merge(top.Open[ip], known.Open[ip])))
		if top.TimedOut[ip] || known.TimedOut[ip] {
			r.TimedOut = append(r.TimedOut, ip)
		}
	}
	return r, nil
}

func merge(a, b map[int]any) map[int]any {
	out := map[int]any{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func (p *Prober) host(ctx context.Context, ip string, open map[int]any) Host {
	nums := make([]int, 0, len(open))
	for n := range open {
		nums = append(nums, n)
	}
	slices.Sort(nums)
	h := Host{IP: ip}
	for _, n := range nums {
		e := map[string]any{"nmap_service": open[n]}
		if !slices.Contains(noHTTPPorts(), n) {
			if scheme, root := p.isHTTP(ctx, ip, n); scheme != "" {
				e["scheme"] = scheme
				paths := map[string]any{"/": root}
				for _, path := range probePaths()[1:] {
					paths[path] = p.get(ctx, baseURL(scheme, ip, n)+path, keepFields(path))
				}
				e["paths"] = paths
			}
		}
		h.Ports = append(h.Ports, Port{Key: strconv.Itoa(n), Num: n, Entry: e})
	}
	return h
}

func baseURL(scheme, ip string, port int) string {
	return scheme + "://" + net.JoinHostPort(ip, strconv.Itoa(port))
}

// isHTTP finds the scheme a port answers HTTP on: http, else https; a 400 to plain http ("HTTP request sent to an
// HTTPS port") is kept only when https does not answer.
func (p *Prober) isHTTP(ctx context.Context, ip string, port int) (string, map[string]any) {
	var firstScheme string
	var first map[string]any
	for _, scheme := range []string{"http", "https"} {
		r := p.get(ctx, baseURL(scheme, ip, port)+"/", nil)
		st, ok := r["status"]
		if !ok {
			continue
		}
		if st == int64(http.StatusBadRequest) && scheme == "http" {
			if first == nil {
				firstScheme, first = scheme, r
			}
			continue
		}
		return scheme, r
	}
	return firstScheme, first
}

// get sends one GET and describes the answer as the reference does: status, whether it asks for credentials, the
// Server and Content-Type headers and the first bytes (2xx); status, auth, Server and Location (otherwise); or the
// class of error. With keep, the named fields of a JSON answer's "data" object instead.
func (p *Prober) get(ctx context.Context, url string, keep []string) map[string]any {
	ctx, cancel := context.WithTimeout(ctx, getTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return map[string]any{"error": "ValueError"}
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := p.Client.Do(req)
	if err != nil {
		return map[string]any{"error": errorName(err)}
	}
	out, err := describe(resp, keep)
	if cerr := resp.Body.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if err != nil {
		return map[string]any{"error": errorName(err)}
	}
	return out
}

func describe(resp *http.Response, keep []string) (map[string]any, error) {
	_, auth := resp.Header["Www-Authenticate"]
	status := int64(resp.StatusCode)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return map[string]any{"status": status, "auth": auth, "server": resp.Header.Get("Server"),
			"location": resp.Header.Get("Location")}, nil
	}
	limit := int64(bodyBytes)
	if keep != nil {
		limit = keepBodyBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if keep != nil {
		if fields, ok := jsonFields(body, keep); ok {
			return map[string]any{"status": status, "auth": false, "fields": fields}, nil
		}
	}
	snippet := body
	if len(snippet) > snippetBytes {
		snippet = snippet[:snippetBytes]
	}
	return map[string]any{"status": status, "auth": auth, "server": resp.Header.Get("Server"),
		"ctype": resp.Header.Get("Content-Type"), "snippet": DecodeReplace(snippet)}, nil
}

// jsonFields is {k: data.get(k)} of a JSON object's "data" object; false when the body is not that shape.
func jsonFields(body []byte, keep []string) (map[string]any, bool) {
	v, err := pyvalue.DecodeJSON(body)
	if err != nil {
		return nil, false
	}
	root, ok := v.(*pyvalue.Map)
	if !ok {
		return nil, false
	}
	data := any(pyvalue.NewMap())
	if root.Has("data") {
		data = root.Value("data")
	}
	m, ok := data.(*pyvalue.Map)
	if !ok {
		return nil, false
	}
	out := map[string]any{}
	for _, k := range keep {
		out[k] = rundoc.Loose(m.Value(k))
	}
	return out, true
}

// errorName names a failed GET the way the reference's evidence does (the Python exception class): a timeout,
// a connection closed without an answer, a malformed answer, anything else.
func errorName(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout():
		return "TimeoutError"
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		return "RemoteDisconnected"
	case strings.Contains(err.Error(), "malformed HTTP"):
		return "BadStatusLine"
	default:
		return "URLError"
	}
}

// DecodeReplace is bytes.decode("utf-8", "replace"): each maximal invalid subsequence becomes one U+FFFD.
func DecodeReplace(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			size = maximalSubpart(b)
		}
		sb.WriteRune(r)
		b = b[size:]
	}
	return sb.String()
}

// maximalSubpart is the length of the invalid sequence at the start of b that Python replaces with one U+FFFD:
// a valid lead byte and the continuation bytes that may follow it, cut short.
func maximalSubpart(b []byte) int {
	lead := b[0]
	var need int
	lo, hi := byte(0x80), byte(0xbf)
	switch {
	case lead >= 0xc2 && lead <= 0xdf:
		need = 1
	case lead >= 0xe0 && lead <= 0xef:
		need = 2
		lo, hi = secondRange(lead)
	case lead >= 0xf0 && lead <= 0xf4:
		need = 3
		lo, hi = secondRange(lead)
	default:
		return 1
	}
	n := 1
	for i := 1; i <= need && i < len(b); i++ {
		if b[i] < lo || b[i] > hi {
			break
		}
		lo, hi = 0x80, 0xbf
		n++
	}
	return n
}

func secondRange(lead byte) (lo, hi byte) {
	switch lead {
	case 0xe0:
		return 0xa0, 0xbf
	case 0xed:
		return 0x80, 0x9f
	case 0xf0:
		return 0x90, 0xbf
	case 0xf4:
		return 0x80, 0x8f
	}
	return 0x80, 0xbf
}
