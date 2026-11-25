package identity

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
)

const (
	requestTimeout = 60 * time.Second
	maxBody        = 32 << 20 // one API answer
)

// errInsecureURL is returned for an API base that is neither https nor http to a loopback host.
var errInsecureURL = errors.New("must be https (plain http only to a loopback host)")

// apiBase validates a configured API base URL: https, or http to localhost / a loopback address (a local mirror,
// a test server). The token is sent to this host only.
func apiBase(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("api_url %q: not an absolute URL", raw)
	}
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		if loopback(u.Hostname()) {
			return u, nil
		}
	}
	return nil, fmt.Errorf("api_url %q: %w", raw, errInsecureURL)
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// response is one HTTP answer, its body read through the size limit.
type response struct {
	status int
	reason string
	header http.Header
	body   []byte
}

// httpClient returns the client of a run: the injected one (tests), else one that never follows a redirect (the
// token would go along) and uses the environment's proxy settings (loopback hosts never go through a proxy).
func httpClient(env *rundoc.Env) *http.Client {
	if env.HTTP != nil {
		return env.HTTP
	}
	return &http.Client{Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}, Transport: &http.Transport{Proxy: proxyFrom(env), TLSHandshakeTimeout: 15 * time.Second,
		ResponseHeaderTimeout: requestTimeout}}
}

// proxyFrom is http.ProxyFromEnvironment over the run's environment (not the process's).
func proxyFrom(env *rundoc.Env) func(*http.Request) (*url.URL, error) {
	pick := func(names ...string) string {
		for _, n := range names {
			if v := env.Getenv(n); v != "" {
				return v
			}
		}
		return ""
	}
	https, plain, no := pick("HTTPS_PROXY", "https_proxy"), pick("HTTP_PROXY", "http_proxy"), pick("NO_PROXY", "no_proxy")
	return func(r *http.Request) (*url.URL, error) {
		if loopback(r.URL.Hostname()) || noProxy(no, r.URL.Hostname()) {
			return nil, nil
		}
		p := plain
		if r.URL.Scheme == "https" {
			p = https
		}
		if p == "" {
			return nil, nil
		}
		return url.Parse(p)
	}
}

func noProxy(list, host string) bool {
	for _, e := range strings.Split(list, ",") {
		e = strings.TrimPrefix(strings.TrimSpace(e), ".")
		if e == "*" || e != "" && (host == e || strings.HasSuffix(host, "."+e)) {
			return true
		}
	}
	return false
}

// do sends one request with a time limit and reads the answer (at most maxBody bytes).
func do(ctx context.Context, client *http.Client, req *http.Request) (*response, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", req.Method, req.URL.Path, scrub(err))
	}
	body, err := rundoc.ReadAllLimited(resp.Body, maxBody)
	if cerr := resp.Body.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", req.Method, req.URL.Path, err)
	}
	return &response{status: resp.StatusCode, reason: http.StatusText(resp.StatusCode), header: resp.Header, body: body}, nil
}

// scrub drops the URL from a transport error (url.Error): only the cause is kept.
func scrub(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
