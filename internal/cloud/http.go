package cloud

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"time"
)

const maxErrorBody = 64 << 10 // an error response kept for its reason

// httpClient is the client for one account's provider calls: the injected base client, or a default one with
// time limits; with the account's `ca_file`, the CA certificates in it are trusted in addition to the system's
// (an emulator, a sovereign cloud or a TLS-inspecting proxy with a private CA).
func (b *base) httpClient() (*http.Client, error) {
	if b.deps.HTTP != nil && b.cfg.Str("ca_file") == "" {
		return b.deps.HTTP, nil
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: callTimeout,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if p := b.cfg.Str("ca_file"); p != "" {
		pem, err := readSmallFile(ExpandUser(p, b.deps.home()))
		if err != nil {
			return nil, failf("%s: ca_file unreadable: %s", b.kind, pyExcName(err))
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, failf("%s: ca_file holds no PEM certificate", b.kind)
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{Transport: tr, Timeout: 2 * callTimeout}, nil
}

// errorCapture keeps the URL of the last request that passes through it and, for an error response, its status and
// body (the SDK's own error text is not a stable reason); the body is handed on unchanged. One per acquisition.
type errorCapture struct {
	next   http.RoundTripper
	url    string // the last request's URL, without its query
	status int
	body   []byte
}

func (c *errorCapture) RoundTrip(req *http.Request) (*http.Response, error) {
	u := *req.URL
	u.RawQuery, u.Fragment = "", ""
	c.url, c.status, c.body = u.String(), 0, nil
	resp, err := c.next.RoundTrip(req)
	if err != nil || resp.StatusCode < 400 {
		return resp, err
	}
	data, rerr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	if cerr := resp.Body.Close(); rerr != nil || cerr != nil {
		data = nil // the status alone is then the reason
	}
	c.status, c.body = resp.StatusCode, data
	resp.Body = io.NopCloser(bytes.NewReader(data))
	return resp, nil
}

func transportOf(c *http.Client) http.RoundTripper {
	if c.Transport != nil {
		return c.Transport
	}
	return http.DefaultTransport
}
