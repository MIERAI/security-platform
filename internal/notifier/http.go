package notifier

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const defaultTelegramAPI = "https://api.telegram.org"

// client returns the HTTP client: the injected one, else one with HTTPTimeout that uses the environment's proxy
// settings (as the reference's urllib does).
func client(env Env) *http.Client {
	if env.Client != nil {
		return env.Client
	}
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Client{Timeout: HTTPTimeout}
	}
	return &http.Client{Timeout: HTTPTimeout, Transport: t.Clone()}
}

// post sends one request. The error names the HTTP status or the class of connection failure only: the URL may
// hold a secret (a bot token in the path, a webhook key in the query).
func post(ctx context.Context, env Env, rawURL string, body []byte, ctype string) (err error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("%w: the URL is not an http(s) URL", ErrConfig)
	}
	ctx, cancel := context.WithTimeout(ctx, HTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: cannot build the request", ErrConfig)
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", "security-platform")
	resp, err := client(env).Do(req)
	if err != nil {
		return fmt.Errorf("%w: cannot connect (%s)", ErrDelivery, failureClass(err))
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("%w: close the response: %w", ErrDelivery, cerr)
		}
	}()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%w: HTTP %d", ErrDelivery, resp.StatusCode)
	}
	return nil
}

// failureClass names why a request failed without the URL or any part of it.
func failureClass(err error) string {
	var dnsErr *net.DNSError
	var tlsErr *tls.CertificateVerificationError
	var recErr tls.RecordHeaderError
	var netErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()):
		return "timeout"
	case errors.As(err, &dnsErr):
		return "name resolution"
	case errors.As(err, &tlsErr) || errors.As(err, &recErr):
		return "tls"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Op
	}
	return "connection"
}

// webhook posts to an incoming webhook: slack {"text"} (Slack, Mattermost, Rocket.Chat), json {"title", "text"}
// (Teams workflows, generic receivers), text (ntfy, Gotify-like push).
func webhook(ctx context.Context, env Env, cfg *pyvalue.Map, text string) error {
	var target string
	var err error
	if f := cfg.Value("url_file"); pyvalue.Truthy(f) {
		target, err = secret(env, pyvalue.Str(f))
	} else {
		target, err = required(cfg, "url")
	}
	if err != nil {
		return err
	}
	format := pyvalue.Str(cfg.GetOr("format", "slack"))
	switch format {
	case "slack":
		return post(ctx, env, target, compactJSON("text", text), "application/json")
	case "json":
		title, rest, _ := strings.Cut(text, "\n")
		return post(ctx, env, target, compactJSON("title", title, "text", rest), "application/json")
	case "text":
		return post(ctx, env, target, []byte(text), "text/plain; charset=utf-8")
	}
	return fmt.Errorf("%w: webhook format %s: slack, json or text", ErrConfig, pyvalue.Repr(format))
}

// compactJSON is json.dumps({k: v, ...}) with Python's defaults (", " and ": ", ASCII escapes).
func compactJSON(kv ...string) []byte {
	o := pyjson.NewObject()
	for i := 0; i+1 < len(kv); i += 2 {
		o.Set(kv[i], kv[i+1])
	}
	b, err := pyjson.Marshal(o, pyjson.Compact())
	if err != nil { // not reached: an object of strings always encodes
		return []byte("{}")
	}
	return b
}

// telegram sends the text (its first 4000 characters) through a bot's sendMessage.
func telegram(ctx context.Context, env Env, cfg *pyvalue.Map, text string) error {
	tf, err := required(cfg, "token_file")
	if err != nil {
		return err
	}
	token, err := secret(env, tf)
	if err != nil {
		return err
	}
	var chat string
	if v := cfg.Value("chat_id"); pyvalue.Truthy(v) {
		chat = pyvalue.Str(v)
	} else {
		cf, err := required(cfg, "chat_id_file")
		if err != nil {
			return err
		}
		b, err := readLimited(expandUser(cf, env.Getenv), maxSecret)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrConfig, cf, err)
		}
		chat = strings.TrimSpace(string(b))
	}
	api := strings.TrimRight(pyvalue.Str(cfg.GetOr("api", defaultTelegramAPI)), "/")
	// the reference's field order (urlencode of an ordered dict), not url.Values' sorted one
	body := "chat_id=" + url.QueryEscape(chat) + "&text=" + url.QueryEscape(headChars(text, maxTelegram)) +
		"&disable_web_page_preview=true"
	return post(ctx, env, api+"/bot"+token+"/sendMessage", []byte(body), "application/x-www-form-urlencoded")
}
