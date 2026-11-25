package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

const maxGoogleResponse = 64 << 20 // one page of an inventory listing

// apiRequest is one REST call: method, URL (with its query) and the JSON body (nil for none).
type apiRequest struct {
	method, url string
	in          any
}

// googleError is a non-200 answer of a Google API.
type googleError struct {
	status int
	body   []byte
}

func (e *googleError) Error() string { return "HTTP " + strconv.Itoa(e.status) + " " + ErrText(e.body) }

// googleJSON calls one Google REST method (JSON in, JSON out) with an authenticated client. The three read-only
// methods the adapter uses after authentication (getIamPolicy, searchAllResources, instances.aggregatedList) are
// plain JSON over HTTPS; the provider rules that matter (token exchange, ADC refresh, impersonation) are
// golang.org/x/oauth2/google's (docs/go.md: why google.golang.org/api is not used).
func googleJSON(ctx context.Context, client *http.Client, r apiRequest, out any) error {
	var body io.Reader
	if r.in != nil {
		data, err := json.Marshal(r.in)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, r.method, r.url, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if r.in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() // #nosec G104 -- fully read below; a close error loses nothing
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxGoogleResponse))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return &googleError{status: resp.StatusCode, body: data}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// googleReason is "HTTP <status> <status name>: <message>" for a Google API error, else why it was unreachable.
func googleReason(err error, url string) string {
	var ge *googleError
	if errors.As(err, &ge) {
		return ge.Error()
	}
	return hostOf(url) + " unreachable (" + errorKind(err) + ")"
}
