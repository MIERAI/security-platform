package events

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"sort"
	"time"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// metaKeys is the structured metadata of each stream kind (docs/detection.md "Log contract"), in order.
func metaKeys(label string) []string {
	switch label {
	case "auth":
		return []string{"event", "user", "src_ip", "novel"}
	case "codehost":
		return []string{"event", "actor", "repo"}
	default:
		return []string{"event", "actor"}
	}
}

// nanos is str(int(ts * 1e9)).
func nanos(ts float64) string {
	x := ts * 1e9
	if math.Abs(x) < 9e18 {
		return fmt.Sprint(int64(x))
	}
	i, _ := big.NewFloat(x).Int(nil) // finite: ts comes from parsed times and --now
	return i.String()
}

// toStream is ship.py to_streams: one stream (labels source, host) with the events in time order.
func toStream(label string, host any, evs []*event) *pyvalue.Map {
	sorted := append([]*event(nil), evs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ts < sorted[j].ts })
	vals := make([]any, 0, len(sorted))
	for _, e := range sorted {
		md := pyvalue.NewMap()
		for _, k := range metaKeys(label) {
			if v := e.get(k); v != nil && v != "" {
				md.Set(k, pyvalue.Str(v))
			}
		}
		if md.Len() > 0 {
			vals = append(vals, []any{nanos(e.ts), e.line, md})
		} else {
			vals = append(vals, []any{nanos(e.ts), e.line})
		}
	}
	labels := pyvalue.NewMap()
	labels.Set("source", label)
	labels.Set("host", host)
	s := pyvalue.NewMap()
	s.Set("stream", labels)
	s.Set("values", vals)
	return s
}

// pusher sends streams to the Loki push API: POST to that URL only, in batches, with the bearer token of a 0600
// file. A batch the store does not accept (anything but 2xx) is an error: the caller keeps the cursor.
type pusher struct {
	url     string
	token   string
	batch   int64
	timeout time.Duration
	client  *http.Client
}

func newPusher(loki *pyvalue.Map, d *deps) (*pusher, error) {
	u, ok := loki.Get("url")
	if !ok {
		return nil, keyError("url")
	}
	p := &pusher{url: pyvalue.Str(u)}
	if f := loki.Value("token_file"); pyvalue.Truthy(f) {
		tok, err := readSecret(pyvalue.Str(f), d.home)
		if err != nil {
			return nil, err
		}
		p.token = tok
	}
	batch, err := pyvalue.ToInt(loki.GetOr("batch", int64(500)))
	if err != nil || batch <= 0 {
		return nil, pyErr("ValueError", "batch must be a positive integer")
	}
	timeout, err := pyvalue.ToInt(loki.GetOr("timeout", int64(15)))
	if err != nil {
		return nil, pyErr("ValueError", "timeout must be an integer")
	}
	p.batch, p.timeout, p.client = batch, time.Duration(timeout)*time.Second, d.client(p.url)
	return p, nil
}

func (p *pusher) push(ctx context.Context, streams []*pyvalue.Map) error {
	for _, s := range streams {
		vals, _ := s.Value("values").([]any) // built by toStream
		for i := int64(0); i < int64(len(vals)); i += p.batch {
			if err := p.send(ctx, s.Value("stream"), vals[i:min(i+p.batch, int64(len(vals)))]); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *pusher) send(ctx context.Context, labels any, vals []any) error {
	one := pyvalue.NewMap()
	one.Set("stream", labels)
	one.Set("values", vals)
	doc := pyvalue.NewMap()
	doc.Set("streams", []any{one})
	body, err := dumps(doc, defaultJSON())
	if err != nil {
		return fmt.Errorf("encode push body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader([]byte(body)))
	if err != nil {
		return pyErr("ValueError", "unknown url type: "+pyvalue.Repr(p.url))
	}
	req.Header.Set("Content-Type", "application/json")
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	r, err := send(ctx, p.client, req, p.timeout)
	if err != nil {
		return err
	}
	if r.status/100 != 2 {
		return httpError(r)
	}
	return nil
}
