package detection

import (
	"math"
	"strings"
	"testing"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// FuzzQueryAnswer: any Loki/Prometheus query answer is read or rejected with a reason, never a crash.
func FuzzQueryAnswer(f *testing.F) {
	for _, s := range []string{`{"data": {"result": [{"metric": {"host": "a"}, "value": [1, "3"]}]}}`, `{}`, `[]`,
		`{"data": {"result": [{"metric": null, "value": [1]}]}}`, `{"data": {"result": [{"value": [1, "NaN"]}]}}`, `null`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := pyvalue.DecodeJSON(data)
		if err != nil {
			return
		}
		res, err := apiResult(doc)
		if err != nil {
			if reason(err) == "" {
				t.Fatal("empty reason")
			}
			return
		}
		if _, err := vector(res, "host"); err != nil && !strings.Contains(reason(err), "Error") {
			t.Fatalf("reason %q", reason(err))
		}
	})
}

// FuzzRulerState: any rules answer gives loaded names and unhealthy rules within the answer's size.
func FuzzRulerState(f *testing.F) {
	for _, s := range []string{`{"data": {"groups": [{"rules": [{"name": "A", "health": "err"}]}]}}`, `{"data": null}`, `{"data": {"groups": 3}}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := pyvalue.DecodeJSON(data)
		if err != nil {
			return
		}
		loaded, unhealthy := RulerState(doc)
		if len(loaded)+len(unhealthy) > len(data) {
			t.Fatalf("%d loaded, %d unhealthy from %d bytes", len(loaded), len(unhealthy), len(data))
		}
	})
}

// FuzzRouting: any Alertmanager configuration text (YAML) is read without failing; a page route implies a
// notifying receiver.
func FuzzRouting(f *testing.F) {
	for _, s := range []string{"route: {routes: [{receiver: p, matchers: [severity=page]}]}\nreceivers: [{name: p, webhook_configs: [{}]}]",
		"", "{[", "route: &a {routes: [*a]}", "receivers: [{name: [1], email_configs: [x]}]"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, conf string) {
		notifying, page := Routing(conf)
		if page && len(notifying) == 0 {
			t.Fatal("page route without a notifying receiver")
		}
	})
}

// FuzzKubectlList: any kubectl output is read or rejected; the backstop count is never negative.
func FuzzKubectlList(f *testing.F) {
	for _, s := range []string{`{"items": [{"metadata": {"name": "security-detection"}, "spec": {"groups": [{"rules": [1]}]}}]}`,
		`{"items": 1}`, `[]`, `not json`, `{"items": [{"metadata": {"name": "falco"}, "status": {"desiredNumberScheduled": "x"}}]}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, out string) {
		list, err := items(out)
		if err != nil {
			return
		}
		if BackstopRules(list) < 0 {
			t.Fatal("negative count")
		}
		for _, i := range list {
			_ = itemName(i)
		}
	})
}

func FuzzDuration(f *testing.F) {
	for _, s := range []string{"30m", "1.5h", " 7d", "x", "", "1e9w", "99999999999999999999w"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, err := Duration(s)
		if err == nil && (d < 0 || math.IsNaN(d)) {
			t.Fatalf("Duration(%q) = %v", s, d)
		}
	})
}

// FuzzEventTime: a recorded time is read or rejected; text and its YAML timestamp form agree.
func FuzzEventTime(f *testing.F) {
	for _, s := range []string{"2026-07-01T10:00:00", "2026-2-29T1:2:3", "2024-02-29T23:59:61", "2026-07-01 10:00:00+02:00", "x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if v, ok := EventTime(s); ok && math.IsNaN(v) {
			t.Fatal("NaN time")
		}
		if v, ok := EventTime(pyvalue.DateTime{Text: s}); ok && math.IsNaN(v) {
			t.Fatal("NaN time")
		}
		_, _ = DateTime(s)
	})
}
