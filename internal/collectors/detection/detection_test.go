package detection

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/MIERAI/security-platform/internal/collectors/roclient"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

func TestDuration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   any
		want float64
		err  bool
	}{
		{"30m", 1800, false}, {"1.5h", 5400, false}, {" 2d ", 172800, false}, {"1w", 604800, false},
		{int64(90), 90, false}, {12.5, 12.5, false}, {true, 1, false},
		{"5", 0, true}, {"5x", 0, true}, {nil, 0, true}, {"-1d", 0, true}, {"1d1h", 0, true},
	}
	for _, tt := range tests {
		got, err := Duration(tt.in)
		if (err != nil) != tt.err || got != tt.want {
			t.Errorf("Duration(%#v) = %v, %v", tt.in, got, err)
		}
		if err != nil && !errors.Is(err, ErrDuration) {
			t.Errorf("Duration(%#v): error %v is not ErrDuration", tt.in, err)
		}
	}
}

func TestEventTime(t *testing.T) {
	t.Parallel()
	const summer = 1782900000 // 2026-07-01T10:00:00Z
	tests := []struct {
		name string
		in   any
		want float64
		ok   bool
	}{
		{"text", "2026-07-01T10:00:00", summer, true},
		{"text with zone is cut at 19", "2026-07-01T10:00:00Z", summer, true},
		{"lower-case t", "2026-07-01t10:00:00", summer, true},
		{"one-digit fields", "2026-7-1T10:0:0", summer, true},
		{"leap second rolls over", "2026-07-01T09:59:60", summer, true},
		{"space separator is not the format", "2026-07-01 10:00:00", 0, false},
		{"day out of range", "2026-02-30T10:00:00", 0, false},
		{"hour out of range", "2026-07-01T24:00:00", 0, false},
		{"date only", "2026-07-01", 0, false},
		{"yaml timestamp with offset", pyvalue.DateTime{Text: "2026-07-01 12:00:00+02:00"}, summer, true},
		{"yaml timestamp without offset is UTC", pyvalue.DateTime{Text: "2026-07-01 10:00:00"}, summer, true},
		{"yaml timestamp fraction", pyvalue.DateTime{Text: "2026-07-01 10:00:00.500000+00:00"}, summer + 0.5, true},
		{"yaml date", pyvalue.Date{Year: 2026, Month: 7, Day: 1}, 0, false},
		{"number", int64(summer), 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := EventTime(tt.in)
			if ok != tt.ok || got != tt.want {
				t.Errorf("EventTime(%#v) = %v, %v; want %v, %v", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestDateTime(t *testing.T) {
	t.Parallel()
	if got, ok := DateTime("2026-11-24"); !ok || got != 1795478400 {
		t.Errorf("DateTime = %v %v", got, ok)
	}
	if _, ok := DateTime("2026-11-24 junk"); !ok {
		t.Error("only the first 10 characters count")
	}
	if _, ok := DateTime(""); ok {
		t.Error("empty is not a date")
	}
}

func TestAlertName(t *testing.T) {
	t.Parallel()
	tests := map[string]string{"k8s-pod-exec": "SecurityDetectionK8sPodExec", "auth_sudo-FAILURE": "SecurityDetectionAuthSudoFailure",
		"": "SecurityDetection", "a--b": "SecurityDetectionAB"}
	for in, want := range tests {
		if got := AlertName(in); got != want {
			t.Errorf("AlertName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestQuery(t *testing.T) {
	t.Parallel()
	if got := Query("auth", "host", "1d"); got != `sum by (host) (count_over_time({source="auth"}[1d]))` {
		t.Error(got)
	}
}

func TestRouting(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, conf string
		notifying  []string
		page       bool
	}{
		{"nested page route to a pager", "route: {receiver: a, routes: [{receiver: b, routes: [{receiver: p, matchers: ['severity = \"page\"']}]}]}\n" +
			"receivers: [{name: a}, {name: p, webhook_configs: [{url: x}]}]", []string{"p"}, true},
		{"unquoted matcher", "route: {routes: [{receiver: p, matchers: [severity=page]}]}\nreceivers: [{name: p, email_configs: [{to: x}]}]", []string{"p"}, true},
		{"page route to a silent receiver", "route: {routes: [{receiver: s, matchers: [severity=page]}]}\nreceivers: [{name: s}, {name: e, email_configs: [{}]}]", []string{"e"}, false},
		{"empty configs do not notify", "route: {routes: [{receiver: s, matchers: [severity=page]}]}\nreceivers: [{name: s, webhook_configs: []}]", nil, false},
		{"not YAML", "{[", nil, false},
		{"empty", "", nil, false},
		{"not a mapping", "- a", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			n, p := Routing(tt.conf)
			if !slices.Equal(n, tt.notifying) || p != tt.page {
				t.Errorf("Routing = %v %v, want %v %v", n, p, tt.notifying, tt.page)
			}
		})
	}
}

func TestKubectlArgv(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kc   string
		want []string
		err  bool
	}{
		{"", []string{"kubectl", "get"}, false},
		{"in-cluster", []string{"kubectl", "get"}, false},
		{"/k/c.yaml", []string{"kubectl", "--kubeconfig=/k/c.yaml", "get"}, false},
		{"--token=x", nil, true},
		{"a\nb", nil, true},
	}
	for _, tt := range tests {
		got, err := KubectlArgv(tt.kc, []string{"get"})
		if (err != nil) != tt.err || !slices.Equal(got, tt.want) {
			t.Errorf("KubectlArgv(%q) = %v, %v", tt.kc, got, err)
		}
	}
}

func TestVectorAndRuler(t *testing.T) {
	t.Parallel()
	doc, err := pyvalue.DecodeJSON([]byte(`{"data": {"result": [{"metric": {"host": "a"}, "value": [1, "3"]},
		{"metric": {}, "value": [1, "0.5"]}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := apiResult(doc)
	if err != nil {
		t.Fatal(err)
	}
	v, err := vector(res, "host")
	if err != nil || v["a"] != 3 || v[""] != 0.5 {
		t.Errorf("vector = %v, %v", v, err)
	}
}

func TestAPIResultErrors(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{`{}`: "KeyError: 'data'", `{"data": {}}`: "KeyError: 'result'", `[]`: "TypeError"} {
		d, _ := pyvalue.DecodeJSON([]byte(in))
		if _, err := apiResult(d); err == nil || !strings.HasPrefix(reason(err), want) {
			t.Errorf("apiResult(%s) = %v, want %s", in, err, want)
		}
	}
	bad, err := pyvalue.DecodeJSON([]byte(`[{"metric": {}, "value": [1, "x"]}]`))
	badList, ok := bad.([]any)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if _, err := vector(badList, "h"); err == nil || reason(err) != "ValueError: could not convert string to float: 'x'" {
		t.Errorf("bad value: %v", err)
	}
}

func TestRulerStateOfRules(t *testing.T) {
	t.Parallel()
	rules, _ := pyvalue.DecodeJSON([]byte(`{"data": {"groups": [{"rules": [{"name": "A", "health": "ok"}, {"name": "B", "health": "err"},
		{"health": "err"}, {"name": "C", "health": "unknown"}]}]}}`))
	loaded, unhealthy := RulerState(rules)
	if !loaded["A"] || !loaded["B"] || !loaded["C"] || len(loaded) != 3 || len(unhealthy) != 2 || unhealthy[0] != "B" || unhealthy[1] != nil {
		t.Errorf("RulerState = %v %v", loaded, unhealthy)
	}
}

func TestBackstopRules(t *testing.T) {
	t.Parallel()
	list, err := items(`{"items": [{"metadata": {"name": "security-detection"}, "spec": {"groups": [{"rules": [1, 2]}, {"rules": [3]}, {}]}},
		{"metadata": {"name": "other"}, "spec": {"groups": [{"rules": [1]}]}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if n := BackstopRules(list); n != 3 {
		t.Errorf("BackstopRules = %d", n)
	}
	if _, err := items("not json"); err == nil {
		t.Error("not JSON accepted")
	}
}

// TestClientIsReadOnly: the endpoint's client refuses every method but GET/HEAD before anything is sent.
func TestClientIsReadOnly(t *testing.T) {
	t.Parallel()
	srv := newFakeStore(t, fakeScenario{})
	cl, err := roclient.New(roclient.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if _, err := cl.Do(context.Background(), m, srv.URL+"/loki/api/v1/push", nil); !errors.Is(err, roclient.ErrMutating) {
			t.Errorf("%s: %v", m, err)
		}
	}
	if n := srv.mutations.Load(); n != 0 {
		t.Errorf("%d mutating requests reached the server", n)
	}
}

func TestVersionMatchesTree(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("../../../collectors/detection/VERSION")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != Version {
		t.Fatalf("collectors/detection/VERSION %s, Go %s", got, Version)
	}
}

func TestCapitalizeAndJSONText(t *testing.T) {
	t.Parallel()
	if capitalize("connection refused") != "Connection refused" || capitalize("") != "" {
		t.Error("capitalize")
	}
	if jsonErrorText(nil) != "Expecting value: line 1 column 1 (char 0)" || jsonErrorText([]byte("<html>")) == jsonErrorText([]byte("{")) {
		t.Error("jsonErrorText")
	}
}
