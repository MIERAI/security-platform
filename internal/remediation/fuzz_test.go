package remediation

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// FuzzDuration: SLO durations from the instance never panic, and a parsed one is a whole number of seconds that
// the same text always gives.
func FuzzDuration(f *testing.F) {
	for _, s := range []string{"7d", "1.5d", " 90m ", "3600", "1e3s", "-1d", "d", "NaNd", "1e400d", "0x10", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, okA, errA := duration(s)
		b, okB, errB := duration(s)
		if a != b || okA != okB || (errA == nil) != (errB == nil) {
			t.Fatalf("duration(%q) is not deterministic", s)
		}
	})
}

// FuzzTrackPreviousItems: whatever DATA/tracker/items.json holds, track either fails cleanly or writes a valid
// tracker file.
func FuzzTrackPreviousItems(f *testing.F) {
	for _, s := range []string{`{"items": {}}`, `{"items": {"233790a18561": {"status": "fixed", "history": 5, "reopened_at": "x"}}}`,
		`{"items": {"../../x": {"id": "../../x", "status": "open", "severity": "high"}}}`, `[]`, `{"items": []}`} {
		f.Add([]byte(s))
	}
	ledger := []byte(`{"schema": "security-platform/ledger/v1", "runs": [], "entries": {"233790a18561": ` +
		entryJSON("233790a18561", `"status": "open"`) + `}}`)
	f.Fuzz(func(t *testing.T, items []byte) {
		data := t.TempDir()
		if err := os.MkdirAll(filepath.Join(data, "tracker"), 0o700); err != nil {
			t.Fatal(err)
		}
		for name, b := range map[string][]byte{"ledger.json": ledger, filepath.Join("tracker", "items.json"): items} {
			if err := os.WriteFile(filepath.Join(data, name), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		opt := Options{Data: data, Now: t0, Wall: t0, Version: "0", Stderr: &bytes.Buffer{}}
		if err := Track(context.Background(), opt); err == nil {
			checkItemsFile(t, data)
		}
	})
}

// checkItemsFile: items.json parses and tracks the ledger's entry; nothing was written outside the data dir.
func checkItemsFile(t *testing.T, data string) {
	t.Helper()
	out, err := os.ReadFile(filepath.Join(data, "tracker", "items.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := pyjson.Decode(out)
	if o, _ := v.(*pyjson.Object); err != nil || o == nil || o.Obj("items").Obj("233790a18561") == nil {
		t.Fatalf("items.json: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(data), "x.md")); err == nil {
		t.Fatal("an item id escaped the tracker directory")
	}
}
