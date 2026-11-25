package events

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// FuzzParseSyslog: any line parses or is skipped without failing; an event keeps the line it came from.
func FuzzParseSyslog(f *testing.F) {
	for _, s := range []string{
		"2026-11-25T11:40:00+00:00 lab sshd[1]: Accepted publickey for ops from 10.0.0.1 port 5 ssh2",
		"Feb 29 01:02:03 h dropbear[1]: Login attempt for nonexistent user 'x' from 1.2.3.4:5",
		"1795606800.123 1 2 I sshd : Invalid user z from ::1", "Nov  5 01:02:03 h.example sudo:  u : COMMAND=/x"} {
		f.Add(s, "+09:00")
	}
	f.Fuzz(func(t *testing.T, line, offset string) {
		opts := pyvalue.NewMap()
		opts.Set("utc_offset", offset)
		e, err := parseSyslog(line, testNow, opts, time.UTC)
		if err != nil || e == nil {
			return
		}
		if e.line != strings.TrimRight(line, "\n") {
			t.Fatalf("line %q kept as %q", line, e.line)
		}
	})
}

func FuzzParseMacOS(f *testing.F) {
	f.Add(`{"timestamp": "2026-11-25 11:40:00.000000+0000", "eventMessage": "Accepted publickey for ops from 10.0.0.1 port 5", "processImagePath": "/usr/sbin/sshd", "processID": 1}`)
	f.Add(`{"timestamp": "x", "eventMessage": 1}`)
	f.Add(`[]`)
	f.Fuzz(func(t *testing.T, line string) {
		opts := pyvalue.NewMap()
		opts.Set("keep_unclassified", true)
		e, err := parseMacOS(line, testNow, opts, time.UTC)
		if err == nil && e != nil && !strings.HasPrefix(e.line, "{") {
			t.Fatalf("line %q", e.line)
		}
	})
}

func FuzzNextLink(f *testing.F) {
	for _, s := range []string{`<https://a/b?page=2>; rel="next"`, `<x>; rel="last", <y>; rel="next"`, ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, link string) {
		if got := nextLink(link); got != "" && !strings.Contains(link, "<"+got+">") {
			t.Fatalf("%q is not a <target> of %q", got, link)
		}
	})
}

func FuzzMapRecord(f *testing.F) {
	f.Add(`{"type": "UPDATE", "target": {"type": "NODE", "property": "KEY_EXPIRY_DISABLED"}, "new": true}`)
	f.Add(`{"action": "CREATE", "target": {"type": "USER"}}`)
	f.Add(`{"target": 3}`)
	f.Fuzz(func(t *testing.T, data string) {
		v, err := pyvalue.DecodeJSON([]byte(data))
		m, ok := v.(*pyvalue.Map)
		if err != nil || !ok {
			return
		}
		ev, err := mapRecord(m)
		if err == nil && ev == "" {
			t.Fatal("empty event name")
		}
	})
}

func FuzzDurationAndTZ(f *testing.F) {
	for _, s := range []string{"1h", "30m", "2d", "-1h", "1.5h", "+05:30", "-0800"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if d, err := parseDur(s); err == nil && d < 0 {
			t.Fatalf("negative duration %v from %q", d, s)
		}
		if z, err := parseTZ(s); err == nil && z != nil && (z.sec <= -86400 || z.sec >= 86400) {
			t.Fatalf("offset %d from %q", z.sec, s)
		}
	})
}

// FuzzLoadConfig: any config file is accepted or refused without failing; an accepted source name is safe as a
// file name.
func FuzzLoadConfig(f *testing.F) {
	f.Add(`{"loki": {"url": "http://x"}, "sources": [{"name": "a.b-c_d", "type": "command"}]}`)
	f.Add(`{"sources": [{"name": "../x"}]}`)
	f.Add(`{"sources": 1}`)
	f.Fuzz(func(t *testing.T, data string) {
		p := filepath.Join(t.TempDir(), "c.json")
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		_, srcs, err := loadConfig(p)
		if err != nil {
			return
		}
		for _, s := range srcs {
			n, _ := s.Value("name").(string)             // checked by loadConfig
			if n == "" || strings.ContainsAny(n, `/\`) { // "<name>.json" stays inside the state directory
				t.Fatalf("name %q accepted", n)
			}
		}
	})
}
