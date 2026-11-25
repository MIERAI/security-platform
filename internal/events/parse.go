package events

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Python's \s and \S for text patterns (str.isspace), not RE2's ASCII classes.
const (
	ws  = `[\t\n\x0b\x0c\r \x1c-\x1f\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]`
	nws = `[^\t\n\x0b\x0c\r \x1c-\x1f\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]`
	// the programs whose lines are auth evidence
	prog = `(?P<prog>sshd(?:-session)?|sudo|dropbear|sshd-auth)(?:\[[0-9]+\])?`
)

// pyRE turns the reference's expression into RE2 with Python's (Unicode) \s and \S.
func pyRE(s string) string {
	return strings.NewReplacer(`\s`, ws, `\S`, nws, `\d`, `[0-9]`, "PROG", prog).Replace(s)
}

// Line formats and auth messages (events/ship.py). Never written after initialisation.
var (
	rxLogcat = regexp.MustCompile(pyRE(`^\s*(?P<ts>\d{9,}\.\d+)\s+\d+\s+\d+\s+[VDIWEF]\s+PROG\s*:\s?(?P<msg>.*)$`))
	rxISO    = regexp.MustCompile(pyRE(`^(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d))\s+\S+\s+PROG:\s?(?P<msg>.*)$`))
	rxBSD    = regexp.MustCompile(pyRE(`^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d\d:\d\d:\d\d)\s+(?:\S+\s+)?(?:\S+\.\S+\s+)?PROG:\s?(?P<msg>.*)$`))
	rxPort   = regexp.MustCompile(`:\d+$`)

	ruleAccepted    = regexp.MustCompile(pyRE(`^Accepted \S+ for (?P<user>\S+) from (?P<src_ip>\S+) port`))
	ruleFailed      = regexp.MustCompile(pyRE(`^Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>\S+) port`))
	ruleInvalid     = regexp.MustCompile(pyRE(`^Invalid user (?P<user>\S*) from (?P<src_ip>\S+)`))
	ruleBadPassword = regexp.MustCompile(pyRE(`^Bad password attempt for '(?P<user>[^']*)' from (?P<addr>\S+)`))
	ruleNoUser      = regexp.MustCompile(pyRE(`^Login attempt for nonexistent user(?: '(?P<user>[^']*)')? from (?P<addr>\S+)`))
	ruleAuthOK      = regexp.MustCompile(pyRE(`^(?:Pubkey|Password) auth succeeded for '(?P<user>[^']*)'.* from (?P<addr>\S+)`))
	ruleSudoFail    = regexp.MustCompile(pyRE(`^\s*(?P<user>\S+) : .*(?:incorrect password|NOT in sudoers|password is required|authentication failure)`))
	ruleSudo        = regexp.MustCompile(pyRE(`^\s*(?P<user>\S+) : .*COMMAND=`))
)

// ruleRxs are the auth rules in order (events/ship.py AUTH_RULES).
func ruleRxs() []*regexp.Regexp {
	return []*regexp.Regexp{ruleAccepted, ruleFailed, ruleInvalid, ruleBadPassword, ruleNoUser, ruleAuthOK, ruleSudoFail, ruleSudo}
}

// ruleEvents are the events of ruleRxs, in the same order (sudo failures first: they carry COMMAND= too).
func ruleEvents() []string {
	return []string{"ssh_login_success", "ssh_login_failure", "ssh_login_failure", "ssh_login_failure",
		"ssh_login_failure", "ssh_login_success", "sudo_failure", "sudo"}
}

// event is one record to ship: its time, the raw line (or compact JSON) and the structured metadata
// (event, user, src_ip, novel / actor, repo; insertion order kept as the reference's dict).
type event struct {
	ts   float64
	line string
	meta *pyvalue.Map
	hash string // the command source's edge hash
	id   string // the overlay source's record id
}

func (e *event) get(k string) any { return e.meta.Value(k) }

// isSpace is str.isspace for one character.
func isSpace(r rune) bool {
	return r >= 0x2000 && r <= 0x200a ||
		strings.ContainsRune("\t\n\v\f\r \x1c\x1d\x1e\x1f\u0085\u00a0\u1680\u2028\u2029\u202f\u205f\u3000", r)
}

func pyStrip(s string) string { return strings.TrimFunc(s, isSpace) }

// splitLines is str.splitlines(): \n, \r, \r\n, \v, \f, \x1c-\x1e, \x85, \u2028, \u2029 end a line.
func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if !isLineBreak(r) {
			i += size
			continue
		}
		out = append(out, s[start:i])
		i += size
		if r == '\r' && i < len(s) && s[i] == '\n' {
			i++
		}
		start = i
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func isLineBreak(r rune) bool {
	return strings.ContainsRune("\n\r\v\f\x1c\x1d\x1e\u0085\u2028\u2029", r)
}

// splitAddr is ship.py split_addr: dropbear's "A:P", "[v6]:P", "v6:P" -> the address.
func splitAddr(addr string) string {
	addr = strings.TrimRight(pyStrip(addr), ",")
	switch {
	case strings.HasPrefix(addr, "["):
		if i := strings.Index(addr, "]"); i >= 0 {
			return addr[1:i]
		}
		r := []rune(addr)
		if len(r) < 2 {
			return ""
		}
		return string(r[1 : len(r)-1])
	case strings.Count(addr, ":") == 1:
		return strings.SplitN(addr, ":", 2)[0]
	case strings.Count(addr, ":") > 1 && rxPort.MatchString(addr):
		return addr[:strings.LastIndex(addr, ":")]
	}
	return addr
}

// classify is ship.py classify: an auth message -> {event, user, src_ip?}; nil when no rule matches.
func classify(msg string) *pyvalue.Map {
	for i, re := range ruleRxs() {
		m := re.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		group := func(name string) string {
			if j := re.SubexpIndex(name); j >= 0 {
				return m[j]
			}
			return ""
		}
		out := pyvalue.NewMap()
		out.Set("event", ruleEvents()[i])
		out.Set("user", group("user"))
		ip := group("src_ip")
		if ip == "" && group("addr") != "" {
			ip = splitAddr(group("addr"))
		}
		if ip != "" {
			out.Set("src_ip", ip)
		}
		return out
	}
	return nil
}

// parser reads one output line of a command source; nil without error = not evidence.
type parser func(line string, now float64, opts *pyvalue.Map, loc *time.Location) (*event, error)

func parsers() map[string]parser {
	return map[string]parser{"openssh": parseSyslog, "dropbear": parseSyslog, "sudo": parseSyslog, "syslog": parseSyslog,
		"macos-unified": parseMacOS}
}

// parseSyslog reads openssh / dropbear / sudo lines in logcat (-v epoch), ISO-8601 and BSD syslog format.
func parseSyslog(line string, now float64, opts *pyvalue.Map, loc *time.Location) (*event, error) {
	if strings.Contains(line, "avc:") { // Android SELinux audit noise around every exec
		return nil, nil //nolint:nilnil // not evidence, not an error
	}
	sm, err := syslogTime(line, now, opts, loc)
	if err != nil || sm == nil {
		return nil, err
	}
	ts, msg := sm.ts, sm.group("msg")
	if sm.group("prog") == "dropbear" && strings.HasPrefix(msg, "Exit before auth") {
		return nil, nil //nolint:nilnil // not evidence, not an error
	}
	meta := classify(msg)
	if meta == nil {
		meta = pyvalue.NewMap()
	}
	return &event{ts: ts, line: strings.TrimRight(line, "\n"), meta: meta}, nil
}

// syslogMatch is a line in one of the syslog formats: its time, the submatches and the expression that matched.
type syslogMatch struct {
	ts float64
	m  []string
	re *regexp.Regexp
}

func (sm *syslogMatch) group(name string) string { return sm.m[sm.re.SubexpIndex(name)] }

// syslogTime matches a line (logcat, ISO-8601, BSD) and reads its time; nil without error when no format matches.
func syslogTime(line string, now float64, opts *pyvalue.Map, loc *time.Location) (*syslogMatch, error) {
	if m := rxLogcat.FindStringSubmatch(line); m != nil {
		ts, err := strconv.ParseFloat(m[rxLogcat.SubexpIndex("ts")], 64)
		return &syslogMatch{ts, m, rxLogcat}, err
	}
	if m := rxISO.FindStringSubmatch(line); m != nil {
		s := strings.ReplaceAll(m[rxISO.SubexpIndex("ts")], "Z", "+00:00")
		ts, ok := isoTimestamp(s, loc)
		if !ok {
			return nil, pyErr("ValueError", "Invalid isoformat string: "+pyvalue.Repr(s))
		}
		return &syslogMatch{ts, m, rxISO}, nil
	}
	m := rxBSD.FindStringSubmatch(line)
	if m == nil {
		return nil, nil //nolint:nilnil // no format matches: not a log line
	}
	tz, err := parseTZ(textOf(opts.Value("utc_offset")))
	if err != nil {
		return nil, err
	}
	ts, err := bsdTime(m[rxBSD.SubexpIndex("ts")], now, tz, loc)
	return &syslogMatch{ts, m, rxBSD}, err
}

// textOf is a configured text value ("" for none).
func textOf(v any) string {
	if !pyvalue.Truthy(v) {
		return ""
	}
	return pyvalue.Str(v)
}

// parseMacOS reads one `log show --style ndjson` record; unclassified records are dropped unless
// keep_unclassified.
func parseMacOS(line string, _ float64, opts *pyvalue.Map, _ *time.Location) (*event, error) {
	v, err := pyvalue.DecodeJSON([]byte(line))
	r, isMap := v.(*pyvalue.Map)
	if err != nil || !isMap || !r.Has("eventMessage") {
		return nil, nil //nolint:nilnil,nilerr // not a record: skipped, as the reference
	}
	if !r.Has("timestamp") {
		return nil, pyErr("KeyError", "'timestamp'")
	}
	stamp, ok := r.Value("timestamp").(string)
	if !ok {
		return nil, pyErr("TypeError", "strptime() argument 1 must be str, not "+pyvalue.TypeName(r.Value("timestamp")))
	}
	ts, err := macTimestamp(stamp)
	if err != nil {
		return nil, err
	}
	msg, ok := r.Value("eventMessage").(string)
	if !ok {
		return nil, pyErr("TypeError", "expected string or bytes-like object, got '"+pyvalue.TypeName(r.Value("eventMessage"))+"'")
	}
	meta := classify(msg)
	if meta == nil && !pyvalue.Truthy(opts.Value("keep_unclassified")) {
		return nil, nil //nolint:nilnil // directory-service chatter around every sudo: not evidence
	}
	if meta == nil {
		meta = pyvalue.NewMap()
	}
	keep := pyvalue.NewMap()
	keep.Set("timestamp", stamp)
	keep.Set("process", basename(textOf(r.Value("processImagePath"))+textOrEmpty(r, "process")))
	keep.Set("pid", r.Value("processID"))
	keep.Set("message", msg)
	text, err := dumps(keep, lineJSON())
	if err != nil {
		return nil, fmt.Errorf("encode record: %w", err)
	}
	return &event{ts: ts, line: text, meta: meta}, nil
}

// basename is os.path.basename: the text after the last "/".
func basename(p string) string { return p[strings.LastIndex(p, "/")+1:] }

// textOrEmpty is the `or r.get("process")` fallback: used only when processImagePath is empty.
func textOrEmpty(r *pyvalue.Map, key string) string {
	if pyvalue.Truthy(r.Value("processImagePath")) {
		return ""
	}
	return textOf(r.Value(key))
}
