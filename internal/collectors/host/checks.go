package host

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/pytext"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const day = 86400.0

// wildRe matches a listener on every interface; securityPatchRe a value that is meant as a date. Both are never
// written after initialisation.
var (
	wildRe          = regexp.MustCompile(`^(0\.0\.0\.0|\*|\[::\]|::|0{8}):`)
	securityPatchRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}`)
)

// dbPorts are ports of database-like services that must not listen on every interface.
func dbPorts() map[float64]bool {
	return map[float64]bool{5432: true, 55432: true, 3306: true, 6379: true, 27017: true, 9200: true, 2379: true}
}

// checker evaluates one host's probe values.
type checker struct {
	doc       *rundoc.Document
	asset, ev string
	kv        *ordered
	now       time.Time
}

// add reports a finding a human must act on when human is set (needs_human).
func (c *checker) add(f rundoc.Finding, human bool) {
	f.Asset, f.Evidence, f.NeedsHuman = c.asset, c.ev, human
	c.doc.AddFinding(&f)
}

// f is a finding of this host: layer, check, title, severity, remediation.
func f(layer, check, title, severity, fix string) rundoc.Finding {
	return rundoc.Finding{Layer: layer, Check: check, Title: title, Severity: severity, Remediation: fix}
}

// str is kv.get(k) as an f-string prints it ("None" when absent).
func (c *checker) str(k string) string {
	if v, ok := c.kv.get(k); ok {
		return v
	}
	return "None"
}

func (c *checker) is(k, want string) bool {
	v, ok := c.kv.get(k)
	return ok && v == want
}

// num is int(float(kv[k])) as a float (0 when absent or not a number).
func (c *checker) num(k string) float64 {
	v, ok := c.kv.get(k)
	if !ok {
		return 0
	}
	return num(v)
}

// num is Python's int(float(v)) with 0 for text that is not a number (and, unlike Python, for infinities, which
// it cannot convert).
func num(v string) float64 {
	f, err := pyvalue.ToFloat(v)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return math.Trunc(f)
}

func intText(f float64) string { return strconv.FormatFloat(f, 'f', 0, 64) }

func (c *checker) all() {
	c.ssh()
	c.patches()
	c.firewall()
	c.macOS()
	c.windows()
	c.platforms()
}

func (c *checker) ssh() {
	if v, _ := c.kv.get("sshd.passwordauthentication"); strings.HasPrefix(v, "yes") {
		c.add(f("identity", "ssh.password_auth_enabled", "SSH password authentication is enabled", "high",
			"PasswordAuthentication no (keys only)"), false)
	}
	if c.is("sshd.permitrootlogin", "yes") {
		c.add(f("identity", "ssh.root_login_password", "SSH root login with password allowed", "high",
			"PermitRootLogin prohibit-password/no"), false)
	}
	if c.is("sshd.x11forwarding", "yes") {
		c.add(f("host", "ssh.x11_forwarding", "SSH X11Forwarding enabled", "low", "X11Forwarding no"), false)
	}
}

func (c *checker) patches() {
	sec, up := c.num("pkg.security_upgradable"), c.num("pkg.upgradable")
	switch {
	case sec != 0:
		c.add(f("host", "patch.security_pending", intText(sec)+" security updates pending", "medium", "apply updates"), false)
	case up != 0:
		c.add(f("host", "patch.pending", intText(up)+" package updates pending", "low", "apply updates"), false)
	}
	now := float64(c.now.UnixNano()) / 1e9
	if cm := c.num("pkg.cache_mtime"); cm != 0 && now-cm > 7*day {
		c.add(f("host", "patch.metadata_stale", "package metadata "+intText(math.Trunc((now-cm)/day))+
			" days old: pending-update count is unreliable", "low", "enable periodic metadata refresh"), false)
	}
	if c.is("reboot_required", "yes") {
		c.add(f("host", "patch.reboot_required", "reboot required to activate installed updates (uptime "+
			c.str("uptime_days")+"d)", "medium", "schedule a reboot (planned maintenance)"), false)
	}
	if c.is("pkg.auto_updates", "no") {
		c.add(f("host", "patch.auto_updates_off", "automatic security updates are off", "low", "enable unattended-upgrades"), false)
	}
}

func (c *checker) firewall() {
	ufw, hasUFW := c.kv.get("fw.ufw")
	if !hasUFW || ufw == "active" || ufw == "活动" || ufw == "激活" || c.is("fw.nft_input_policy", "drop") {
		return
	}
	if ipt, ok := c.kv.get("fw.iptables_input_policy"); !ok || ipt == "ACCEPT" || ipt == "" {
		c.add(f("network", "fw.host_firewall_off", "no host firewall: INPUT default-accept, ufw inactive", "medium",
			"default-deny INPUT except ssh/needed ports (tailnet/LAN only)"), false)
	}
}

func (c *checker) macOS() {
	for _, x := range []struct{ key, sev, title, fix string }{
		{"disk.filevault", "high", "FileVault disk encryption is off", "enable FileVault"},
		{"fw.app_firewall", "medium", "macOS application firewall is off", "enable the firewall"},
		{"sip", "high", "System Integrity Protection is off", "re-enable SIP"},
		{"gatekeeper", "high", "Gatekeeper is off", "spctl --master-enable"}} {
		if c.is(x.key, "off") {
			c.add(f("host", "macos."+strings.ReplaceAll(x.key, ".", "_")+"_off", x.title, x.sev, x.fix), x.key != "fw.app_firewall")
		}
	}
	if c.is("fw.stealth", "off") {
		c.add(f("host", "macos.fw_stealth_off", "macOS firewall stealth mode is off", "low", "enable stealth mode"), false)
	}
	if c.num("pkg.os_updates_pending") != 0 {
		c.add(f("host", "patch.os_updates_pending", c.str("pkg.os_updates_pending")+" OS updates pending", "medium",
			"install macOS updates"), true)
	}
	if c.num("pkg.brew_outdated") > 20 {
		c.add(f("host", "patch.brew_outdated", c.str("pkg.brew_outdated")+" Homebrew packages outdated", "low", "brew upgrade"), false)
	}
}

func (c *checker) windows() {
	for _, k := range c.kv.keys {
		if strings.HasPrefix(k, "fw.profile_") && c.kv.vals[k] == "off" {
			c.add(f("network", "win."+strings.ReplaceAll(k, ".", "_"), "Windows firewall profile "+k[len("fw.profile_"):]+" is off",
				"high", "enable it"), false)
		}
	}
	if c.is("av.realtime", "off") {
		c.add(f("host", "win.av_realtime_off", "Defender real-time protection off", "high", "enable it"), false)
	}
	if c.num("av.signature_age_days") > 7 {
		c.add(f("host", "win.av_signatures_stale", "AV signatures "+c.str("av.signature_age_days")+" days old", "medium", "update"), false)
	}
	if c.is("disk.bitlocker", "Off") || c.is("disk.bitlocker", "0") {
		c.add(f("host", "win.disk_unencrypted", "system drive not encrypted (BitLocker/device encryption off)", "medium",
			"enable device encryption (keep the recovery key offline)"), true)
	}
	if c.is("smb.v1", "True") {
		c.add(f("host", "win.smb1_enabled", "SMBv1 server enabled", "high", "disable SMB1"), false)
	}
	if lh, _ := c.kv.get("pkg.last_hotfix"); lh != "" {
		if d, ok := parseDate(lh); ok && c.now.Sub(d) > 45*24*time.Hour {
			c.add(f("host", "patch.windows_stale", "last Windows update installed "+lh, "medium", "run Windows Update"), false)
		}
	}
}

func (c *checker) platforms() {
	if sp, _ := c.kv.get("os.security_patch"); securityPatchRe.MatchString(sp) {
		if d, ok := parseDate(sp); ok && c.now.Sub(d) > 90*24*time.Hour {
			c.add(f("host", "patch.android_security_patch_old", "Android security patch level "+sp+" (> 90 days)", "medium",
				"install the vendor OTA (vendor may have stopped updates)"), true)
		}
	}
	if c.num("proc.secret_in_argv_suspects") != 0 {
		c.add(f("data-secrets", "secret.in_process_argv", "a process carries a credential on its command line (visible to ps)",
			"medium", "pass it via a 0600 file or env instead of argv"), false)
	}
	if c.num("telnetd") != 0 {
		c.add(f("network", "telnet.daemon_running", "telnetd is running", "high", "disable telnetd"), false)
	}
}

// listeners reports database-like ports listening on every interface and returns how many listeners do.
func (c *checker) listeners(listen []string) int {
	wild := 0
	for _, l := range listen {
		if !wildRe.MatchString(l) {
			continue
		}
		wild++
		first := strings.FieldsFunc(l, pytext.IsSpace)[0]
		port := num(first[strings.LastIndexByte(first, ':')+1:])
		if dbPorts()[port] {
			p := intText(port)
			c.add(f("network", "listen.db_wildcard."+p, "database-like port "+p+" listens on all interfaces ("+l+")",
				"medium", "bind to localhost/bridge only"), false)
		}
	}
	return wild
}

// parseDate reads time.strptime(s, "%Y-%m-%d") — a four-digit year, a month 1..12 and a day of one or two digits
// (or a space and one digit), a valid calendar date — as UTC midnight.
func parseDate(s string) (time.Time, bool) {
	y, rest, ok := strings.Cut(s, "-")
	m, d, ok2 := strings.Cut(rest, "-")
	if strings.HasPrefix(d, " ") && len(d) == 2 {
		d = d[1:]
	}
	if !ok || !ok2 || len(y) != 4 || !digits(y) || !oneOrTwoDigits(m) || !oneOrTwoDigits(d) {
		return time.Time{}, false
	}
	yi, mi, di := atoi(y), atoi(m), atoi(d)
	t := time.Date(yi, time.Month(mi), di, 0, 0, 0, 0, time.UTC)
	if yi < 1 || t.Month() != time.Month(mi) || t.Day() != di {
		return time.Time{}, false
	}
	return t, true
}

// atoi is the value of a text of ASCII digits (checked by the caller).
func atoi(s string) int {
	n := 0
	for _, r := range s {
		n = 10*n + int(r-'0')
	}
	return n
}

func oneOrTwoDigits(s string) bool { return len(s) >= 1 && len(s) <= 2 && digits(s) }

func digits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// badDates are the date-valued probe keys whose value is meant as a date but is not one, with the reason: their
// checks cannot be evaluated (a narrow gap), they must not end the run.
func badDates(kv *ordered) *ordered {
	out := newOrdered()
	if lh, _ := kv.get("pkg.last_hotfix"); lh != "" {
		if _, ok := parseDate(lh); !ok {
			out.set("pkg.last_hotfix", "not a date: "+pyvalue.Repr(lh))
		}
	}
	if sp, _ := kv.get("os.security_patch"); securityPatchRe.MatchString(sp) {
		if _, ok := parseDate(sp); !ok {
			out.set("os.security_patch", "not a date: "+pyvalue.Repr(sp))
		}
	}
	return out
}
