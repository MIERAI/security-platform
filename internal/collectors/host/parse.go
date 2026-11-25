package host

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/MIERAI/security-platform/internal/collectors/pytext"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const (
	endKey       = "probe.end" // printed after the profile: its absence = the script did not finish
	timeoutKey   = "probe.timeout"
	listenKey    = "listen"
	whyTimeout   = "did not finish within its time limit"
	maxErrorTail = 160
)

// plannedRe finds the probe keys a profile script prints (sp_probe/sp_lines in sh, Probe in PowerShell); it is
// never written after initialisation.
var plannedRe = regexp.MustCompile(`(?m)^\s*(?:sp_probe|sp_lines|Probe)\s+([A-Za-z0-9_.-]+)\s`)

// ordered is a string mapping that keeps the order keys were first set (a Python dict).
type ordered struct {
	keys []string
	vals map[string]string
}

func newOrdered() *ordered { return &ordered{vals: map[string]string{}} }

func (o *ordered) set(k, v string) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *ordered) get(k string) (string, bool) {
	v, ok := o.vals[k]
	return v, ok
}

func (o *ordered) delete(k string) {
	if _, ok := o.vals[k]; !ok {
		return
	}
	delete(o.vals, k)
	for i, x := range o.keys {
		if x == k {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			return
		}
	}
}

func (o *ordered) pyMap() *pyvalue.Map {
	m := pyvalue.NewMap()
	for _, k := range o.keys {
		m.Set(k, o.vals[k])
	}
	return m
}

// output is a profile's parsed output.
type output struct {
	kv       *ordered
	listen   []string
	timeouts []string
}

// parse reads key=value lines (stripped; lines without "=" ignored): listen= lines collected in order,
// probe.timeout= lines name timed-out probes, every other key keeps its last value.
func parse(out string) output {
	o := output{kv: newOrdered()}
	for _, line := range pytext.SplitLines(out) {
		line = pytext.Strip(line)
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case listenKey:
			o.listen = append(o.listen, v)
		case timeoutKey:
			o.timeouts = append(o.timeouts, pytext.Strip(v))
		default:
			o.kv.set(k, pytext.Strip(v))
		}
	}
	return o
}

// planned are the probe keys the script prints, in order.
func planned(script string) []string {
	var keys []string
	for _, m := range plannedRe.FindAllStringSubmatch(script, -1) {
		keys = append(keys, m[1])
	}
	return keys
}

// unread is {probe key: reason} for every probe whose value is unknown: it timed out, or the whole script was
// stopped before reaching it.
func unread(o output, script string, rc int) *ordered {
	miss := newOrdered()
	for _, k := range o.timeouts {
		if _, ok := miss.get(k); !ok {
			miss.set(k, whyTimeout)
		}
	}
	if _, finished := o.kv.get(endKey); finished {
		return miss
	}
	seen := append([]string(nil), o.kv.keys...)
	if len(o.listen) > 0 {
		seen = append(seen, listenKey)
	}
	for _, k := range planned(script) {
		if _, ok := miss.get(k); ok || anyPrints(seen, k) {
			continue
		}
		miss.set(k, "not reached: the script was stopped (rc="+strconv.Itoa(rc)+")")
	}
	return miss
}

// anyPrints: one of the keys seen is k or a key k prints (k.x, k_x).
func anyPrints(seen []string, k string) bool {
	for _, s := range seen {
		if s == k || strings.HasPrefix(s, k+".") || strings.HasPrefix(s, k+"_") {
			return true
		}
	}
	return false
}

// part is a group of checks that read the same probe keys: a key that could not be read makes
// host:<name>/<part> a narrow gap for exactly these checks.
type part struct {
	name         string
	keys, checks []string
}

// parts: keys outside this table feed no check (informational only).
func parts() []part {
	return []part{
		{"ssh", []string{"sshd", "sshd.*"}, []string{"ssh.password_auth_enabled", "ssh.root_login_password", "ssh.x11_forwarding"}},
		{"package-updates", []string{"pkg.upgradable", "pkg.security_upgradable"}, []string{"patch.security_pending", "patch.pending"}},
		{"package-metadata", []string{"pkg.cache_mtime"}, []string{"patch.metadata_stale"}},
		{"reboot", []string{"reboot_required"}, []string{"patch.reboot_required"}},
		{"auto-updates", []string{"pkg.auto_updates"}, []string{"patch.auto_updates_off"}},
		{"firewall", []string{"fw.ufw", "fw.nft_input_policy", "fw.iptables_input_policy"}, []string{"fw.host_firewall_off"}},
		{"disk-encryption", []string{"disk.filevault"}, []string{"macos.disk_filevault_off"}},
		{"app-firewall", []string{"fw.app_firewall"}, []string{"macos.fw_app_firewall_off"}},
		{"firewall-stealth", []string{"fw.stealth"}, []string{"macos.fw_stealth_off"}},
		{"sip", []string{"sip"}, []string{"macos.sip_off"}},
		{"gatekeeper", []string{"gatekeeper"}, []string{"macos.gatekeeper_off"}},
		{"os-updates", []string{"pkg.os_updates_pending"}, []string{"patch.os_updates_pending"}},
		{"brew", []string{"pkg.brew_outdated"}, []string{"patch.brew_outdated"}},
		{"windows-firewall", []string{"fw.profile", "fw.profile_*"}, []string{"win.fw_profile_*"}},
		{"antivirus", []string{"av", "av.*"}, []string{"win.av_realtime_off", "win.av_signatures_stale"}},
		{"disk-encryption", []string{"disk.bitlocker"}, []string{"win.disk_unencrypted"}},
		{"smb1", []string{"smb.v1"}, []string{"win.smb1_enabled"}},
		{"windows-updates", []string{"pkg.last_hotfix"}, []string{"patch.windows_stale"}},
		{"android-patch", []string{"os.security_patch"}, []string{"patch.android_security_patch_old"}},
		{"process-arguments", []string{"proc.secret_in_argv_suspects"}, []string{"secret.in_process_argv"}},
		{"telnet", []string{"telnetd"}, []string{"telnet.daemon_running"}},
		{"listeners", []string{"listen"}, []string{"listen.db_wildcard.*"}},
	}
}

// narrowGap is one part that could not be checked.
type narrowGap struct {
	part, why string
	checks    []string
}

// narrowGaps are the parts whose checks read a key in miss, sorted by part.
func narrowGaps(miss *ordered) []narrowGap {
	whys := map[string][]string{}
	checks := map[string]map[string]bool{}
	for _, k := range miss.keys {
		for _, p := range parts() {
			if !matchAny(k, p.keys) {
				continue
			}
			whys[p.name] = append(whys[p.name], k+": "+miss.vals[k])
			if checks[p.name] == nil {
				checks[p.name] = map[string]bool{}
			}
			for _, c := range p.checks {
				checks[p.name][c] = true
			}
		}
	}
	out := make([]narrowGap, 0, len(whys))
	for name, w := range whys {
		cs := make([]string, 0, len(checks[name]))
		for c := range checks[name] {
			cs = append(cs, c)
		}
		sort.Strings(cs)
		out = append(out, narrowGap{part: name, why: strings.Join(w, "; "), checks: cs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].part < out[j].part })
	return out
}

func matchAny(name string, patterns []string) bool {
	for _, p := range patterns {
		if pytext.FnMatch(name, p) {
			return true
		}
	}
	return false
}
