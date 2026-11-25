package secretsfiles

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/MIERAI/security-platform/internal/collectors/collkit"
	"github.com/MIERAI/security-platform/internal/collectors/pytext"
	"github.com/MIERAI/security-platform/internal/collectors/spdoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const day = 86400.0

// privateKind: kinds that are secrets themselves (notes merely may contain one).
func privateKind(k string) bool {
	switch k {
	case "private-key", "kubeconfig", "tf-state", "dotenv", "rclone-config", "age-key", "netrc", "docker-config",
		"gh-config", "k3s-token", "secret-file":
		return true
	}
	return false
}

// item is one scanned file's metadata.
type item struct {
	m          *pyvalue.Map // as the scan printed it, path made home-relative (the evidence)
	path, kind string
	mode       string // "0o600" ..., or "unknown" (Windows ACL not readable)
	bits       int64
	mtime      float64
}

// scanResult is the scan's result line.
type scanResult struct{ items []*item }

var errResult = errors.New("not the scan result")

// parseScan reads the last line of the scan's output: {"home": ..., "items": [{path, kind, mode, mtime, ...}]}.
// Paths under the home directory become "~/...", with "/" separators.
func parseScan(out string) (scanResult, error) {
	lines := pytext.SplitLines(pytext.Strip(out))
	if len(lines) == 0 {
		return scanResult{}, fmt.Errorf("%w: no output", errResult)
	}
	v, err := pyvalue.DecodeJSON([]byte(lines[len(lines)-1]))
	doc, isMap := v.(*pyvalue.Map)
	if err != nil || !isMap {
		return scanResult{}, fmt.Errorf("%w: the last line is not a JSON object", errResult)
	}
	home, okHome := doc.Value("home").(string)
	raw, okItems := doc.Value("items").([]any)
	if !okHome || !okItems {
		return scanResult{}, fmt.Errorf("%w: no home and items", errResult)
	}
	var sr scanResult
	for n, x := range raw {
		it, err := newItem(x, home)
		if err != nil {
			return scanResult{}, fmt.Errorf("item %d: %w", n, err)
		}
		sr.items = append(sr.items, it)
	}
	return sr, nil
}

func newItem(x any, home string) (*item, error) {
	m, ok := x.(*pyvalue.Map)
	if !ok {
		return nil, fmt.Errorf("%w: not an object", errResult)
	}
	it := &item{m: m}
	path, okPath := m.Value("path").(string)
	kind, okKind := m.Value("kind").(string)
	mode, okMode := m.Value("mode").(string)
	mtime, okTime := pyvalue.ToFloat64(m.Value("mtime"))
	if _, isBool := m.Value("mtime").(bool); !okPath || !okKind || !okMode || !okTime || isBool {
		return nil, fmt.Errorf("%w: path, kind, mode and mtime are required", errResult)
	}
	it.path = strings.ReplaceAll(homeRelative(path, home), `\`, "/")
	m.Set("path", it.path)
	it.kind, it.mode, it.mtime = kind, mode, mtime
	if mode != "unknown" {
		bits, err := pyvalue.ParseInt(mode, 8)
		if err != nil {
			return nil, fmt.Errorf("%w: mode %s", errResult, pyvalue.Repr(mode))
		}
		it.bits = bits
	}
	return it, nil
}

// homeRelative writes a path under home as "~" + the rest: only a leading home directory, as whole path
// components (collector-protocol COLLECTOR-D5).
func homeRelative(path, home string) string {
	h := strings.TrimRight(home, `/\`)
	switch {
	case h == "":
		return path
	case path == h:
		return "~"
	case strings.HasPrefix(path, h) && (path[len(h)] == '/' || path[len(h)] == '\\'):
		return "~" + path[len(h):]
	}
	return path
}

// report records one target's evidence, coverage, findings and metrics.
func report(r *collkit.Run, host string, sr scanResult) error {
	list := make([]any, len(sr.items))
	for i, it := range sr.items {
		list[i] = it.m
	}
	ev, err := r.Doc.Raw(r.Dir, host+".json", list)
	if err != nil {
		return err
	}
	r.Doc.OK("host:" + host)
	now := float64(r.Now().UnixNano()) / 1e9
	total, old := 0, 0
	for _, it := range sr.items {
		e := &evaluation{doc: r.Doc, it: it, asset: "secret-file:" + host + ":" + it.path, ev: ev + "#" + it.path,
			ageDays: math.Trunc((now - it.mtime) / day)}
		e.run()
		if e.err != nil {
			return e.err
		}
		if privateKind(it.kind) {
			total++
			if e.ageDays > 90 {
				old++
			}
		}
	}
	store := map[string]string{"store": "files:" + host}
	r.Doc.Metric("security_secrets_total", float64(total), "Secret files found", store)
	r.Doc.Metric("security_secrets_older_than_90d", float64(old), "Secret files older than 90 days", store)
	return nil
}

// evaluation turns one item into its findings.
type evaluation struct {
	doc       *spdoc.Document
	it        *item
	asset, ev string
	ageDays   float64
	err       error
}

// add reports a finding on the item (needs_human when human is set).
func (e *evaluation) add(f spdoc.Finding, human bool) {
	if e.err == nil {
		f.Asset, f.Evidence, f.NeedsHuman = e.asset, e.ev, human
		e.err = e.doc.Add(&f)
	}
}

// secret is a data-secrets finding: check, title, severity, remediation.
func secret(check, title, severity, fix string) spdoc.Finding {
	return spdoc.Finding{Layer: "data-secrets", Check: check, Title: title, Severity: severity, Remediation: fix}
}

func (e *evaluation) flag(k string) bool { return pyvalue.Truthy(e.it.m.Value(k)) }

func (e *evaluation) age() string { return strconv.FormatFloat(e.ageDays, 'f', 0, 64) }

func (e *evaluation) run() {
	if e.it.mode == "unknown" {
		e.doc.Gap(e.asset+"/permissions", "file permissions could not be read", nil)
	}
	e.permissions()
	e.properties()
	kind := e.it.kind
	if privateKind(kind) && e.ageDays > 90 && (kind == "private-key" || kind == "age-key" || kind == "k3s-token" ||
		kind == "secret-file" || kind == "dotenv") {
		sev := "medium"
		if e.ageDays < 365 {
			sev = "low"
		}
		e.add(secret("secret.age_over_90d", kind+" unchanged for "+e.age()+" days (rotation unknown)", sev,
			"rotate on a schedule; record rotation date"), false)
	}
}

func (e *evaluation) permissions() {
	kind := e.it.kind
	if !privateKind(kind) || e.it.bits&0o077 == 0 ||
		kind == "kubeconfig" && !e.flag("embedded_client_key") && !e.flag("token_auth") {
		return
	}
	sev, enc := "medium", ""
	if e.it.bits&0o004 != 0 {
		sev = "high"
	}
	if e.flag("encrypted") {
		sev, enc = "low", " (encrypted)"
	}
	e.add(secret("secret.permissions_too_open", kind+enc+" readable by group/others (mode "+e.it.mode+")", sev,
		"chmod 600 (dirs 700)"), false)
}

func (e *evaluation) properties() {
	m := e.it.m
	switch e.it.kind {
	case "private-key":
		base := e.it.path[strings.LastIndexByte(e.it.path, '/')+1:]
		if m.Value("passphrase") == false && !strings.HasPrefix(base, "ssh_host_") {
			// (an SSH server's host key never has a passphrase: the daemon must read it unattended)
			e.add(secret("secret.ssh_key_no_passphrase", "private key without passphrase ("+
				pyvalue.Str(m.GetOr("type", m.Value("format")))+", "+e.age()+"d old)", "medium",
				"add a passphrase (ssh-keygen -p) + agent, or move to a hardware/Secure-Enclave key"), true)
		}
	case "kubeconfig":
		if e.flag("embedded_client_key") {
			e.add(secret("secret.kubeconfig_embedded_client_key", "kubeconfig embeds a client private key (long-lived, not revocable)",
				"medium", "short-lived credentials (OIDC/exec plugin); keep admin certs offline"), false)
		}
	case "tf-state":
		if !e.flag("encrypted") {
			e.add(secret("secret.tf_state_plaintext", "plaintext Terraform/OpenTofu state (may contain secrets)",
				"medium", "enable state encryption or delete stale state files"), false)
		}
	default:
		e.configs()
	}
}

func (e *evaluation) configs() {
	switch kind := e.it.kind; {
	case kind == "rclone-config" && !e.flag("encrypted"):
		e.add(secret("secret.rclone_config_plaintext", "rclone config not encrypted (remote credentials only obscured)",
			"medium", "rclone config encryption, or keep 600 on a trusted host"), false)
	case kind == "docker-config" && e.flag("inline_auth"):
		e.add(secret("secret.docker_inline_auth", "registry credentials stored inline in docker config",
			"medium", "use a credential helper (credsStore)"), false)
	case kind == "gh-config" && e.flag("token_in_file"):
		e.add(secret("secret.gh_token_in_file", "GitHub token stored in plain file", "medium",
			"gh auth login with keyring storage"), false)
	case kind == "notes" && e.flag("credential_like_lines"):
		e.add(spdoc.Finding{Layer: "ai-agents", Check: "secret.credential_in_notes",
			Title: pyvalue.Str(e.it.m.Value("credential_like_lines")) +
				" line(s) that look like a credential value in a notes/memory file read by AI agents", Severity: "high",
			Remediation: "remove the values (keep only 'where it is stored'), then rotate those credentials"}, true)
	}
}
