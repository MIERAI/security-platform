package agentclaude

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Rules and paths. Never written after initialisation.
var (
	// a deny rule naming a credential path (collectors/agent-claude-code CRED_PATHS)
	credPaths = regexp.MustCompile(`(?i)(\.ssh|\.kube|\.aws|\.config/gh|\.config/gcloud|\.docker/config|\.netrc|credentials|secrets?|token)`)
	notAlnum  = regexp.MustCompile(`[^a-z0-9]+`)
	notLower  = regexp.MustCompile(`[^a-z]+`)
)

// broadRule is an allow rule shape that effectively grants arbitrary execution, remote reach or credential access.
type broadRule struct {
	re  *regexp.Regexp
	why string
}

func broadRules() []broadRule {
	return []broadRule{
		{regexp.MustCompile(`^Bash(\(\*\)|\(\*:\*\))?$`), "any shell command"},
		{regexp.MustCompile(`^Bash\((ssh|scp|rsync)[ :]`), "remote shell to other hosts"},
		{regexp.MustCompile(`^Bash\((kubectl|helm|tofu|terraform|ansible|ansible-playbook)[ :]`), "infrastructure control"},
		{regexp.MustCompile(`^Bash\((gh|git push)[ :]`), "code-host write access"},
		{regexp.MustCompile(`^Bash\((curl|wget)[ :]`), "arbitrary network egress"},
		{regexp.MustCompile(`^Bash\((python3?|node|bash|sh|zsh|uv run)[ :]`), "arbitrary interpreter"},
		{regexp.MustCompile(`^Bash\((sudo|rm)[ :]`), "destructive/privileged"},
		{regexp.MustCompile(`^(Read|Edit|Write)\((~|/|\*\*)`), "file access outside the project"},
	}
}

// settingsFile is one configured settings path that exists. doc is nil when the file is not a settings document
// (bad JSON, not an object, rules that are not text): it is then a coverage gap, not a crash of the run.
type settingsFile struct {
	configured, path string
	mode             os.FileMode
	doc              *settingsDoc
	problem          string
}

type hookCount struct {
	event string
	n     int
}

type settingsDoc struct {
	root                    *pyvalue.Map
	perms                   *pyvalue.Map
	allow, deny             []string
	additional, envKeys     int
	hooks                   []hookCount
	hasCleanup              bool
	cleanup                 int64
	defaultMode, blockReads any
	skipDanger              any
	hookNames               []string
	broadOrder              []string
	broadCount              map[string]int
}

var errNotSettings = errors.New("not a settings document")

func (c *collector) readSettings(a *pyvalue.Map) []*settingsFile {
	var out []*settingsFile
	for _, v := range rundoc.List(a.Value("settings")) {
		sp, ok := v.(string)
		if !ok {
			continue
		}
		p := rundoc.ExpandUser(sp, c.home)
		st, err := os.Stat(p)
		if err != nil {
			continue // os.path.exists: a missing (or unreadable) path is skipped
		}
		f := &settingsFile{configured: sp, path: p, mode: st.Mode().Perm()}
		doc, err := parseSettingsFile(p)
		if err != nil {
			f.problem = err.Error()
		} else {
			f.doc = doc
		}
		out = append(out, f)
	}
	return out
}

func parseSettingsFile(p string) (*settingsDoc, error) {
	data, err := rundoc.ReadLimited(p, maxSettingsFile)
	if err != nil {
		return nil, fmt.Errorf("%w: unreadable: %w", errNotSettings, err)
	}
	return ParseSettings(data)
}

// ParseSettings reads a settings file (JSON object) and the keys the collector looks at.
func ParseSettings(data []byte) (*settingsDoc, error) {
	v, err := pyvalue.DecodeJSON(data)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid JSON", errNotSettings)
	}
	root, ok := v.(*pyvalue.Map)
	if !ok {
		return nil, fmt.Errorf("%w: not a JSON object", errNotSettings)
	}
	d := &settingsDoc{root: root, perms: pyvalue.NewMap(), broadCount: map[string]int{}}
	if err := d.readPermissions(); err != nil {
		return nil, err
	}
	if err := d.readHooks(); err != nil {
		return nil, err
	}
	if err := d.readScalars(); err != nil {
		return nil, err
	}
	d.classify()
	return d, nil
}

func (d *settingsDoc) readPermissions() error {
	if p := d.root.Value("permissions"); pyvalue.Truthy(p) {
		m, ok := p.(*pyvalue.Map)
		if !ok {
			return fmt.Errorf("%w: permissions is not an object", errNotSettings)
		}
		d.perms = m
	}
	var err error
	if d.allow, err = ruleList(d.perms.Value("allow"), "allow"); err != nil {
		return err
	}
	if d.deny, err = ruleList(d.perms.Value("deny"), "deny"); err != nil {
		return err
	}
	if v := d.perms.Value("additionalDirectories"); pyvalue.Truthy(v) {
		l, ok := v.([]any)
		if !ok {
			return fmt.Errorf("%w: additionalDirectories is not a list", errNotSettings)
		}
		d.additional = len(l)
	}
	d.defaultMode, d.blockReads = d.perms.Value("defaultMode"), d.perms.Value("blockReadsOutsideWorkingDirectories")
	return nil
}

func ruleList(v any, what string) ([]string, error) {
	if !pyvalue.Truthy(v) {
		return nil, nil
	}
	l, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a list", errNotSettings, what)
	}
	out := make([]string, len(l))
	for i, e := range l {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("%w: %s[%d] is not text", errNotSettings, what, i)
		}
		out[i] = s
	}
	return out, nil
}

func (d *settingsDoc) readHooks() error {
	h := d.root.Value("hooks")
	if !pyvalue.Truthy(h) {
		return nil
	}
	m, ok := h.(*pyvalue.Map)
	if !ok {
		return fmt.Errorf("%w: hooks is not an object", errNotSettings)
	}
	for _, k := range m.Keys() {
		n, ok := pyLen(m.Value(k))
		if !ok {
			return fmt.Errorf("%w: hooks.%s is not a list", errNotSettings, k)
		}
		d.hooks = append(d.hooks, hookCount{event: k, n: n})
	}
	d.hookNames = append([]string(nil), m.Keys()...)
	sort.Strings(d.hookNames)
	return nil
}

// pyLen is len(v or []) for the sized values JSON has.
func pyLen(v any) (int, bool) {
	switch x := v.(type) {
	case nil:
		return 0, true
	case []any:
		return len(x), true
	case *pyvalue.Map:
		return x.Len(), true
	case string:
		return utf8.RuneCountInString(x), true
	case bool:
		return 0, !x
	case int64:
		return 0, x == 0
	case float64:
		return 0, x == 0
	}
	return 0, false
}

func (d *settingsDoc) readScalars() error {
	d.skipDanger = d.root.Value("skipDangerousModePermissionPrompt")
	n, ok := pyLen(d.root.Value("env"))
	if !ok {
		return fmt.Errorf("%w: env is not an object", errNotSettings)
	}
	d.envKeys = n
	if v := d.root.Value("cleanupPeriodDays"); v != nil {
		r, err := pyvalue.ToInt(v)
		if err != nil {
			return fmt.Errorf("%w: cleanupPeriodDays is not a number", errNotSettings)
		}
		d.hasCleanup, d.cleanup = true, r
	}
	return nil
}

// classify groups the allow rules by the broad grant they amount to, in the order the grants first appear.
func (d *settingsDoc) classify() {
	for _, r := range d.allow {
		for _, b := range broadRules() {
			if b.re.MatchString(r) {
				if d.broadCount[b.why] == 0 {
					d.broadOrder = append(d.broadOrder, b.why)
				}
				d.broadCount[b.why]++
			}
		}
	}
}

// evidenceName is the evidence file of a settings path: re.sub("[^a-z0-9]+", "-", path.lower()).strip("-").json
func evidenceName(configured string) string {
	return strings.Trim(notAlnum.ReplaceAllString(strings.ToLower(configured), "-"), "-") + ".json"
}

func (c *collector) settings(f *settingsFile) error {
	asset := "agent:claude-code:" + f.configured
	if f.doc == nil {
		c.doc.Gap(asset, "settings file not evaluated: "+f.problem, nil)
		return nil
	}
	d := f.doc
	broad := map[string]any{}
	for _, k := range d.broadOrder {
		broad[k] = d.broadCount[k]
	}
	hooks := make([]any, len(d.hookNames))
	for i, h := range d.hookNames {
		hooks[i] = h
	}
	mode := "0o" + strconv.FormatUint(uint64(f.mode), 8)
	ev, err := c.doc.Raw(c.runDir, evidenceName(f.configured), rundoc.JSON(map[string]any{
		"defaultMode": rundoc.Loose(d.defaultMode), "blockReadsOutsideWorkingDirectories": rundoc.Loose(d.blockReads),
		"skipDangerousModePermissionPrompt": rundoc.Loose(d.skipDanger), "allow_rules": len(d.allow),
		"deny_rules": len(d.deny), "additional_directories": d.additional, "hooks": hooks, "env_keys": d.envKeys,
		"broad_allow": broad, "mode": mode}))

	if err != nil {
		return err
	}
	c.doc.OK(asset, "")
	c.settingsFindings(asset, ev, d, f.mode, mode)
	return nil
}

func (c *collector) settingsFindings(asset, ev string, d *settingsDoc, perm os.FileMode, mode string) {
	if d.defaultMode == "bypassPermissions" {
		title := "agent runs in bypassPermissions by default (no per-action confirmation)"
		if pyvalue.Truthy(d.skipDanger) {
			title += " and the danger prompt is skipped"
		}
		c.doc.AddFinding(&rundoc.Finding{Layer: layer, Asset: asset, Check: "agent.bypass_permissions_default", Title: title,
			Severity: "high", Evidence: ev, NeedsHuman: true,
			Remediation: "default to an allowlist mode; use bypass only in a sandbox/container"})

	}
	if b, ok := d.blockReads.(bool); ok && !b {
		c.doc.AddFinding(&rundoc.Finding{Layer: layer, Asset: asset, Check: "agent.reads_outside_workdir",
			Title:    "agent may read outside its working directories (blockReadsOutsideWorkingDirectories=false): ~/.ssh, kubeconfigs, tokens are readable",
			Severity: "high", Evidence: ev, NeedsHuman: true,
			Remediation: "turn it on; add needed dirs explicitly to additionalDirectories"})

	}
	for _, why := range d.broadOrder {
		c.doc.AddFinding(&rundoc.Finding{Layer: layer, Asset: asset, Check: "agent.broad_allow." + notLower.ReplaceAllString(why, "_"),
			Title:    fmt.Sprintf("%d allow rule(s) grant %s without confirmation", d.broadCount[why], why),
			Severity: "medium", Evidence: ev, NeedsHuman: true,
			Remediation: "narrow to read-only subcommands; require confirmation for writes"})

	}
	if perm&0o022 != 0 {
		c.doc.AddFinding(&rundoc.Finding{Layer: layer, Asset: asset, Check: "agent.settings_writable_by_others",
			Title: "settings file writable by others (" + mode + ")", Severity: "high", Evidence: ev, Remediation: "chmod 600"})

	}
}
