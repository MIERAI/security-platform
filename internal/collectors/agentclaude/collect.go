// Package agentclaude is the agent-claude-code collector (collectors/agent-claude-code): what a coding agent is
// allowed to do, READ-ONLY. It reads permission-related keys of the agent's settings files (never `env` values),
// scans its memory files for credential shapes (the file and the pattern class are reported, never the value) and
// looks at the metadata of its session transcripts (count, age, size; never the content).
package agentclaude

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Version is the collector's version (collectors/agent-claude-code/VERSION; TestVersionMatchesTree keeps them equal).
const Version = "0.3.0"

// Name is the collector's name (the document is <name>.findings.json unless SP_COLLECTOR_NAME says otherwise).
const Name = "agent-claude-code"

const (
	layer             = "ai-agents"
	defaultRetention  = 30
	maxSettingsFile   = 4 << 20
	maxMemoryFile     = 16 << 20
	guardAsset        = "agent-guard:claude-code"
	memoryAsset       = "agent-memory:claude-code"
	auditAsset        = "agent-audit:claude-code"
	defaultTranscript = "~/.claude/projects"
)

// Main is `sp agent-claude-code collect`.
func Main(ctx context.Context, env *rundoc.Env, args []string, stdout io.Writer) int {
	return rundoc.Main(ctx, &rundoc.Collector{Name: Name, Version: Version, Collect: collect}, args, env, stdout)
}

// collect is one run (collector protocol); the caller writes the document.
func collect(_ context.Context, run *rundoc.Run, env *rundoc.Env) error {
	c := &collector{runDir: run.Dir, doc: run.Doc, home: env.Home(), now: float64(env.Clock()().UnixNano()) / 1e9}
	for i, a := range rundoc.List(run.Instance.Value("agents")) {
		if err := c.agent(a); err != nil {
			return fmt.Errorf("%w: agents[%d]: %w", rundoc.ErrUsage, i, err)
		}
	}
	return nil
}

type collector struct {
	runDir string // SP_RUN_DIR: the evidence goes under it
	doc    *rundoc.Document
	home   string
	now    float64 // epoch seconds
}

var errNoType = errors.New("no type")

func (c *collector) agent(v any) error {
	a, ok := v.(*pyvalue.Map)
	if !ok || !a.Has("type") {
		return errNoType
	}
	if t := pyvalue.Str(a.Value("type")); t != "claude-code" {
		c.doc.Gap("agent:"+t, "adapter not implemented (future)", nil)
		return nil
	}
	files := c.readSettings(a)
	if err := c.guard(files); err != nil {
		return err
	}
	if err := c.memory(a); err != nil {
		return err
	}
	if err := c.auditTrail(a, retention(files)); err != nil {
		return err
	}
	for _, f := range files {
		if err := c.settings(f); err != nil {
			return err
		}
	}
	return nil
}

func (c *collector) guard(files []*settingsFile) error {
	var deny []string
	hooks := map[string]any{}
	counts := map[string]int64{}
	for _, f := range files {
		if f.doc == nil {
			continue
		}
		deny = append(deny, f.doc.deny...)
		for _, h := range f.doc.hooks {
			counts[h.event] += int64(h.n)
		}
	}
	for k, n := range counts {
		hooks[k] = n
	}
	guarded := 0
	for _, r := range deny {
		if credPaths.MatchString(r) {
			guarded++
		}
	}
	ev, err := c.doc.Raw(c.runDir, "guards.json", rundoc.JSON(map[string]any{"deny_rules": len(deny), "credential_path_deny_rules": guarded,
		"hooks": hooks}))

	if err != nil {
		return err
	}
	c.doc.OK(guardAsset, "")
	if guarded == 0 {
		c.doc.AddFinding(&rundoc.Finding{Layer: layer, Asset: guardAsset, Check: "agent.no_credential_deny_rules",
			Title:    "no deny rule protects credential paths (~/.ssh, kubeconfigs, cloud and gh credentials) from the agent",
			Severity: "medium", Evidence: ev, NeedsHuman: true,
			Remediation: "add deny rules such as Read(~/.ssh/**), Read(~/.kube/**), Read(~/.config/gh/**); grant exceptions per project"})

	}
	return nil
}

// retention is the transcripts' retention in days: the last settings file that sets cleanupPeriodDays wins.
func retention(files []*settingsFile) int64 {
	r := int64(defaultRetention)
	for _, f := range files {
		if f.doc != nil && f.doc.hasCleanup {
			r = f.doc.cleanup
		}
	}
	return r
}
