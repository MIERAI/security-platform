package agentclaude

import (
	"fmt"
	"os"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const (
	day           = 86400.0
	recentWindow  = 7 * day
	bytesPerMB    = 1e6
	defaultMinRet = 30
)

// trail is the metadata of the session transcripts: never their content.
type trail struct {
	files          int
	newest, oldest float64 // modification times, epoch seconds; 0 when there is none
	size           int64
}

func readTrail(dirs []string) trail {
	var t trail
	for _, d := range dirs {
		for _, p := range transcripts(d) {
			st, err := os.Stat(p)
			if err != nil {
				continue
			}
			t.files++
			m := float64(st.ModTime().UnixNano()) / 1e9
			if t.files == 1 || m > t.newest {
				t.newest = m
			}
			if t.files == 1 || m < t.oldest {
				t.oldest = m
			}
			t.size += st.Size()
		}
	}
	return t
}

func (c *collector) ageDays(t float64) any {
	if t == 0 {
		return nil
	}
	return pyvalue.Round((c.now-t)/day, 1)
}

func (c *collector) auditTrail(a *pyvalue.Map, retention int64) error {
	configured := []string{defaultTranscript}
	if a.Has("transcripts_dirs") {
		configured = rundoc.Texts(a.Value("transcripts_dirs"))
	}
	dirs := make([]string, len(configured))
	for i, d := range configured {
		dirs[i] = rundoc.ExpandUser(d, c.home)
	}
	t := readTrail(dirs)
	ev, err := c.doc.Raw(c.runDir, "audit-trail.json", rundoc.JSON(map[string]any{"transcripts": t.files, "newest_age_days": c.ageDays(t.newest),
		"oldest_age_days": c.ageDays(t.oldest), "retention_days": retention,
		"size_mb": pyvalue.Round(float64(t.size)/bytesPerMB, 1)}))

	if err != nil {
		return err
	}
	if !anyDir(dirs) {
		c.doc.Gap(auditAsset, "transcripts directory not found", nil)
		return nil
	}
	c.doc.OK(auditAsset, "")
	minRet := int64(defaultMinRet)
	if v, ok := a.Get("min_transcript_retention_days"); ok {
		if minRet, err = pyvalue.ToInt(v); err != nil {
			return fmt.Errorf("min_transcript_retention_days: %w", err)
		}
	}
	switch {
	case t.files == 0 || t.newest == 0 || c.now-t.newest > recentWindow:
		c.doc.AddFinding(&rundoc.Finding{Layer: layer, Asset: auditAsset, Check: "agent.audit_trail_missing",
			Title: "no agent session transcript in the last 7 days (audit trail off?)", Severity: "medium", Evidence: ev,
			Remediation: "keep session transcripts (do not disable them); they are the agent's audit trail"})

	case retention < minRet:
		c.doc.AddFinding(&rundoc.Finding{Layer: layer, Asset: auditAsset, Check: "agent.audit_trail_missing",
			Title:    fmt.Sprintf("agent transcripts are kept %d days (< %d): too short to investigate an incident", retention, minRet),
			Severity: "low", Evidence: ev, Remediation: fmt.Sprintf("set cleanupPeriodDays >= %d", minRet)})

	}
	c.doc.Metric("security_agent_transcripts", float64(t.files), "Agent session transcripts kept (audit trail; metadata only)", nil)
	return nil
}

func anyDir(dirs []string) bool {
	for _, d := range dirs {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			return true
		}
	}
	return false
}
