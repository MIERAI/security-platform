package ledger

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MIERAI/security-platform/internal/ledger/fileio"
	"github.com/MIERAI/security-platform/internal/ledger/instant"
	"github.com/MIERAI/security-platform/internal/ledger/prom"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// write produces every output of §1; ledger.json last but one (the private report follows it, as the
// reference), so that an earlier failure leaves the previous ledger in place.
func (m *merger) write(docs []document, invalid *pyjson.Object, slis []sliResult, series []prom.Series) error {
	text := []byte(prom.Render(series))
	metricsDir := filepath.Join(m.opt.Data, "metrics")
	if err := os.MkdirAll(metricsDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", metricsDir, err)
	}
	steps := []func() error{
		func() error { return fileio.Write(filepath.Join(m.opt.Run, "sli.prom"), text) },
		func() error { return fileio.Write(filepath.Join(metricsDir, "ledger.prom"), text) },
		m.writeAllProm,
		m.writeOCSF,
		func() error { return m.writeLedger(docs, invalid, slis) },
		m.writeReport,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	m.summary(invalid.Len(), slis)
	return nil
}

// writeAllProm concatenates every RUN/*.prom (except all.prom itself) in name order.
func (m *merger) writeAllProm() error {
	entries, err := os.ReadDir(m.opt.Run)
	if err != nil {
		return fmt.Errorf("list %s: %w", m.opt.Run, err)
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, ".prom") && !strings.HasPrefix(n, ".") && !strings.HasSuffix(n, "all.prom") && !e.IsDir() {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var all []byte
	for _, n := range names {
		data, err := readFile(filepath.Join(m.opt.Run, n), MaxDocumentBytes)
		if err != nil {
			return fmt.Errorf("read %s: %w", n, err)
		}
		all = append(all, data...)
	}
	return fileio.Write(filepath.Join(m.opt.Run, "all.prom"), all)
}

func (m *merger) writeOCSF() error {
	var b strings.Builder
	for _, id := range m.entries.Keys() {
		e := m.entries.Obj(id)
		if e == nil {
			continue
		}
		line, err := pyjson.Marshal(OCSF(e), pyjson.Compact())
		if err != nil {
			return fmt.Errorf("ocsf %s: %w", id, err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return fileio.Write(filepath.Join(m.opt.Run, "ocsf.jsonl"), []byte(b.String()))
}

func (m *merger) writeLedger(docs []document, invalid *pyjson.Object, slis []sliResult) error {
	now := instant.ISO(m.opt.Now)
	runDir, err := relPath(m.opt.Data, m.opt.Run)
	if err != nil {
		return err
	}
	cols := pyjson.NewObject()
	for _, d := range docs {
		cols.Set(d.collector, d.version)
	}
	runs, _ := m.ledger.Get("runs")
	list, _ := runs.([]pyjson.Value) // absent or malformed: a fresh list
	list = append(list, pyjson.ObjectOf("at", now, "run_dir", runDir, "core", m.opt.Version, "implementation", "go",
		"collectors", cols, "invalid", invalid))
	m.ledger.Set("runs", list)
	sli := pyjson.NewObject()
	for _, r := range slis {
		sli.Set(r.name, pyjson.ObjectOf("value", r.value, "target", r.def.target, "ok", r.ok, "description", r.def.description))
	}
	m.ledger.Set("sli", sli)
	m.ledger.Set("updated_at", now)
	data, err := pyjson.Marshal(m.ledger, pyjson.Ledger())
	if err != nil {
		return fmt.Errorf("encode ledger: %w", err)
	}
	return fileio.WriteDurable(filepath.Join(m.opt.Data, "ledger.json"), data)
}

// relPath is os.path.relpath(target, base) on absolute paths.
func relPath(base, target string) (string, error) {
	ab, err := filepath.Abs(base)
	if err != nil {
		return "", fmt.Errorf("data dir: %w", err)
	}
	at, err := filepath.Abs(target)
	if err != nil {
		return "", fmt.Errorf("run dir: %w", err)
	}
	rel, err := filepath.Rel(ab, at)
	if err != nil {
		return "", fmt.Errorf("run dir relative to the data dir: %w", err)
	}
	return rel, nil
}

func (m *merger) summary(invalid int, slis []sliResult) {
	open := len(m.byStatus(statusOpen))
	gaps, _ := m.ledger.Obj("sli").Obj("collector_coverage_gaps").Get("value")
	_, _ = fmt.Fprintf(m.opt.Stderr, "[ledger %s] entries=%d open=%d invalid_docs=%d gaps=%s\n", m.opt.Version,
		m.entries.Len(), open, invalid, pyjson.Str(gaps)) // stderr is best effort
	for _, r := range slis {
		state := "BREACH"
		if r.ok {
			state = "OK"
		}
		_, _ = fmt.Fprintf(m.opt.Stderr, "  SLI %s = %s (<= %s) %s\n", r.name, pyjson.Str(r.value), pyjson.Str(r.def.target), state)
	}
}
