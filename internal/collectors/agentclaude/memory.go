package agentclaude

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// memoryHit is a memory file with credential-shaped lines: how many and of which classes. Never the text.
type memoryHit struct {
	path    string
	lines   int
	classes []string
}

func (c *collector) memory(a *pyvalue.Map) error {
	var hits []memoryHit
	files := 0
	for _, d := range rundoc.Strings(a.Value("memory_dirs")) {
		for _, p := range markdownFiles(rundoc.ExpandUser(d, c.home)) {
			files++
			n, classes, err := ScanFile(p)
			if err != nil || n == 0 {
				continue // unreadable: as the reference, counted but not scanned
			}
			hits = append(hits, memoryHit{path: p, lines: n, classes: classes})
		}
	}
	if !pyvalue.Truthy(a.Value("memory_dirs")) {
		c.doc.Gap(memoryAsset, "no memory_dirs configured")
		return nil
	}
	c.doc.OK(memoryAsset)
	sort.Slice(hits, func(i, j int) bool { return hits[i].path < hits[j].path })
	suspect, classes := map[string]any{}, map[string]any{}
	for _, h := range hits {
		suspect[filepath.Base(h.path)] = h.lines
		classes[filepath.Base(h.path)] = h.classes
	}
	ev, err := c.doc.Raw("memory-scan.json", map[string]any{"files": files, "suspect_files": suspect,
		"pattern_classes": classes})
	if err != nil {
		return err
	}
	for _, h := range hits {
		base := filepath.Base(h.path)
		c.doc.Add(&rundoc.Finding{Layer: layer, Check: "agent.memory_secret_suspect",
			Asset:    memoryAsset + "/" + filepath.Base(filepath.Dir(filepath.Dir(h.path))) + "/" + base,
			Title:    fmt.Sprintf("%d line(s) shaped like a credential in agent memory file %s", h.lines, base),
			Severity: "high", Evidence: ev, NeedsHuman: true, Attributes: map[string]any{"pattern_classes": h.classes},
			Remediation: "remove the value (keep where it lives, not what it is); rotate it if it was real"})
	}
	c.doc.Metric("security_agent_memory_files", float64(files), "Agent memory files scanned for credential shapes")
	return nil
}

// ScanFile counts the lines of a memory file shaped like a credential and the classes seen.
func ScanFile(p string) (lines int, classes []string, err error) {
	data, err := rundoc.ReadLimited(p, maxMemoryFile)
	if err != nil {
		return 0, nil, err
	}
	n, cls := ScanText(string(data))
	return n, cls, nil
}

// ScanText counts the lines shaped like a credential and returns the sorted set of their classes.
func ScanText(text string) (lines int, classes []string) {
	seen := map[string]bool{}
	for _, line := range SplitLines(text) {
		cls := LineClasses(line)
		if len(cls) == 0 {
			continue
		}
		lines++
		for _, k := range cls {
			seen[k] = true
		}
	}
	classes = make([]string, 0, len(seen))
	for k := range seen {
		classes = append(classes, k)
	}
	sort.Strings(classes)
	return lines, classes
}

// markdownFiles is glob(<root>/**/*.md, recursive=True): every *.md entry under root, hidden files and
// directories skipped. Symbolic links to directories are not followed (the reference follows them, loops included).
func markdownFiles(root string) []string {
	var out []string
	walk := func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable entry is skipped, as glob does
		}
		if p == root {
			return nil
		}
		hidden := strings.HasPrefix(d.Name(), ".")
		if d.IsDir() {
			if hidden {
				return filepath.SkipDir
			}
		}
		if !hidden && matchMD(d.Name()) {
			out = append(out, p)
		}
		return nil
	}
	if err := filepath.WalkDir(root, walk); err != nil {
		return out // walk never fails: every error is skipped above
	}
	return out
}

func matchMD(name string) bool {
	ok, err := path.Match("*.md", name)
	return err == nil && ok
}

// transcripts is glob(<dir>/*/*.jsonl): the session files one level below each directory, hidden entries skipped.
func transcripts(dir string) []string {
	var out []string
	top, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range top {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		sub, err := os.ReadDir(filepath.Join(dir, e.Name()))
		if err != nil {
			continue // not a directory
		}
		for _, f := range sub {
			if ok, err := path.Match("*.jsonl", f.Name()); err == nil && ok && !strings.HasPrefix(f.Name(), ".") {
				out = append(out, filepath.Join(dir, e.Name(), f.Name()))
			}
		}
	}
	return out
}
