package agentclaude

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
)

// canary values are assembled at run time: no credential-shaped string is committed (secret scanners).
func canaries() (github, password, env string) {
	return "gh" + "p_" + strings.Repeat("Q7", 18), "Canary-Pw-" + "Zx81Kq09", "env-canary-" + "7f3a9c"
}

func TestLineClasses(t *testing.T) {
	t.Parallel()
	gh, pw, _ := canaries()
	tests := []struct {
		line string
		want []string
	}{
		{"github token for the bot: " + gh, []string{ClassGitHub}},
		{"password: " + pw, []string{ClassAssignment}},
		{"password = same as the admin UI", nil},
		{"token=" + pw + "中文", nil},                         // the value must end at white space or punctuation
		{"token=" + pw + "，下一个", []string{ClassAssignment}}, // full-width comma ends it
		{"secret：" + pw + ")", []string{ClassAssignment}},   // full-width colon
		{"PASSWORD　=　" + pw, []string{ClassAssignment}},     // Python's \s includes U+3000
		{"-----BEGIN " + "RSA PRIVATE KEY-----", []string{ClassPrivateKey}},
		{"AK" + "IA" + "ABCDEFGHIJKLMNOP", []string{ClassAWS}},
		{"ak" + "ia" + "abcdefghijklmnop", []string{ClassAWS}}, // re.I, as the reference
		{"xox" + "b-" + "1234567890-abc", []string{ClassSlack}},
		{"sk-" + strings.Repeat("a", 32), []string{ClassSecretKey}},
		{"AI" + "za" + strings.Repeat("b", 35), []string{ClassGoogle}},
		{"key " + gh + " and password: " + pw, []string{ClassAssignment, ClassGitHub}},
		{"nothing here", nil},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			t.Parallel()
			if got := LineClasses(tt.line); !slices.Equal(got, tt.want) {
				t.Errorf("LineClasses = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSplitLines(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want []string
	}{{"", nil}, {"a", []string{"a"}}, {"a\n", []string{"a"}}, {"a\r\nb\rc\n\nd", []string{"a", "b", "c", "", "d"}}}
	for _, tt := range tests {
		if got := SplitLines(tt.in); !slices.Equal(got, tt.want) {
			t.Errorf("SplitLines(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func write(t *testing.T, p, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

type document struct {
	Findings []struct {
		Asset, Check string
		Attributes   json.RawMessage
	}
	Coverage []struct{ Asset, Status string }
}

type runResult struct {
	doc    document
	stderr string
	files  map[string][]byte
}

func collect(t *testing.T, dir string, inst map[string]any) runResult {
	t.Helper()
	instPath := filepath.Join(dir, "instance.json")
	data, err := json.Marshal(inst)
	if err != nil {
		t.Fatal(err)
	}
	write(t, instPath, string(data))
	run := filepath.Join(dir, "run")
	vars := map[string]string{"SP_INSTANCE": instPath, "SP_RUN_DIR": run, "HOME": filepath.Join(dir, "home")}
	var stderr bytes.Buffer
	env := rundoc.Env{Getenv: func(k string) string { return vars[k] }, Stderr: &stderr, Now: time.Now}
	if code := Main(context.Background(), env, []string{"collect"}); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	res := runResult{stderr: stderr.String(), files: map[string][]byte{}}
	err = filepath.WalkDir(run, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		res.files[p] = b
		return rerr
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(res.files[filepath.Join(run, Name+".findings.json")], &res.doc); err != nil {
		t.Fatal(err)
	}
	return res
}

func checks(doc document) []string {
	var out []string
	for _, f := range doc.Findings {
		out = append(out, f.Check)
	}
	return out
}

func noCanary(t *testing.T, res runResult, canaries ...string) {
	t.Helper()
	for p, b := range res.files {
		for _, c := range canaries {
			if bytes.Contains(b, []byte(c)) {
				t.Errorf("canary %.8s... in %s", c, p)
			}
		}
	}
	for _, c := range canaries {
		if strings.Contains(res.stderr, c) {
			t.Errorf("canary %.8s... on stderr", c)
		}
	}
}

// TestCredentialValuesNeverLeave plants canary credentials in memory files and the settings' env and asserts that
// no output file and no output line carries any of them, while the findings name the file and the classes.
func TestCredentialValuesNeverLeave(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	gh, pw, envSecret := canaries()
	home := filepath.Join(dir, "home")
	write(t, filepath.Join(home, "mem", "p", "memory", "MEMORY.md"), "bot "+gh+"\npassword: "+pw+"\n")
	write(t, filepath.Join(home, "settings.json"), `{"env": {"TOKEN": "`+envSecret+`"}, "permissions": {"allow": ["Bash(*)"]}}`)
	res := collect(t, dir, map[string]any{"agents": []any{map[string]any{"type": "claude-code",
		"settings": []any{"~/settings.json"}, "memory_dirs": []any{"~/mem"}}}})
	noCanary(t, res, gh, pw, envSecret)
	i := slices.IndexFunc(res.doc.Findings, func(f struct {
		Asset, Check string
		Attributes   json.RawMessage
	}) bool {
		return f.Asset == "agent-memory:claude-code/p/MEMORY.md"
	})
	if i < 0 {
		t.Fatalf("no memory finding: %v", checks(res.doc))
	}
	var attrs map[string][]string
	if err := json.Unmarshal(res.doc.Findings[i].Attributes, &attrs); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(attrs["pattern_classes"], []string{ClassAssignment, ClassGitHub}) {
		t.Errorf("attributes %v", attrs)
	}
}

func TestMalformedSettingsAreGaps(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	tests := map[string]string{"bad.json": `{"permissions":`, "list.json": `[1]`, "rules.json": `{"permissions": {"allow": [1]}}`,
		"hooks.json": `{"hooks": [1]}`, "days.json": `{"cleanupPeriodDays": "soon"}`, "good.json": `{"cleanupPeriodDays": "12"}`}
	var settings []any
	for name, text := range tests {
		write(t, filepath.Join(home, name), text)
		settings = append(settings, "~/"+name)
	}
	res := collect(t, dir, map[string]any{"agents": []any{map[string]any{"type": "claude-code", "settings": settings}}})
	cov := map[string]string{}
	for _, c := range res.doc.Coverage {
		cov[c.Asset] = c.Status
	}
	for name := range tests {
		want := "gap"
		if name == "good.json" {
			want = "ok"
		}
		if got := cov["agent:claude-code:~/"+name]; got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
	if !strings.Contains(string(res.files[filepath.Join(dir, "run", "raw", Name, "audit-trail.json")]), `"retention_days": 12`) {
		t.Error("cleanupPeriodDays given as text is read as int() reads it")
	}
}

func TestEvidenceName(t *testing.T) {
	t.Parallel()
	if got := evidenceName("~/.claude/Settings.Local.json"); got != "claude-settings-local-json.json" {
		t.Error(got)
	}
}

func TestVersionMatchesTree(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "collectors", "agent-claude-code", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != Version {
		t.Fatalf("collectors/agent-claude-code/VERSION %s, Go %s", got, Version)
	}
}

func TestUsage(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	env := rundoc.Env{Getenv: func(string) string { return "" }, Stderr: &stderr, Now: time.Now}
	if code := Main(context.Background(), env, nil); code != 2 {
		t.Errorf("no verb: exit %d", code)
	}
	if code := Main(context.Background(), env, []string{"collect"}); code != 2 || !strings.Contains(stderr.String(), "SP_INSTANCE") {
		t.Errorf("no SP_INSTANCE: exit %d %q", code, stderr.String())
	}
}
