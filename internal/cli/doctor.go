package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/cli/flags"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// probeTimeout bounds the interpreter check.
const probeTimeout = 30 * time.Second

// collectorTools are the programs each collector needs on this machine (cloud: the engines' paths are in the
// instance, cloud.engines).
func collectorTools() map[string][]string {
	return map[string][]string{"exposure": {"nmap"}, "host": nil, "k8s": {"kubectl"}, "codehost-github": {"gh"},
		"vuln-intel": {"trivy"}, "secrets-files": nil, "agent-claude-code": nil, "codehost-gitea": nil,
		"identity": nil, "host-sbom": nil, "cloud": nil}
}

// collectorName is a collector directory name (anything else cannot be one).
var collectorName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// checkup collects doctor's lines and counts what must be fixed.
type checkup struct {
	s        *session
	b        strings.Builder
	problems int
}

func (c *checkup) ok(msg string) {
	fmt.Fprintf(&c.b, "  %s    %s\n", c.s.paint("32", "ok"), msg)
}

func (c *checkup) bad(msg, fix string) {
	c.problems++
	fmt.Fprintf(&c.b, "  %s   %s\n        -> %s\n", c.s.paint("31", "FIX"), msg, fix)
}

func runDoctor(ctx context.Context, s *session, _ *flags.Result) (int, error) {
	if err := s.locate(); err != nil {
		return 0, err
	}
	c := &checkup{s: s}
	fmt.Fprintf(&c.b, "config %s\n", s.instancePath)
	inst, err := s.instance()
	if err != nil {
		return 0, errors.Join(emit(s.env.Stdout, c.b.String()), err)
	}
	c.ok(fmt.Sprintf("loads (%d sections, name=%s)", inst.Len(), str(inst.GetOr("name", "?"))))
	c.dataDir()
	c.jobs(inst)
	c.ssh(inst)
	c.secretFiles(inst)
	c.python(ctx)
	if c.problems > 0 {
		c.b.WriteString("\n" + s.paint("31", fmt.Sprintf("%d thing(s) to fix", c.problems)) + "\n")
	} else {
		c.b.WriteString("\n" + s.paint("32", "ready: sp run") + "\n")
	}
	code := ExitOK
	if c.problems > 0 {
		code = ExitFail
	}
	return code, emit(s.env.Stdout, c.b.String())
}

func (c *checkup) dataDir() {
	fi, err := os.Stat(c.s.data)
	if err != nil {
		c.bad(fmt.Sprintf("data directory cannot be read (%v)", unwrapPath(err)), "check "+c.s.data)
		return
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 && c.s.env.GOOS != "windows" {
		c.bad(fmt.Sprintf("data directory is readable by others (mode 0o%s)", strconv.FormatUint(uint64(mode), 8)),
			"chmod 700 "+c.s.data)
		return
	}
	c.ok("data directory is private (0700)")
}

func (c *checkup) jobs(inst *pyvalue.Map) {
	names, jobs := jobsOf(inst)
	if len(names) == 0 {
		c.bad("no jobs in runner.jobs", "add jobs (sp init writes examples)")
	}
	tools := collectorTools()
	for _, name := range names {
		j := jobs[name]
		if pyvalue.Str(j.GetOr("type", "collector")) != "collector" {
			continue
		}
		col := pyvalue.Str(j.GetOr("collector", name))
		if !c.collectorExists(col) {
			c.bad(fmt.Sprintf("job %s: unknown collector %s", safe(name), safe(col)),
				"one of: "+strings.Join(sortedKeys(tools), ", "))
			continue
		}
		for _, t := range tools[col] {
			if col == "exposure" && !exposureLocal(inst) {
				continue // nmap runs on the remote vantage host
			}
			msg := fmt.Sprintf("job %s: needs %#q", safe(name), t)
			if c.which(t) {
				c.ok(msg)
			} else {
				c.bad(msg+" - not found", "install "+t+" (see docs/quickstart.md)")
			}
		}
	}
}

func exposureLocal(inst *pyvalue.Map) bool {
	vantage := asMap(field(asMap(inst.Value("exposure")), "vantage"))
	return field(vantage, "type") == "local"
}

// collectorExists reports whether the product tree has the collector (collectors/<name>/collector.py).
func (c *checkup) collectorExists(col string) bool {
	if c.s.env.Tree == "" || !collectorName.MatchString(col) {
		return false
	}
	fi, err := os.Stat(filepath.Join(c.s.env.Tree, "collectors", col, "collector.py"))
	return err == nil && !fi.IsDir()
}

// which reports whether a program is on PATH (shutil.which: an executable regular file).
func (c *checkup) which(prog string) bool {
	for _, dir := range filepath.SplitList(c.s.env.Getenv("PATH")) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue // a relative PATH entry depends on the working directory: not trusted
		}
		for _, name := range exeNames(prog, c.s.env.GOOS) {
			fi, err := os.Stat(filepath.Join(dir, name))
			if err == nil && fi.Mode().IsRegular() && (c.s.env.GOOS == "windows" || fi.Mode().Perm()&0o111 != 0) {
				return true
			}
		}
	}
	return false
}

func exeNames(prog, goos string) []string {
	if goos == "windows" {
		return []string{prog + ".exe", prog + ".cmd", prog + ".bat", prog}
	}
	return []string{prog}
}

func (c *checkup) ssh(inst *pyvalue.Map) {
	hosts, _ := inst.Value("hosts").([]any)
	for _, h := range hosts {
		if field(asMap(field(asMap(h), "exec")), "type") == "ssh" && !c.which("ssh") {
			c.bad("hosts use ssh but `ssh` is not installed", "install an OpenSSH client")
			return
		}
	}
}

// secretFile is a *_file setting that names a secret.
type secretFile struct{ section, key, path string }

func secretFilesOf(inst *pyvalue.Map) []secretFile {
	var out []secretFile
	for _, sect := range []string{"codehost", "notify"} {
		entries, _ := inst.Value(sect).([]any)
		for _, e := range entries {
			out = append(out, fileKeys(sect, asMap(e))...)
		}
	}
	sinks, _ := field(asMap(inst.Value("runner")), "sinks").([]any)
	for _, e := range sinks {
		out = append(out, fileKeys("sink", asMap(e))...)
	}
	return out
}

// fileKeys are the *_file settings of one entry, except ca_file (a CA bundle is not a secret).
func fileKeys(section string, m *pyvalue.Map) []secretFile {
	var out []secretFile
	if m == nil {
		return nil
	}
	for _, k := range m.Keys() {
		if strings.HasSuffix(k, "_file") && k != "ca_file" {
			out = append(out, secretFile{section, k, pyvalue.Str(m.Value(k))})
		}
	}
	return out
}

// secretFiles checks that every secret file exists and is private; it never reads one.
func (c *checkup) secretFiles(inst *pyvalue.Map) {
	for _, f := range secretFilesOf(inst) {
		fi, err := os.Stat(expandUser(f.path, c.s.env.Getenv))
		switch {
		case err != nil:
			c.bad(fmt.Sprintf("%s: %s %s does not exist", f.section, safe(f.key), safe(f.path)),
				"create it (one line, the secret only) with mode 0600")
		case fi.Mode().Perm()&0o077 != 0 && c.s.env.GOOS != "windows":
			c.bad(fmt.Sprintf("%s: %s %s is readable by others", f.section, safe(f.key), safe(f.path)), "chmod 600 "+safe(f.path))
		default:
			c.ok(fmt.Sprintf("%s: %s is private", f.section, safe(f.key)))
		}
	}
}

// python checks what the jobs need: the product tree, an interpreter and, for a YAML config, PyYAML in it (the
// collectors and the runner are Python programs that read the instance).
func (c *checkup) python(ctx context.Context) {
	if c.s.env.Tree == "" {
		c.bad(fmt.Sprintf("the product tree (collectors, runner) was not found: %v", c.s.env.TreeErr),
			"install sp in <tree>/bin, or set SP_PY_HOME")
		return
	}
	py, err := c.s.env.Python()
	if err != nil {
		c.bad(fmt.Sprintf("no Python interpreter for the jobs: %v", err), "install python3 3.10+, or set SP_PYTHON")
		return
	}
	if !strings.HasSuffix(c.s.instancePath, ".yaml") && !strings.HasSuffix(c.s.instancePath, ".yml") {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	if rc, err := c.s.env.Probe(ctx, []string{py, "-c", "import yaml"}); err != nil || rc != 0 {
		c.bad("PyYAML is missing (needed for a YAML config)", "pip install -r deploy/requirements.lock, or use JSON")
	}
}
