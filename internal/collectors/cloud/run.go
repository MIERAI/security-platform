package cloud

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/MIERAI/security-platform/internal/cloud"
	"github.com/MIERAI/security-platform/internal/cloud/dyn"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
)

// Env is everything a collector run reads from its process.
type Env struct {
	Getenv     func(string) string
	Environ    []string
	Stderr     io.Writer
	Now        func() time.Time
	Executable string // sp itself: engines call back into it for credentials
	GOOS       string
	HTTP       *http.Client // nil: a default client per account
}

// ErrUsage marks a configuration error of the run as a whole (exit 2).
var ErrUsage = errors.New("configuration error")

// Collect is one run of the collector (collector protocol): it reads SP_INSTANCE, writes <name>.findings.json,
// <name>.prom and raw/<name>/ into SP_RUN_DIR. Gaps are inside the document; an error is a failed run.
func Collect(ctx context.Context, env Env) error {
	runDir, instPath := env.Getenv("SP_RUN_DIR"), env.Getenv("SP_INSTANCE")
	if instPath == "" {
		return fmt.Errorf("%w: SP_INSTANCE not set (path to the private instance config)", ErrUsage)
	}
	if runDir == "" {
		return fmt.Errorf("%w: SP_RUN_DIR not set", ErrUsage)
	}
	data, err := readLimited(cloud.ExpandUser(instPath, env.Getenv("HOME")), maxInstanceFile)
	if err != nil {
		return fmt.Errorf("%w: instance config unreadable: %w", ErrUsage, err)
	}
	cfg, err := parseInstance(data)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUsage, err)
	}
	if err := os.MkdirAll(runDir, 0o750); err != nil {
		return fmt.Errorf("create the run directory: %w", err)
	}
	c := newCollector(env, dyn.Or(env.Getenv("SP_COLLECTOR_NAME"), "cloud"))
	c.run(ctx, &cfg)
	return c.write(runDir) // the document, then the SDK's summary line on stderr
}

func newCollector(env Env, name string) *collector {
	now := env.Now
	if now == nil {
		now = time.Now
	}
	if env.Stderr == nil {
		env.Stderr = io.Discard
	}
	tmp := env.Getenv("TMPDIR")
	if tmp == "" {
		tmp = os.TempDir()
	}
	return &collector{
		deps:    cloud.Deps{Getenv: env.Getenv, Now: now, HTTP: env.HTTP, Executable: env.Executable, GOOS: env.GOOS},
		tmpBase: tmp, environ: env.Environ, stderr: env.Stderr, doc: rundoc.New(name, Version, env.Getenv("SP_INSTANCE_NAME"), now),
		pool: NewPool(), evidence: map[evKey]*evidence{}, stats: stats{engines: map[[2]string]int{}},
	}
}

func (c *collector) run(ctx context.Context, cfg *instanceConfig) {
	defaultRefuse := cloud.Account(cfg.cloud).Bool("refuse_over_privileged", true)
	for _, a := range dyn.List(cfg.cloud["accounts"]) {
		c.scanAccount(ctx, cloud.Account(dyn.Map(a)), cfg, defaultRefuse)
	}
	for _, imp := range dyn.List(cfg.cloud["imports"]) {
		c.runImport(cloud.Account(dyn.Map(imp)))
	}
	c.emit()
}

// runImport reads one export of a provider's own posture service.
func (c *collector) runImport(imp cloud.Account) {
	typ := dyn.Str(imp["type"])
	label := "cloud:import/" + pyStrOrNone(imp["type"])
	im, ok := importers()[typ]
	if !ok {
		c.doc.Gap(label, "unknown import type "+pyStrOrNone(imp["type"])+" ("+importerNames()+")", nil)
		return
	}
	file := ""
	if v, ok := imp["file"]; ok {
		file = pyStrOrNone(v)
	}
	path := cloud.ExpandUser(file, c.home())
	age, doc, err := readExport(path, c.deps.Now())
	if err != nil {
		c.doc.Gap(label, "export unreadable: "+err.Error(), nil)
		return
	}
	if age.Seconds() > float64(Seconds(imp["max_age"], 2*86400)) {
		maxAge := "2d"
		if v, ok := imp["max_age"]; ok {
			maxAge = pyStrOrNone(v)
		}
		c.doc.Gap(label, "export is "+strconv.FormatFloat(age.Hours()/24, 'f', 1, 64)+" days old (max_age "+maxAge+")", nil)
		return
	}
	c.addImport(typ, im.provider, im.parse(doc), imp.List("accounts"), age)
}

// addImport covers the export's accounts (the configured ones, else every account it names) and merges its
// verdicts on them.
func (c *collector) addImport(typ, provider string, results []Result, accounts []string, age time.Duration) {
	if len(accounts) == 0 {
		accounts = resultAccounts(results)
	}
	count := map[string]int{}
	for i := range results {
		count[results[i].Account]++
	}
	in := map[string]bool{}
	for _, a := range accounts {
		in[a] = true
		c.doc.OK("cloud:"+provider+"/"+a, "")
		ev := c.ev(provider, a)
		ev.imports = append(ev.imports, map[string]any{"type": typ, "age_hours": round1(age.Hours()), "results": count[a]})
	}
	if !c.doc.Tools.Has("import-" + typ) {
		c.doc.Tools.Set("import-"+typ, "export")
	}
	for i := range results {
		if in[results[i].Account] {
			c.pool.Add(provider, results[i].Account, &results[i])
		}
	}
}

func resultAccounts(results []Result) []string {
	set := map[string]bool{}
	for i := range results {
		if results[i].Account != "" {
			set[results[i].Account] = true
		}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

func round1(x float64) float64 { return math.RoundToEven(x*10) / 10 }

// importError names a read failure like the Python implementation (its exception type).
type importError string

func (e importError) Error() string { return string(e) }

func readExport(path string, now time.Time) (time.Duration, any, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, nil, importError(excName(err))
	}
	data, err := readLimited(path, maxImportFile)
	if err != nil {
		return 0, nil, importError(excName(err))
	}
	doc, err := dyn.Decode(data)
	if err != nil {
		return 0, nil, importError("JSONDecodeError")
	}
	return now.Sub(st.ModTime()), doc, nil
}

func excName(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "FileNotFoundError"
	case errors.Is(err, fs.ErrPermission):
		return "PermissionError"
	case errors.Is(err, errFileTooLarge):
		return "ValueError"
	default:
		return "OSError"
	}
}
