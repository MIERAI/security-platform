// Package vulnintel is the Go implementation of the `vuln-intel` collector (collectors/vuln-intel): `sp vuln-intel
// collect`. SBOM inventory x vulnerability intelligence -> prioritised findings, READ-ONLY: images and local
// repositories through trivy (an external engine), hosts through their package / platform inventories, CISA KEV,
// EPSS, OSV, Android bulletins, Apple security releases and MSRC as feeds. Its documents are byte for byte those
// of the Python collector on the same inputs; the feed fetch is the target behaviour of VULN-D1..D3.
package vulnintel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Version is the collector's version (collectors/vuln-intel/VERSION).
const Version = "0.5.0"

// Main is `sp vuln-intel ...`.
func Main(ctx context.Context, args []string, env *rundoc.Env, stdout io.Writer) int {
	return rundoc.Main(ctx, &rundoc.Collector{Name: "vuln-intel", Version: Version, Collect: collect}, args, env, stdout)
}

// collector is one run.
type collector struct {
	doc                       *rundoc.Document
	cfg                       *pyvalue.Map
	runDir, dataDir, inputDir string
	home                      string
	appleDir                  string
	environ                   []string
	getenv                    func(string) string
	now                       func() time.Time
	stderr                    io.Writer
	fetch                     *fetcher
	creds                     []registryCred
	sbomMaxAgeDays            float64
	nowEpoch                  float64
	in                        intel
	tally                     tally
	evidence, high            *pyjson.Object
	unmatched                 map[string]int
	rawErr                    error
}

func (c *collector) epoch() float64 { return float64(c.now().UnixNano()) / 1e9 }

func itoa(n int) string { return strconv.Itoa(n) }

func collect(ctx context.Context, run *rundoc.Run, env *rundoc.Env) error {
	cfg := rundoc.Map(run.Instance.Value("intel"))
	if err := refuse(cfg); err != nil {
		return err
	}
	data := run.Data
	if data == "" {
		data = "."
	}
	input := run.Input
	if input == "" {
		input = run.Dir
	}
	c := &collector{doc: run.Doc, cfg: cfg, runDir: run.Dir, dataDir: data, inputDir: input, home: run.Home,
		appleDir: data + "/cache/feeds/apple", environ: env.Environ, getenv: env.Getenv, now: env.Clock(),
		stderr: env.Errout(), sbomMaxAgeDays: rundoc.Float(cfg.Value("sbom_max_age_days"), 30),
		in: intel{kev: &kevIndex{byCVE: map[string]*kevEntry{}}}, evidence: pyjson.NewObject(), high: pyjson.NewObject(), unmatched: map[string]int{}}
	c.fetch = newFetcher(env.HTTP, c.now)
	return c.run(ctx)
}

// refuse stops a run whose configuration needs what only the Python collector implements.
func refuse(cfg *pyvalue.Map) error {
	for _, f := range rundoc.List(cfg.Value("feeds")) {
		if rundoc.Str(rundoc.Map(f).Value("type")) == "vendor-advisories" {
			return fmt.Errorf("%w: feed vendor-advisories (unstructured vendor pages, advisor, human review state) is "+
				"served by the Python collector (collectors/vuln-intel/collector.py); keep that collector for this instance",
				rundoc.ErrUsage)
		}
	}
	if len(rundoc.List(cfg.Value("code_repos"))) > 0 {
		return fmt.Errorf("%w: intel.code_repos (code-host listing and clones) is served by the Python collector "+
			"(collectors/vuln-intel/collector.py); keep that collector for this instance", rundoc.ErrUsage)
	}
	return nil
}

func (c *collector) run(ctx context.Context) error {
	if err := c.registryAuth(); err != nil {
		return err
	}
	if pyvalue.Truthy(c.cfg.Value("update_db")) {
		r := c.trivy(ctx, []string{"image", "--download-db-only"}, nil, trivyDBTimeout)
		if r.RC == 0 {
			c.doc.OK("feed:trivy-db", "")
		} else {
			c.doc.Gap("feed:trivy-db", "trivy DB update rc="+itoa(r.RC)+": "+tail(strip(r.Stderr), 160), nil)
		}
	}
	c.loadFeeds(ctx)
	c.trivyVersion(ctx)
	inv, err := readInventories(c.inputDir)
	if err != nil {
		return err
	}
	imgs := c.images(ctx, inv)
	repos := c.scanRepos(ctx)
	c.nowEpoch = c.epoch()
	for _, ref := range imgs.order {
		if im := imgs.byRef[ref]; nonEmpty(im.report) {
			c.handle("image:"+ref, im.meta(), im.report)
		}
	}
	for _, r := range repos {
		if nonEmpty(r.report) {
			c.handle("repo:"+r.name, &matchMeta{exposed: false, prod: true}, r.report)
		}
	}
	c.doc.Metric("security_sbom_repos", 0, "Code-host repositories with a dependency SBOM matched", nil)
	hostSBOMs := c.hosts(ctx, inv)
	c.osvMatches(append(imgs.sboms(), hostSBOMs...))
	return c.finish(imgs)
}

// registryAuth reads the read-only registry credentials (never logged; a file readable by others is refused).
func (c *collector) registryAuth() error {
	for _, x := range rundoc.List(c.cfg.Value("registry_auth")) {
		ra := rundoc.Map(x)
		host, file := rundoc.Str(ra.Value("host")), rundoc.Str(ra.Value("token_file"))
		if host == "" || file == "" {
			return fmt.Errorf("%w: intel.registry_auth entries need host and token_file", rundoc.ErrUsage)
		}
		tok, exc := readSecretFile(rundoc.ExpandUser(file, c.home))
		if exc != "" {
			c.doc.Gap("registry-auth:"+host, "read-only registry credential unavailable ("+exc+"): private images not "+
				"refreshed - create a read-only token file (see docs/runner.md)", nil)
			continue
		}
		c.creds = append(c.creds, registryCred{host: host, user: rundoc.Str(ra.Value("username")), token: tok})
		c.doc.OK("registry-auth:"+host, "")
	}
	return nil
}

func (c *collector) loadFeeds(ctx context.Context) {
	for _, x := range rundoc.List(c.cfg.Value("feeds")) {
		fc := &feedConfig{m: rundoc.Map(x), dataDir: c.dataDir}
		fc.typ = rundoc.Str(fc.m.Value("type"))
		asset := "feed:" + fc.typ
		res, err := c.loadFeed(ctx, fc, &c.in)
		switch {
		case err != nil:
			c.doc.Gap(asset, err.Error(), nil)
			continue
		case res.warn != "":
			c.doc.Gap(asset, res.warn, nil)
		default:
			c.doc.OK(asset, "")
		}
		c.doc.Metric("security_intel_feed_age_seconds", float64(int64(c.epoch()-res.checkedAt)),
			"Age of the cached intel feed", map[string]string{"feed": fc.typ})
	}
}

var errInventory = errors.New("inventory unreadable")

// partialNote prints that retirement is off for this run (stderr, like the Python collector).
func (c *collector) partialNote(partial []string) {
	_, _ = fmt.Fprintf(c.stderr, "[vuln-intel] image inventory partial (%s): findings of images no longer listed "+
		"stay as they are\n", cut(strings.Join(partial, "; "), 300)) // informational
}
