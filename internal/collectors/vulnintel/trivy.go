package vulnintel

import (
	"context"
	"crypto/sha1" // #nosec G505 -- the SBOM cache key, as the Python collector names it; not a security use
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

const (
	trivyTimeout   = 900 * time.Second
	trivyDBTimeout = 1800 * time.Second
	maxTrivyOutput = 512 << 20
	maxTokenFile   = 64 << 10
)

// trivy runs the external engine exactly as the Python collector does (argument vector, no shell): global
// options, then the command, `--cache-backend memory` for image / sbom / fs, then the arguments. A registry
// credential travels only in the child's environment (TRIVY_USERNAME / TRIVY_PASSWORD).
func (c *collector) trivy(ctx context.Context, args []string, extra map[string]string, timeout time.Duration) rundoc.Result {
	argv := []string{"trivy", "--cache-dir", filepath.Join(c.dataDir, "cache", "trivy"), "--quiet", args[0]}
	if args[0] == "image" || args[0] == "sbom" || args[0] == "fs" {
		argv = append(argv, "--cache-backend", "memory")
	}
	argv = append(argv, args[1:]...)
	env := c.environ
	if len(extra) > 0 {
		env = rundoc.WithEnv(env, extra)
	}
	return rundoc.Exec(ctx, &rundoc.Cmd{Argv: argv, Env: env, Timeout: timeout, MaxOut: maxTrivyOutput})
}

// registryCred is one registry_auth entry that could be read.
type registryCred struct{ host, user, token string }

// registryEnv is the credential for an image reference: the first configured host it is under, else the
// SP_REGISTRY_* fallback (default host ghcr.io).
func (c *collector) registryEnv(ref string) map[string]string {
	for _, r := range c.creds {
		if strings.HasPrefix(ref, r.host+"/") {
			return map[string]string{"TRIVY_USERNAME": r.user, "TRIVY_PASSWORD": r.token}
		}
	}
	tok := c.getenv("SP_REGISTRY_TOKEN")
	host := c.getenv("SP_REGISTRY_HOST")
	if host == "" {
		host = "ghcr.io"
	}
	if tok != "" && strings.HasPrefix(ref, host) {
		return map[string]string{"TRIVY_USERNAME": c.getenv("SP_REGISTRY_USER"), "TRIVY_PASSWORD": tok}
	}
	return nil
}

// readSecretFile is adapters/sinks.read_secret_file: a token file readable by group or others is refused.
func readSecretFile(p string) (token, failure string) {
	st, err := os.Stat(p)
	switch {
	case err != nil:
		return "", excName(err)
	case st.Mode().Perm()&0o077 != 0:
		return "", "PermissionError"
	}
	data, err := rundoc.ReadLimited(p, maxTokenFile)
	if err != nil {
		return "", excName(err)
	}
	return strings.TrimSpace(string(data)), ""
}

// excName is the Python exception class a file error would be.
func excName(err error) string {
	switch {
	case os.IsNotExist(err):
		return "FileNotFoundError"
	case os.IsPermission(err):
		return "PermissionError"
	case strings.Contains(err.Error(), "is a directory"):
		return "IsADirectoryError"
	default:
		return "OSError"
	}
}

// scanned is one image's scan: its report, or why there is none; sbom is the SBOM's path relative to the data
// directory.
type scanned struct {
	report *pyjson.Object
	note   string
}

// scanRef is the reference trivy scans: the digest actually running when the inventory knows it.
func scanRef(item *pyjson.Object) string {
	ref := sget(item, "image")
	id := sget(item, "image_id")
	if !strings.Contains(id, "@sha256:") {
		return ref
	}
	parts := strings.Split(id, "://")
	pinned := parts[len(parts)-1]
	if repo, _, _ := strings.Cut(pinned, "@"); !strings.Contains(repo, "/") {
		return ref
	}
	return pinned
}

// scanImage is scan_image(): an SBOM per image (cached by reference, refreshed after sbom_max_age_days), then
// trivy's match of the SBOM.
func (c *collector) scanImage(ctx context.Context, item *pyjson.Object) scanned {
	ref, refScan := sget(item, "image"), scanRef(item)
	sum := sha1.Sum([]byte(refScan)) // #nosec G401 -- see the import
	sbom := filepath.Join(c.dataDir, "sbom", hex.EncodeToString(sum[:])[:16]+".cdx.json")
	if err := rundoc.MkdirPrivate(filepath.Dir(sbom)); err != nil {
		return scanned{note: "sbom: " + err.Error()}
	}
	env := c.registryEnv(ref)
	fi, statErr := os.Stat(sbom)
	exists := statErr == nil
	stale := exists && c.now().Sub(fi.ModTime()).Seconds() > c.sbomMaxAgeDays*86400
	if !exists || stale {
		r := c.trivy(ctx, []string{"image", "--image-src", "remote", "--format", "cyclonedx", "--skip-db-update",
			"--output", sbom + ".tmp", refScan}, env, trivyTimeout)
		switch {
		case r.RC != 0 && !stale:
			return scanned{note: "sbom rc=" + strconv.Itoa(r.RC) + unauthorizedHint(env, r.Stderr) + ": " + tail(strip(r.Stderr), 120)}
		case r.RC != 0:
			_ = os.Remove(sbom + ".tmp") // #nosec G104 -- a stale SBOM of the same digest is matched instead
		default:
			if err := os.Rename(sbom+".tmp", sbom); err != nil {
				return scanned{note: "sbom: " + err.Error()}
			}
		}
	}
	rep, note := c.match(ctx, sbom)
	if rep == nil {
		return scanned{note: note}
	}
	rel, err := filepath.Rel(c.dataDir, sbom)
	if err != nil {
		rel = sbom
	}
	return scanned{report: rep, note: filepath.ToSlash(rel)}
}

func unauthorizedHint(env map[string]string, stderr string) string {
	if len(env) == 0 && (strings.Contains(stderr, "UNAUTHORIZED") || strings.Contains(stderr, "unauthorized") ||
		strings.Contains(stderr, "DENIED")) {
		return " (private image: no registry credential configured - coverage gap)"
	}
	return ""
}

// match is `trivy sbom` of one SBOM file: the report, or the gap reason.
func (c *collector) match(ctx context.Context, sbom string) (*pyjson.Object, string) {
	r := c.trivy(ctx, []string{"sbom", "--format", "json", "--skip-db-update", "--scanners", "vuln", sbom}, nil, trivyTimeout)
	if r.RC != 0 {
		return nil, "match rc=" + strconv.Itoa(r.RC) + ": " + tail(strip(r.Stderr), 160)
	}
	return parseReport(r.Stdout)
}

// parseReport reads trivy's JSON report.
func parseReport(out string) (*pyjson.Object, string) {
	v, err := pyjson.Decode([]byte(out))
	if o := obj(v); err == nil && o != nil {
		return o, ""
	}
	return nil, "match: trivy printed no JSON report"
}

// scanRepo is a local checkout: `trivy fs` (JSON report).
func (c *collector) scanRepo(ctx context.Context, path string) (*pyjson.Object, string) {
	r := c.trivy(ctx, []string{"fs", "--format", "json", "--skip-db-update", "--scanners", "vuln",
		rundoc.ExpandUser(path, c.home)}, nil, trivyTimeout)
	if r.RC != 0 {
		return nil, tail(strip(r.Stderr), 160)
	}
	rep, note := parseReport(r.Stdout)
	return rep, note
}

// scanImages runs scanImage on every image, four at a time; results keep the images' order.
func (c *collector) scanImages(ctx context.Context, items []*pyjson.Object) []scanned {
	out := make([]scanned, len(items))
	sem := make(chan struct{}, 4)
	done := make(chan struct{})
	for i, it := range items {
		go func() {
			sem <- struct{}{}
			out[i] = c.scanImage(ctx, it)
			<-sem
			done <- struct{}{}
		}()
	}
	for range items {
		<-done
	}
	return out
}

// trivyVersion records the engine's and its database's versions, and the database's age.
func (c *collector) trivyVersion(ctx context.Context) {
	r := c.trivy(ctx, []string{"version", "--format", "json"}, nil, trivyTimeout)
	if r.RC != 0 {
		return
	}
	v, err := pyjson.Decode([]byte(r.Stdout))
	tv := obj(v)
	if err != nil || tv == nil {
		return
	}
	db := oget(tv, "VulnerabilityDB")
	c.doc.Tools.Set("trivy", getOr(tv, "Version", ""))
	c.doc.Tools.Set("trivy-db", getOr(db, "UpdatedAt", ""))
	at := sget(db, "UpdatedAt")
	if at == "" {
		return
	}
	t, err := time.Parse("2006-01-02T15:04:05", cut(at, 19))
	if err != nil {
		return
	}
	c.doc.Metric("security_intel_feed_age_seconds", float64(int64(c.epoch()-float64(t.Unix()))),
		"Age of the cached intel feed", map[string]string{"feed": "trivy-db"})
}
