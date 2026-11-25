package remediation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/ledger/fileio"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// GHFunc runs `gh api <args>` with stdin (nil: none) and extra environment, and returns its standard output.
type GHFunc func(ctx context.Context, args []string, stdin []byte, extraEnv []string) ([]byte, error)

// ghTimeout is the limit of one gh call (as the reference).
const ghTimeout = 60 * time.Second

// ErrNotPrivate is returned when the github-issues tracker points at a repository that is not private.
var ErrNotPrivate = errors.New("tracker github-issues: the repository is not private; vulnerability details never go to a public repository")

// ExecGH returns a GHFunc that runs the `gh` program found on PATH (a relative PATH entry is refused by
// os/exec) with environ plus the extra variables.
func ExecGH(environ []string) GHFunc {
	return func(ctx context.Context, args []string, stdin []byte, extraEnv []string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, ghTimeout)
		defer cancel()
		argv := append([]string{"api"}, args...)
		if stdin != nil {
			argv = append(argv, "--input", "-")
		}
		cmd := exec.CommandContext(ctx, "gh", argv...) // #nosec G204 -- fixed program, argument vector (no shell)
		cmd.Env = append(append([]string(nil), environ...), extraEnv...)
		if stdin != nil {
			cmd.Stdin = bytes.NewReader(stdin)
		}
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			tail := strings.TrimSpace(stderr.String())
			if len(tail) > 160 {
				tail = tail[len(tail)-160:]
			}
			return nil, fmt.Errorf("gh api %s: %w: %s", args[0], err, tail)
		}
		return stdout.Bytes(), nil
	}
}

// githubTracker is the github-issues adapter: one issue per item in a PRIVATE repository.
type githubTracker struct {
	cfg     *pyjson.Object
	repo    string
	label   string
	mapPath string
	gh      GHFunc
	env     []string
	n       syncCounts
}

func newGitHubTracker(cfg *pyjson.Object, data string, gh GHFunc) (*githubTracker, error) {
	repo := cfg.Str("repo")
	if repo == "" || strings.HasPrefix(repo, "-") {
		return nil, fmt.Errorf("%w: tracker github-issues needs repo: owner/name", ErrConfig)
	}
	label := "security-platform"
	if cfg.Has("label") {
		label = cfg.Str("label")
	}
	g := &githubTracker{cfg: cfg, repo: repo, label: label, gh: gh,
		mapPath: filepath.Join(data, "tracker", "github-issues.json")}
	if u := cfg.Str("gh_user"); u != "" {
		g.env = []string{"GH_USER=" + u}
	}
	return g, nil
}

func (g *githubTracker) call(ctx context.Context, args []string, payload *pyjson.Object) (*pyjson.Object, error) {
	var stdin []byte
	if payload != nil {
		var err error
		if stdin, err = pyjson.Marshal(payload, pyjson.Compact()); err != nil {
			return nil, fmt.Errorf("encode gh payload: %w", err)
		}
	}
	out, err := g.gh(ctx, args, stdin, g.env)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return pyjson.NewObject(), nil
	}
	v, err := pyjson.Decode(out)
	if err != nil {
		return nil, fmt.Errorf("gh api %s: %w", args[0], err)
	}
	o, _ := v.(*pyjson.Object) // a non-object answer carries nothing we use
	if o == nil {
		o = pyjson.NewObject()
	}
	return o, nil
}

func (g *githubTracker) sync(ctx context.Context, items *pyjson.Object) (string, error) {
	if !g.cfg.Truthy("enabled") {
		return "{'created': 0, 'updated': 0, 'closed': 0, 'skipped': 'github-issues tracker not enabled'}", nil
	}
	repo, err := g.call(ctx, []string{"repos/" + g.repo}, nil)
	if err != nil {
		return "", err
	}
	if v, _ := repo.Get("private"); v != true {
		return "", fmt.Errorf("%w (%s)", ErrNotPrivate, g.repo)
	}
	m, err := g.loadMap()
	if err != nil {
		return "", err
	}
	ids := items.Keys()
	sort.Strings(ids)
	for _, id := range ids {
		if it := items.Obj(id); it != nil {
			if err := g.syncItem(ctx, m, it); err != nil {
				return "", err
			}
		}
	}
	return g.n.String(), nil
}

func (g *githubTracker) loadMap() (*pyjson.Object, error) {
	data, err := os.ReadFile(g.mapPath)
	if errors.Is(err, fs.ErrNotExist) {
		return pyjson.NewObject(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", g.mapPath, err)
	}
	v, err := pyjson.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", g.mapPath, err)
	}
	o, ok := v.(*pyjson.Object)
	if !ok {
		return nil, fmt.Errorf("%s: top level is not an object", g.mapPath)
	}
	return o, nil
}

// syncItem creates, updates or closes the issue of one item, then saves the map (a failure later loses
// nothing already done).
func (g *githubTracker) syncItem(ctx context.Context, m, it *pyjson.Object) error {
	id := str(it, "id")
	want := "open"
	if closed(str(it, "status")) {
		want = "closed"
	}
	payload := pyjson.ObjectOf("title", itemTitle(it), "body", itemBody(it))
	sum, err := pyjson.Marshal([]pyjson.Value{payload, want}, pyjson.Compact())
	if err != nil {
		return fmt.Errorf("hash item %s: %w", id, err)
	}
	h := sha256.Sum256(sum)
	hash := hex.EncodeToString(h[:])
	rec := m.Obj(id)
	switch {
	case rec == nil && want == "closed":
	case rec == nil:
		if err := g.create(ctx, m, id, issue{payload, hash}); err != nil {
			return err
		}
	case rec.Str("hash") != hash:
		if err := g.patch(ctx, rec, it, want); err != nil {
			return err
		}
		rec.Set("hash", hash)
		rec.Set("state", want)
	}
	return g.saveMap(m)
}

// issue is the content of an item's issue and its hash.
type issue struct {
	payload *pyjson.Object
	hash    string
}

func (g *githubTracker) create(ctx context.Context, m *pyjson.Object, id string, is issue) error {
	body := pyjson.ObjectOf("title", str(is.payload, "title"), "body", str(is.payload, "body"), "labels", []pyjson.Value{g.label})
	r, err := g.call(ctx, []string{"repos/" + g.repo + "/issues", "-X", "POST"}, body)
	if err != nil {
		return err
	}
	num, _ := r.Get("number")
	m.Set(id, pyjson.ObjectOf("number", num, "hash", is.hash))
	g.n.created++
	return nil
}

func (g *githubTracker) patch(ctx context.Context, rec, it *pyjson.Object, want string) error {
	body := pyjson.ObjectOf("title", itemTitle(it), "body", itemBody(it), "state", want)
	if want == "closed" {
		reason := "not_planned"
		if str(it, "status") == "fixed" {
			reason = "completed"
		}
		body.Set("state_reason", reason)
	}
	num, _ := rec.Get("number")
	if _, err := g.call(ctx, []string{"repos/" + g.repo + "/issues/" + pyjson.Str(num), "-X", "PATCH"}, body); err != nil {
		return err
	}
	state := "open"
	if rec.Has("state") {
		state = rec.Str("state")
	}
	if want == "closed" && state == "open" {
		g.n.closed++
	} else {
		g.n.updated++
	}
	return nil
}

func (g *githubTracker) saveMap(m *pyjson.Object) error {
	data, err := pyjson.Marshal(m, pyjson.Options{Indent: 1, SortKeys: true, EnsureASCII: true})
	if err != nil {
		return fmt.Errorf("encode %s: %w", g.mapPath, err)
	}
	return fileio.Write(g.mapPath, data)
}

// syncTracker runs the configured adapter (default files) and returns its result for the summary line.
func syncTracker(ctx context.Context, opt Options, items *pyjson.Object) (string, error) {
	var tcfg *pyjson.Object
	if opt.Config != nil {
		tcfg = opt.Config.Obj("tracker")
	}
	typ := "files"
	if tcfg != nil && tcfg.Has("type") {
		typ = tcfg.Str("type")
	}
	switch typ {
	case "files":
		n, err := syncFiles(filepath.Join(opt.Data, "tracker"), items)
		return n.String(), err
	case "github-issues":
		if opt.NoExternalSync {
			return "{'skipped': 'external tracker not synced (--no-external-sync)'}", nil
		}
		g, err := newGitHubTracker(tcfg, opt.Data, opt.GH)
		if err != nil {
			return "", err
		}
		return g.sync(ctx, items)
	case "jira", "linear":
		return "", fmt.Errorf("%w: tracker %q is a documented future adapter", ErrConfig, typ)
	default:
		return "", fmt.Errorf("%w: unknown tracker type %q", ErrConfig, typ)
	}
}
