package identity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const (
	toolTimeout  = 30 * time.Second
	maxTokenFile = 64 << 10
)

// errNotPrivate is returned for a secret file readable by group or others.
var errNotPrivate = errors.New("must be mode 0600 (refused)")

var keychainRE = regexp.MustCompile(`"(cdat|mdat)"<timedate>=\S+\s+"(\d{14})Z`)

// runtime is what the providers share: the run's environment, HTTP client and clock.
type runtime struct {
	env    *rundoc.Env
	client *http.Client
	home   string
	now    func() time.Time
}

// token returns an account's code-host token and its metadata record. Sources, in order: `token_file` (a 0600
// file), `token_env` (the name of an environment variable), else the GitHub CLI's keyring for gh_user
// (`gh auth token --user <login>`). The value is only ever put into the Authorization header.
func (r *runtime) token(ctx context.Context, am *pyvalue.Map, user string) (string, *pyjson.Object, error) {
	cred := object("store", "gh-keyring", "id", "gh:"+user, "kind", nil, "location", "keyring", "scopes", nil,
		"created_at", nil, "updated_at", nil, "expires_at", nil, "last_used", nil,
		"notes", "age = keyring item creation (upper bound)")
	switch {
	case am.Has("token_file"):
		p := rundoc.ExpandUser(rundoc.Str(am.Value("token_file")), r.home)
		tok, err := readSecretFile(p)
		if err != nil {
			return "", nil, fmt.Errorf("token_file %s: %w", filepath.Base(p), err)
		}
		cred.Set("store", "file")
		cred.Set("location", p)
		cred.Set("created_at", fileMeta(p))
		cred.Set("notes", "age = file mtime")
		return tok, cred, nil
	case am.Has("token_env"):
		name := rundoc.Str(am.Value("token_env"))
		tok := strings.TrimSpace(r.env.Getenv(name))
		if tok == "" {
			return "", nil, fmt.Errorf("token_env %s is not set", name)
		}
		cred.Set("store", "env")
		cred.Set("location", "env:"+name)
		cred.Set("notes", "age unknown (environment)")
		return tok, cred, nil
	}
	if strings.HasPrefix(user, "-") {
		return "", nil, fmt.Errorf("gh_user %q: a login cannot start with '-'", user)
	}
	res := rundoc.Exec(ctx, &rundoc.Cmd{Argv: []string{"gh", "auth", "token", "--user", user}, Env: r.env.Environ,
		Timeout: toolTimeout, MaxOut: maxTokenFile})
	if res.RC == rundoc.RCNotFound {
		return "", nil, providerError("FileNotFoundError: [Errno 2] No such file or directory: 'gh'")
	}
	meta := r.keychain(ctx, "gh:github.com", user)
	cred.Set("created_at", meta["created_at"])
	cred.Set("updated_at", meta["updated_at"])
	return strings.TrimSpace(res.Stdout), cred, nil
}

// keychain reads the macOS keychain item's dates (attributes only: `security` without -g/-w never prints a secret).
func (r *runtime) keychain(ctx context.Context, service, account string) map[string]pyjson.Value {
	out := map[string]pyjson.Value{"created_at": nil, "updated_at": nil}
	res := rundoc.Exec(ctx, &rundoc.Cmd{Argv: []string{"security", "find-generic-password", "-s", service, "-a", account},
		Env: r.env.Environ, Timeout: 10 * time.Second, MaxOut: 1 << 20})
	for _, m := range keychainRE.FindAllStringSubmatch(res.Stdout, -1) {
		key := map[string]string{"cdat": "created_at", "mdat": "updated_at"}[m[1]]
		if out[key] != nil {
			continue // the first match wins, as re.search
		}
		v := m[2]
		out[key] = v[:4] + "-" + v[4:6] + "-" + v[6:8] + "T" + v[8:10] + ":" + v[10:12] + ":" + v[12:14] + "Z"
	}
	return out
}

// readSecretFile reads a secret file that only its owner may read (the content is returned stripped).
func readSecretFile(p string) (string, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return "", fmt.Errorf("%w", errors.Unwrap(err))
	}
	if fi.Mode().Perm()&0o077 != 0 && !windowsPerms() {
		return "", errNotPrivate
	}
	data, err := rundoc.ReadLimited(p, maxTokenFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
