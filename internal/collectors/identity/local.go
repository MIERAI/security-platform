package identity

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const maxStoreFile = 4 << 20 // a kubeconfig, a Docker config, a public key

// local reads the credential stores of this host (adapters/identity.py: local_credentials): names, kinds, scopes,
// groups, file ages and modes, certificate expiry. Secret values are parsed in memory and never kept.
type local struct {
	cfg  *pyvalue.Map
	home string
	excl []string
}

func newLocal(cfg *pyvalue.Map, home string) *local {
	l := &local{cfg: cfg, home: home}
	for _, x := range rundoc.Strings(cfg.Value("exclude")) {
		l.excl = append(l.excl, absPath(rundoc.ExpandUser(x, home)))
	}
	return l
}

func absPath(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	return a
}

func (l *local) expand(key string) []string {
	var out []string
	for _, p := range rundoc.Strings(l.cfg.Value(key)) {
		out = append(out, pyGlob(rundoc.ExpandUser(p, l.home))...)
	}
	return out
}

func (l *local) excluded(p string) bool {
	a := absPath(p)
	for _, x := range l.excl {
		if a == x || strings.HasPrefix(a, x+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func modeText(fi fs.FileInfo) string { return "0o" + strconv.FormatUint(uint64(fi.Mode().Perm()), 8) }

func mtime(fi fs.FileInfo) pyjson.Value { return iso(float64(fi.ModTime().Unix())) }

func (l *local) collect() *snapshot {
	s := &snapshot{}
	for _, p := range l.expand("kubeconfigs") {
		if !l.excluded(p) && !isDir(p) {
			l.kubeconfig(p, s)
		}
	}
	for _, d := range l.expand("ssh_dirs") {
		l.sshDir(d, s)
	}
	for _, p := range l.expand("docker_configs") {
		if !l.excluded(p) {
			l.docker(p, s)
		}
	}
	for _, p := range l.expand("token_files") {
		if l.excluded(p) || isDir(p) {
			continue
		}
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		s.credentials = append(s.credentials, object("store", "file", "id", "file:"+filepath.Base(p), "kind", "token_file",
			"location", p, "scopes", nil, "created_at", mtime(fi), "expires_at", nil, "last_used", nil,
			"mode", modeText(fi), "notes", "age = file mtime"))
	}
	return s
}

// errKindOf names a file error as Python's exception class.
func errKindOf(err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return "PermissionError"
	case errors.Is(err, fs.ErrNotExist):
		return "FileNotFoundError"
	case errors.Is(err, rundoc.ErrTooLarge):
		return "MemoryError"
	default:
		return "OSError"
	}
}

func (l *local) kubeconfig(p string, s *snapshot) {
	data, err := rundoc.ReadLimited(p, maxStoreFile)
	if err != nil {
		s.gap("credential-store:"+p, errKindOf(err))
		return
	}
	v, err := pyvalue.DecodeYAML(data)
	if err != nil {
		s.gap("credential-store:"+p, "YAMLError")
		return
	}
	kc := rundoc.Map(v)
	if kc == nil && pyvalue.Truthy(v) {
		s.gap("credential-store:"+p, "AttributeError")
		return
	}
	s.cover("credential-store:" + p)
	fi, err := os.Stat(p)
	if err != nil {
		return
	}
	for _, u := range rundoc.List(kc.Value("users")) {
		if c := kubeUser(p, fi, rundoc.Map(u)); c != nil {
			s.credentials = append(s.credentials, c)
		}
	}
}

// kubeUser is one kubeconfig user's credential: a client certificate, a static token, an exec plugin (or none).
func kubeUser(p string, fi fs.FileInfo, u *pyvalue.Map) *pyjson.Object {
	uu := rundoc.Map(u.Value("user"))
	c := object("store", "kubeconfig", "location", p, "scopes", nil, "created_at", mtime(fi), "last_used", nil,
		"mode", modeText(fi), "id", "kube:"+filepath.Base(p)+"/"+pyvalue.Str(u.Value("name")))
	switch {
	case pyvalue.Truthy(uu.Value("client-certificate-data")):
		exp, groups := certNotAfter(uu.Value("client-certificate-data"))
		c.Set("kind", "kube_client_cert")
		c.Set("expires_at", exp)
		c.Set("scopes", strList(groups))
		c.Set("notes", "groups = certificate O")
	case pyvalue.Truthy(uu.Value("token")) || pyvalue.Truthy(uu.Value("tokenFile")):
		c.Set("kind", "kube_token")
		c.Set("expires_at", nil)
		c.Set("notes", "static bearer token")
	case pyvalue.Truthy(uu.Value("exec")):
		cmd := pyvalue.Str(rundoc.Map(uu.Value("exec")).Value("command"))
		c.Set("kind", "kube_exec")
		c.Set("expires_at", nil)
		c.Set("notes", "exec plugin "+pathBase(cmd))
	default:
		return nil
	}
	return c
}

// pathBase is os.path.basename: the text after the last "/".
func pathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func (l *local) sshDir(d string, s *snapshot) {
	for _, pub := range pyGlob(joinPy(d, "*.pub")) {
		key := strings.TrimSuffix(pub, ".pub")
		fi, err := os.Stat(key)
		if err != nil || l.excluded(key) {
			continue
		}
		kt := "?"
		if data, err := rundoc.ReadLimited(pub, maxStoreFile); err == nil {
			if f := strings.Fields(string(data)); len(f) > 0 {
				kt = f[0]
			}
		}
		s.credentials = append(s.credentials, object("store", "ssh", "id", "ssh:"+filepath.Base(key), "kind", "ssh_key",
			"location", key, "scopes", strList([]string{kt}), "created_at", mtime(fi), "expires_at", nil,
			"last_used", nil, "mode", modeText(fi), "notes", "age = file mtime"))
	}
	s.cover("credential-store:" + d)
}

func (l *local) docker(p string, s *snapshot) {
	data, err := rundoc.ReadLimited(p, maxStoreFile)
	if err != nil {
		return
	}
	dc, err := pyjson.Decode(data)
	if err != nil {
		return // not JSON: skipped, as the Python adapter does
	}
	s.cover("credential-store:" + p)
	skip := map[string]bool{}
	for _, r := range rundoc.Strings(l.cfg.Value("exclude_registries")) {
		skip[r] = true
	}
	auths, _ := get(dc, "auths").(*pyjson.Object)
	if auths == nil {
		return
	}
	fi, err := os.Stat(p)
	if err != nil {
		return
	}
	hosts := auths.Keys()
	sort.Strings(hosts)
	for _, host := range hosts {
		if skip[host] {
			continue
		}
		a, _ := auths.Get(host)
		notes := "credsStore " + pyStr(get(dc, "credsStore"))
		if truthy(get(a, "auth")) {
			notes = "inline auth in file"
		}
		s.credentials = append(s.credentials, object("store", "docker", "id", "registry:"+host, "kind", "registry",
			"location", p, "scopes", nil, "created_at", mtime(fi), "expires_at", nil, "last_used", nil, "notes", notes))
	}
}
