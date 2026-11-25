//go:build unix

package runner

import (
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// allowedEnv are the variables of the runner's own environment that every child process gets (contract §4,
// "Environment"): what programs need to run at all (paths, locale, time zone, temporary directory, proxies and
// CA bundles, the in-cluster API address, the product's own SP_* settings). Everything else, in particular
// ambient credentials (cloud keys, tokens), reaches a job only when the instance lists it in
// runner.env_passthrough. A fresh map on every call.
func allowedEnv() map[string]bool {
	m := map[string]bool{}
	for _, k := range []string{"PATH", "HOME", "USER", "LOGNAME", "LANG", "LANGUAGE", "TZ", "TMPDIR", "TERM",
		"NO_COLOR", "SHELL", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
		"SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "KUBERNETES_SERVICE_HOST",
		"KUBERNETES_SERVICE_PORT", "KUBECONFIG", "PYTHONNOUSERSITE", "PIP_NO_INDEX", "UV_OFFLINE", "SSH_AUTH_SOCK",
		"XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR"} {
		m[k] = true
	}
	if runtime.GOOS == "android" { // Termux: its prefix and the exec helper every script with a shebang needs
		for _, k := range []string{"PREFIX", "ANDROID_ROOT", "ANDROID_DATA", "ANDROID_RUNTIME_ROOT", "LD_PRELOAD",
			"TERMUX_VERSION"} {
			m[k] = true
		}
	}
	return m
}

// credentialName matches variable names that usually hold credentials; only their names are ever logged.
var credentialName = regexp.MustCompile(`(?i)(TOKEN|SECRET|PASSW|CREDENTIAL|_KEY|APIKEY|^AWS_|^AZURE_|^GOOGLE_|^GH_|^GITHUB_|^CLOUDSDK_)`)

// envFilter decides which of the runner's variables children get.
type envFilter struct {
	allow map[string]bool
}

func newEnvFilter(passthrough []string) envFilter {
	a := allowedEnv()
	for _, k := range passthrough {
		a[k] = true
	}
	return envFilter{allow: a}
}

func (f envFilter) passes(name string) bool {
	return f.allow[name] || strings.HasPrefix(name, "LC_") || strings.HasPrefix(name, "SP_")
}

// base returns the allowed part of environ as a map.
func (f envFilter) base(environ []string) map[string]string {
	out := map[string]string{}
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if ok && k != "" && f.passes(k) {
			out[k] = v
		}
	}
	return out
}

// withheldCredentials lists the names (never the values) of credential-like variables of environ that children
// do not get, sorted.
func (f envFilter) withheldCredentials(environ []string) []string {
	var names []string
	for _, kv := range environ {
		k, _, ok := strings.Cut(kv, "=")
		if ok && !f.passes(k) && credentialName.MatchString(k) {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	return names
}

// list turns an environment map into a sorted KEY=VALUE slice.
func envList(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}
