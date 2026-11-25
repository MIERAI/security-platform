package cloud

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestNewRefusals(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		cfg  Account
		want string
	}{
		{"unknown provider", Account{"provider": "oracle"}, "provider 'oracle' unknown (aws, gcp, azure)"},
		{"no provider", Account{}, "provider None unknown (aws, gcp, azure)"},
		{"long-lived keys", Account{"provider": "aws", "account_id": "1", "Secret_Access_Key": "x", "access_key_id": "y"},
			"long-lived credentials are not accepted (Secret_Access_Key, access_key_id): use federation/short-lived roles"},
		{"missing id", Account{"provider": "gcp"}, "gcp: `project_id` missing"},
		{"gcp source", Account{"provider": "gcp", "project_id": "p", "source": "key"}, "gcp: source 'key' unknown (workload_identity, adc)"},
		{"gcp provider missing", Account{"provider": "gcp", "project_id": "p", "service_account": "a"}, "gcp: workload_identity_provider missing"},
		{"gcp engine auth", Account{"provider": "gcp", "project_id": "p", "service_account": "a", "source": "adc", "engine_auth": "x"},
			"gcp: engine_auth 'x' unknown (access_token, impersonate)"},
		{"azure tenant", Account{"provider": "azure", "subscription_id": "s"}, "azure: tenant_id missing"},
		{"aws mode", Account{"provider": "aws", "account_id": "1", "mode": "keys"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(tc.cfg, testDeps(nil))
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || Reason(err) != tc.want {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
		})
	}
}

func TestAWSUnknownModeIsAReason(t *testing.T) {
	t.Parallel()
	p, err := New(Account{"provider": "aws", "account_id": "1", "mode": "keys"}, testDeps(nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Identity(context.Background()); err == nil || !strings.Contains(Reason(err), "aws: mode 'keys' unknown (web_identity, profile)") {
		t.Fatalf("got %v", err)
	}
}

func TestCleanEnv(t *testing.T) {
	t.Parallel()
	got := CleanEnv([]string{"PATH=/bin", "AWS_ACCESS_KEY_ID=admin", "AZURE_CLIENT_SECRET=s", "GOOGLE_APPLICATION_CREDENTIALS=/k", "X=a=b"})
	if !reflect.DeepEqual(got, map[string]string{"PATH": "/bin", "X": "a=b"}) {
		t.Fatalf("got %v", got)
	}
}

type tokenCase struct {
	name      string
	src       map[string]any
	want, err string
}

func tokenCases(dir, file string) []tokenCase {
	cases := []tokenCase{
		{"file", map[string]any{"type": "file", "path": file}, "tok-from-file", ""},
		{"file default type, home", map[string]any{"path": "~/t"}, "tok-from-file", ""},
		{"file missing", map[string]any{"path": filepath.Join(dir, "absent")}, "", "identity token unavailable: FileNotFoundError"},
		{"file without path", map[string]any{"type": "file"}, "", "identity token unavailable: KeyError"},
		{"env", map[string]any{"type": "env", "name": "TOKEN"}, "tok-from-env", ""},
		{"env empty", map[string]any{"type": "env", "name": "NONE"}, "", "identity token env NONE empty"},
		{"unknown type", map[string]any{"type": "vault"}, "", "identity_token type 'vault' unknown (file, command, env)"},
		{"not configured", nil, "", "identity_token not configured"},
	}
	if runtime.GOOS == "windows" { // the commands below are POSIX tools
		return cases
	}
	return append(cases,
		tokenCase{"command", map[string]any{"type": "command", "argv": "echo ' tok-from-cmd'"}, "tok-from-cmd", ""},
		tokenCase{"command fails", map[string]any{"type": "command", "argv": []any{"false"}}, "", "identity token command failed (rc=1)"},
		tokenCase{"command missing", map[string]any{"type": "command", "argv": []any{filepath.Join(dir, "nope")}}, "",
			"identity token unavailable: FileNotFoundError"})
}

func TestReadIdentityToken(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := filepath.Join(dir, "t")
	if err := os.WriteFile(file, []byte("  tok-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deps := testDeps(map[string]string{"TOKEN": " tok-from-env ", "HOME": dir})
	for _, tc := range tokenCases(dir, file) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ReadIdentityToken(context.Background(), tc.src, deps)
			switch {
			case tc.err != "" && (err == nil || Reason(err) != tc.err):
				t.Fatalf("got %q %v, want error %s", got, err, tc.err)
			case tc.err == "" && (err != nil || got != tc.want):
				t.Fatalf("got %q %v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestPrecheckToken(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	tests := []struct {
		name, token, aud, want string
	}{
		{"valid, audience list", unsignedJWT(map[string]any{"exp": now.Unix() + 600, "aud": []string{"a", "b"}}), "b", ""},
		{"no exp", unsignedJWT(map[string]any{"aud": "a"}), "a", ""},
		{"expired within skew", unsignedJWT(map[string]any{"exp": now.Unix() + 10}), "", "identity token expired"},
		{"wrong audience", unsignedJWT(map[string]any{"exp": now.Unix() + 600, "aud": "x"}), "a", "identity token audience mismatch (expected a)"},
		{"not a jwt", "opaque", "", "identity token is not a JWT"},
		{"bad payload", "a.!!!.c", "", "identity token is not a JWT"},
		{"array payload", "a.WzFd.c", "", "identity token is not a JWT"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := PrecheckToken(tc.token, tc.aud, now)
			if (tc.want == "" && err != nil) || (tc.want != "" && (err == nil || Reason(err) != tc.want)) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func FuzzJWTClaims(f *testing.F) {
	f.Add(unsignedJWT(map[string]any{"exp": 1, "aud": []string{"a"}}))
	f.Add("a.b")
	f.Add("..")
	f.Fuzz(func(t *testing.T, tok string) {
		c, err := JWTClaims(tok)
		if err == nil && c == nil {
			t.Fatal("no claims and no error")
		}
		if err != nil && Reason(err) != "identity token is not a JWT" {
			t.Fatalf("unexpected reason %v", err)
		}
		_, _ = PrecheckToken(tok, "aud", time.Unix(0, 0)) // must not panic
	})
}

func TestShellSplitAndQuote(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want []string
	}{
		{`a b  c`, []string{"a", "b", "c"}},
		{`'a b' "c d" e\ f`, []string{"a b", "c d", "e f"}},
		{`"a\"b" "a\nb" 'x\y'`, []string{`a"b`, `a\nb`, `x\y`}},
		{`''`, []string{""}},
		{``, nil},
	}
	for _, tc := range tests {
		got, err := ShellSplit(tc.in)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ShellSplit(%q) = %q %v, want %q", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{`"open`, `'open`, `end\`} {
		if _, err := ShellSplit(bad); err == nil {
			t.Errorf("ShellSplit(%q) accepted", bad)
		}
	}
	for _, w := range []string{"plain/path-1.2", "with space", "it's", "", "$(x)"} {
		if got, err := ShellSplit(ShellQuote(w)); err != nil || !reflect.DeepEqual(got, []string{w}) {
			t.Errorf("round trip of %q: %q %v", w, got, err)
		}
	}
}

func FuzzShellSplit(f *testing.F) {
	for _, s := range []string{`a 'b c' "d\"e"`, `x\ y`, `"`, `''`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		words, err := ShellSplit(s)
		if err != nil || !utf8.ValidString(s) {
			return
		}
		quoted := make([]string, len(words))
		for i, w := range words {
			quoted[i] = ShellQuote(w)
		}
		again, err := ShellSplit(strings.Join(quoted, " "))
		if err != nil || !slices.Equal(again, words) {
			t.Fatalf("quote/split round trip of %q: %q -> %q (%v)", s, words, again, err)
		}
	})
}

func TestErrText(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, body, want string }{
		{"sts xml", `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>InvalidIdentityToken</Code><Message>Incorrect token audience</Message></Error></ErrorResponse>`,
			"InvalidIdentityToken: Incorrect token audience"},
		{"google json", `{"error":{"code":403,"status":"PERMISSION_DENIED","message":"denied"}}`, "PERMISSION_DENIED: denied"},
		{"arm json", `{"error":{"code":"AuthorizationFailed","message":"no"}}`, "AuthorizationFailed: no"},
		{"oauth json", `{"error":"invalid_grant","error_description":"Token has been expired or revoked."}`,
			"invalid_grant: Token has been expired or revoked."},
		{"json without error", `{"x":1}`, "None: "},
		{"plain text", "Not Found", "Not Found"},
		{"long text", strings.Repeat("x", 300), strings.Repeat("x", 120)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ErrText([]byte(tc.body)); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func FuzzErrText(f *testing.F) {
	for _, s := range []string{`<a><Code>c</Code><Message>m</Message></a>`, `{"error":"x"}`, `{"error":{"message":1}}`, "\xff\xfe", ""} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		got := ErrText(body)
		if utf8.RuneCountInString(got) > 200 || !utf8.ValidString(got) {
			t.Fatalf("reason too long or not UTF-8: %q", got)
		}
	})
}

func TestExpandUserAndADCPath(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if got := ExpandUser("~/x", home); got != filepath.Join(home, "x") {
		t.Fatalf("ExpandUser: %s", got)
	}
	if got := ExpandUser("~other/x", home); got != "~other/x" {
		t.Fatalf("ExpandUser of another user's home: %s", got)
	}
	tests := []struct {
		name  string
		cfg   Account
		env   map[string]string
		goos  string
		where string
		path  string
	}{
		{"adc_file", Account{"adc_file": "/a.json"}, nil, "linux", "adc_file", "/a.json"},
		{"env", Account{}, map[string]string{"GOOGLE_APPLICATION_CREDENTIALS": "/e.json"}, "linux", "GOOGLE_APPLICATION_CREDENTIALS", "/e.json"},
		{"cloudsdk config", Account{}, map[string]string{"CLOUDSDK_CONFIG": home}, "linux", "the gcloud default location",
			filepath.Join(home, "application_default_credentials.json")},
		{"home", Account{}, map[string]string{"HOME": home}, "linux", "the gcloud default location",
			filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")},
		{"windows", Account{}, map[string]string{"APPDATA": home}, "windows", "the gcloud default location",
			filepath.Join(home, "gcloud", "application_default_credentials.json")},
	}
	for _, tc := range tests {
		deps := testDeps(tc.env)
		deps.GOOS = tc.goos
		if p, w := ADCPath(tc.cfg, deps); p != tc.path || w != tc.where {
			t.Errorf("%s: %s (%s), want %s (%s)", tc.name, p, w, tc.path, tc.where)
		}
	}
}
