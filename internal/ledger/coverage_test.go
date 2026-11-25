package ledger

import "testing"

func TestCoverageCovers(t *testing.T) {
	t.Parallel()
	cov := NewCoverage([]string{"host:h1", "net-endpoint:h@192.0.2.10", "k8s-cluster:c1", "image:registry.example/web:1"})
	tests := []struct {
		asset string
		want  bool
	}{
		{"host:h1", true},
		{"host:h1/os-updates", true},                // prefix ending before a separator
		{"host:h10", false},                         // not a prefix at a separator
		{"net-endpoint:h@192.0.2.10:443", true},     // prefix before ':'
		{"net-endpoint:h@192.0.2.100", false},       // ...but not inside the address
		{"secret-file:h1:/etc/ssl/key.pem", true},   // umbrella host -> secret-file
		{"secret-file:h10:/etc/ssl/key.pem", false}, // other scope
		{"k8s-workload:c1/ns/deploy/web", true},     // umbrella k8s-cluster
		{"cis:c1/1.2.3", true},                      // umbrella k8s-cluster -> cis
		{"k8s-workload:c2/ns/deploy/web", false},    // other cluster
		{"image:registry.example/web:1", true},      // exact
		{"image:registry.example/web:10", false},    // a longer tag is another image
		{"repo:example/web", false},                 // other type
		{"secret-file:h1", true},                    // umbrella with an empty rest
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.asset, func(t *testing.T) {
			t.Parallel()
			if got := cov.Covers(tc.asset); got != tc.want {
				t.Errorf("Covers(%q) = %v, want %v", tc.asset, got, tc.want)
			}
		})
	}
	if !NewCoverage(nil).Empty() || cov.Empty() {
		t.Error("Empty")
	}
}

func TestFnmatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, pattern string
		want          bool
	}{
		{"ssh.password_auth_enabled", "ssh.*", true},
		{"ssh.password_auth_enabled", "ssh.password_auth_enabled", true},
		{"sshd.x", "ssh.*", false},     // "." is literal
		{"a/b", "a*", true},            // "*" also matches "/" (fnmatch, not path.Match)
		{"host.x", "host.?", true},     //
		{"host.xy", "host.?", false},   //
		{"host.a", "host.[ab]", true},  //
		{"host.c", "host.[!ab]", true}, //
		{"host.a", "host.[!ab]", false},
		{"host.[", "host.[", true}, // an unterminated bracket is literal
		{"HOST.X", "host.*", false},
	}
	for _, tc := range tests {
		if got := fnmatch(tc.name, tc.pattern); got != tc.want {
			t.Errorf("fnmatch(%q, %q) = %v, want %v", tc.name, tc.pattern, got, tc.want)
		}
	}
}

func TestScope(t *testing.T) {
	t.Parallel()
	tests := []struct{ asset, typ, scope string }{
		{"host:h1", "host", "h1"},
		{"secret-file:h1:/etc/x", "secret-file", "h1"},
		{"net-endpoint:h@192.0.2.1:22", "net-endpoint", "h"},
		{"k8s-workload:c1/ns/x", "k8s-workload", "c1"},
		{"noseparator", "noseparator", ""},
	}
	for _, tc := range tests {
		if typ, sc := scope(tc.asset); typ != tc.typ || sc != tc.scope {
			t.Errorf("scope(%q) = %q, %q", tc.asset, typ, sc)
		}
	}
}
