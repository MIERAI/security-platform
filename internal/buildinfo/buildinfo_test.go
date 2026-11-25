package buildinfo

import (
	"runtime/debug"
	"testing"
)

func TestFromBuild(t *testing.T) {
	t.Parallel()
	vcs := func(rev, modified string) *debug.BuildInfo {
		return &debug.BuildInfo{GoVersion: "go1.27.4", Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: rev}, {Key: "vcs.modified", Value: modified}}}
	}
	const rev = "65cd3b0f0e1d2c3b4a5968778695a4b3c2d1e0f9"
	tests := []struct {
		name   string
		linked string
		bi     *debug.BuildInfo
		want   string
	}{
		{"release build", "v0.4.0", vcs(rev, "false"), "v0.4.0"},
		{"pre-release build", "v0.4.0-rc.1", vcs(rev, "false"), "v0.4.0-rc.1"},
		{"component tag is not a release", "core/v0.9.0", vcs(rev, "false"), "dev-g65cd3b0"},
		{"untagged build", "", vcs(rev, "false"), "dev-g65cd3b0"},
		{"dirty tree is never a release", "v0.4.0", vcs(rev, "true"), "dev-g65cd3b0-dirty"},
		{"no vcs information", "", &debug.BuildInfo{GoVersion: "go1.27.4"}, "dev"},
		{"no build information", "", nil, "dev"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := FromBuild(tc.linked, tc.bi)
			if got.Release != tc.want {
				t.Errorf("Release = %q, want %q", got.Release, tc.want)
			}
			if got.Platform == "" || got.GoVersion == "" {
				t.Errorf("incomplete info %+v", got)
			}
		})
	}
}

func TestRead(t *testing.T) {
	t.Parallel()
	if got := Read(); got.Release == "" || got.GoVersion == "" {
		t.Fatalf("Read() = %+v", got)
	}
}
