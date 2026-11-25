// Package buildinfo describes the running binary: the product release it was built as, its commit and toolchain.
package buildinfo

import (
	"runtime"
	"runtime/debug"

	"github.com/MIERAI/security-platform/internal/release"
)

// productRelease is set at link time by the release pipeline (-ldflags "-X ...buildinfo.productRelease=vX.Y.Z")
// and never written at run time: it is the one package-level variable the coding standard allows (docs/go.md).
var productRelease string //nolint:gochecknoglobals // link-time constant (-X); never assigned in code

// Info describes a build.
type Info struct {
	Release   string `json:"release"`  // vX.Y.Z for a release build, dev-g<commit> or "dev" otherwise
	Commit    string `json:"commit"`   // full commit hash, "" when the build has no VCS information
	Modified  bool   `json:"modified"` // built from a working tree with uncommitted changes
	GoVersion string `json:"go"`
	Platform  string `json:"platform"` // GOOS/GOARCH
}

// Read returns the running binary's build information.
func Read() Info {
	bi, _ := debug.ReadBuildInfo()
	return FromBuild(productRelease, bi)
}

// FromBuild derives Info from a link-time release name and the module build information (nil when absent).
// A link-time name that is not a product tag is ignored: the binary then calls itself a development build.
func FromBuild(linked string, bi *debug.BuildInfo) Info {
	info := Info{GoVersion: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH}
	if bi != nil {
		info.GoVersion = bi.GoVersion
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				info.Commit = s.Value
			case "vcs.modified":
				info.Modified = s.Value == "true"
			}
		}
	}
	info.Release = devName(info.Commit, info.Modified)
	if release.IsProductTag(linked) && !info.Modified {
		info.Release = linked
	}
	return info
}

func devName(commit string, modified bool) string {
	name := "dev"
	if len(commit) >= 7 {
		name += "-g" + commit[:7]
	}
	if modified {
		name += "-dirty"
	}
	return name
}
