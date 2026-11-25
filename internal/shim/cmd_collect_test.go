package shim

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCollectRunsInGo(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	inst := filepath.Join(dir, "instance.json")
	if err := os.WriteFile(inst, []byte(`{"hosts": [{"name": "off", "exec": null}], "secrets_files": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"host", "host-sbom", "secrets-files"} {
		run1 := filepath.Join(dir, name)
		r := run(t, map[string]string{"SP_RUN_DIR": run1, "SP_INSTANCE": inst}, "", "collect", name)
		if r.code != 0 || !strings.HasPrefix(r.stderr, "["+name+" ") {
			t.Errorf("collect %s: %+v", name, r)
		}
		if _, err := os.Stat(filepath.Join(run1, name+".findings.json")); err != nil {
			t.Error(err)
		}
	}
	for _, args := range [][]string{{"collect"}, {"collect", "nope"}, {"collect", "host", "x"}} {
		if r := run(t, nil, "", args...); r.code != ExitUsage || !strings.Contains(r.stderr, "host-sbom") {
			t.Errorf("%v: %+v", args, r)
		}
	}
	if !slices.Contains(GoSubcommands(), "collect") {
		t.Error("collect is not listed as a Go subcommand")
	}
}
