// Package remediation is the Go implementation of `track` (contracts/ledger/SPEC.md §7): one tracking item per
// ledger entry that is or was open, with an owner, an SLO class and a due date, mirrored into
// DATA/tracker/items.json, DATA/metrics/remediation.prom and the configured tracker adapter. It reproduces the
// reference (core/remediation.py) and its files byte for byte. Nothing here changes a ledger status.
package remediation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/MIERAI/security-platform/internal/ledger/fileio"
	"github.com/MIERAI/security-platform/internal/ledger/instant"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// Schema is the tracker file's schema name.
const Schema = "security-platform/tracker/v1"

// maxFileBytes bounds ledger.json and items.json reads.
const maxFileBytes = 2 << 30

// Options are the inputs of one track run.
type Options struct {
	Data           string
	Config         *pyjson.Object // the instance's `remediation:` section; nil without --instance
	Now            float64        // epoch seconds (--now or the clock)
	Wall           float64        // the wall clock, for the heartbeat metric only
	NoExternalSync bool           // sync only the local files tracker (shadow runs): never call an external tracker
	Version        string         // recorded in items.json "core"
	Stderr         io.Writer
	GH             GHFunc // runs `gh api ...` for the github-issues tracker
}

// Track runs one track. On error items.json is not written.
func Track(ctx context.Context, opt Options) error {
	slo, err := SLOSeconds(opt.Config)
	if err != nil {
		return err
	}
	if aerr := checkAdvisor(opt.Config); aerr != nil {
		return aerr
	}
	ledger, err := readObject(filepath.Join(opt.Data, "ledger.json"), false)
	if err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	items, err := loadItems(opt.Data)
	if err != nil {
		return err
	}
	Update(items, ledger.Obj("entries"), opt.Config, opt.Now, slo)
	result, err := syncTracker(ctx, opt, items)
	if err != nil {
		return err
	}
	if err := writeOutputs(opt, items, slo); err != nil {
		return err
	}
	summary(opt, items, result)
	return nil
}

// loadItems reads the previous items (none yet: empty) and makes sure DATA/tracker exists.
func loadItems(data string) (*pyjson.Object, error) {
	prev, err := readObject(filepath.Join(data, "tracker", "items.json"), true)
	if err != nil {
		return nil, fmt.Errorf("previous items: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(data, "tracker"), 0o700); err != nil {
		return nil, fmt.Errorf("create tracker dir: %w", err)
	}
	if items := prev.Obj("items"); items != nil {
		return items, nil
	}
	return pyjson.NewObject(), nil
}

// readObject reads a JSON object; a missing file is an error unless optional (then an empty object).
func readObject(path string, optional bool) (*pyjson.Object, error) {
	data, err := fileio.Read(path, maxFileBytes)
	if optional && errors.Is(err, fs.ErrNotExist) {
		return pyjson.NewObject(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	v, err := pyjson.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	o, ok := v.(*pyjson.Object)
	if !ok {
		return nil, fmt.Errorf("%s: top level is not an object", path)
	}
	return o, nil
}

// checkAdvisor: the only advisor today is `none` (drafts nothing); the others are documented future adapters.
func checkAdvisor(cfg *pyjson.Object) error {
	if cfg == nil {
		return nil
	}
	adv := cfg.Obj("advisor")
	if adv == nil || !adv.Has("type") {
		return nil
	}
	if t, _ := adv.Get("type"); t != "none" {
		return fmt.Errorf("%w: advisor %s: future adapter (claude / local)", ErrConfig, pyjson.Repr(t))
	}
	return nil
}

func writeOutputs(opt Options, items *pyjson.Object, slo map[string]int64) error {
	sloObj := pyjson.NewObject()
	for _, k := range sortedKeys(slo) {
		sloObj.Set(k, slo[k])
	}
	doc := pyjson.ObjectOf("schema", Schema, "core", opt.Version, "implementation", "go", "updated_at", instant.ISO(opt.Now),
		"slo_seconds", sloObj, "items", items)
	data, err := pyjson.Marshal(doc, pyjson.Ledger())
	if err != nil {
		return fmt.Errorf("encode items: %w", err)
	}
	if err := fileio.WriteDurable(filepath.Join(opt.Data, "tracker", "items.json"), data); err != nil {
		return err
	}
	metrics := filepath.Join(opt.Data, "metrics")
	if err := os.MkdirAll(metrics, 0o700); err != nil {
		return fmt.Errorf("create metrics dir: %w", err)
	}
	return fileio.Write(filepath.Join(metrics, "remediation.prom"), []byte(renderSeries(items, slo, opt.Wall)))
}

func summary(opt Options, items *pyjson.Object, result string) {
	var open, overdue, unassigned int
	for _, id := range items.Keys() {
		it := items.Obj(id)
		if it == nil || it.Str("status") != "open" {
			continue
		}
		open++
		if it.Truthy("overdue") {
			overdue++
		}
		if it.Str("owner") == "unassigned" {
			unassigned++
		}
	}
	_, _ = fmt.Fprintf(opt.Stderr, "[remediation %s] open=%d overdue=%d unassigned=%d drafts=0 tracker=%s\n",
		opt.Version, open, overdue, unassigned, result) // stderr is best effort
}
