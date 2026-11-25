package scorecard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	pv "github.com/MIERAI/security-platform/internal/scorecard/pyvalue"
)

// Document schemas (contracts/scorecard).
const (
	Schema            = "security-platform/scorecard/v1"
	CatalogSchema     = "security-platform/scorecard-catalog/v1"
	AttestationSchema = "security-platform/attestations/v1"
)

// maxInputFile bounds every file the scorecard reads.
const maxInputFile = 64 << 20

// defaultOrder is the sort key of a dimension without an order.
const defaultOrder = 99.0

// ErrConfig is a configuration error: a malformed catalog, instance or attestation file.
var ErrConfig = errors.New("configuration error")

func configErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrConfig}, args...)...)
}

// Dimension is one catalog dimension: its merged catalog entries.
type Dimension struct {
	raw *pv.Map
	ID  string
}

func (d *Dimension) order() any { return d.raw.Value("order") }

// orderKey is the dimension's sort key; a dimension without an order sorts as 99.
func orderKey(d *Dimension) (float64, error) {
	if d == nil || !d.raw.Has("order") {
		return defaultOrder, nil
	}
	f, ok := pv.ToFloat64(d.raw.Value("order"))
	if !ok {
		return 0, configErr("dimension %s: order must be a number", d.ID)
	}
	return f, nil
}

// Control is one catalog control after overrides, with its evaluation result.
type Control struct {
	raw        *pv.Map
	ID         string
	Dimension  string
	Function   string
	Status     string
	Detail     string
	Expires    float64 // epoch of the deciding attestation's expiry; 0 = none
	hasExpires bool
}

func (c *Control) get(key string) any { return c.raw.Value(key) }

func (c *Control) isAttested() bool { return pv.Equal(c.get("check"), "attested") }

// Catalog is the loaded catalog: dimensions in first-seen order, controls in report order.
type Catalog struct {
	Dims     []*Dimension
	dimByID  map[string]*Dimension
	Controls []*Control
}

// catalogDirs lists the catalog directories: the product catalog (unless replace_catalog), the instance's
// catalog_dirs, then the extra directories (--catalog).
func catalogDirs(sc *pv.Map, product, home string, extra []string) ([]string, error) {
	var dirs []string
	if !pv.Truthy(sc.Value("replace_catalog")) {
		dirs = append(dirs, filepath.Join(product, "scorecard", "catalog"))
	}
	own := sc.Value("catalog_dirs")
	if pv.Truthy(own) {
		items, err := pv.Iter(own)
		if err != nil {
			return nil, configErr("scorecard.catalog_dirs: %v", err)
		}
		for _, d := range items {
			s, ok := d.(string)
			if !ok {
				return nil, configErr("scorecard.catalog_dirs: %s is not a path", pv.Repr(d))
			}
			dirs = append(dirs, expandUser(s, home))
		}
	}
	return append(dirs, extra...), nil
}

// expandUser replaces a leading ~ (alone or before a separator) with the home directory.
func expandUser(p, home string) string {
	if home == "" || (p != "~" && !strings.HasPrefix(p, "~/") && !strings.HasPrefix(p, `~`+string(filepath.Separator))) {
		return p
	}
	return home + p[1:]
}

// catalogFiles lists *.yaml and *.json files of a directory, hidden ones excluded, sorted; a missing
// directory has none.
func catalogFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read catalog directory %s: %w", dir, err)
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, ".") && (strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".json")) {
			out = append(out, filepath.Join(dir, n))
		}
	}
	sort.Strings(out)
	return out, nil
}

// LoadCatalog reads the catalog directories in order (a later control with the same id replaces the earlier
// one, keeping its place) and applies the instance's overrides.
func LoadCatalog(dirs []string, sc *pv.Map) (*Catalog, error) {
	cat := &Catalog{dimByID: map[string]*Dimension{}}
	byID := &controlIndex{byID: map[string]*pv.Map{}}
	for _, d := range dirs {
		files, err := catalogFiles(d)
		if err != nil {
			return nil, err
		}
		for _, p := range files {
			if err := cat.addFile(p, byID); err != nil {
				return nil, err
			}
		}
	}
	if err := applyOverrides(byID, sc.Value("overrides")); err != nil {
		return nil, err
	}
	if err := cat.buildControls(byID); err != nil {
		return nil, err
	}
	return cat, nil
}

func (cat *Catalog) addFile(path string, byID *controlIndex) error {
	doc, err := readYAMLFile(path)
	if err != nil {
		return err
	}
	m, ok := orEmpty(doc)
	if !ok {
		return configErr("%s: not a mapping", path)
	}
	if !pv.Equal(m.Value("schema"), CatalogSchema) {
		return configErr("%s: schema must be %s", path, CatalogSchema)
	}
	dm, ok := m.Value("dimension").(*pv.Map)
	if !ok {
		return configErr("%s: dimension must be a mapping", path)
	}
	id, ok := dm.Value("id").(string)
	if !ok {
		return configErr("%s: dimension.id must be text", path)
	}
	cat.mergeDimension(id, dm)
	return addControls(path, m.Value("controls"), dm, byID)
}

func (cat *Catalog) mergeDimension(id string, dm *pv.Map) {
	d, ok := cat.dimByID[id]
	if !ok {
		d = &Dimension{raw: pv.NewMap(), ID: id}
		cat.dimByID[id] = d
		cat.Dims = append(cat.Dims, d)
	}
	d.raw.Update(dm)
}

func addControls(path string, controls any, dm *pv.Map, byID *controlIndex) error {
	if !pv.Truthy(controls) {
		return nil
	}
	list, ok := controls.([]any)
	if !ok {
		return configErr("%s: controls must be a list", path)
	}
	for _, x := range list {
		c, ok := x.(*pv.Map)
		if !ok {
			return configErr("%s: a control must be a mapping", path)
		}
		c = c.Copy()
		c.Set("dimension", dm.Value("id"))
		c.SetDefault("pillars", dm.GetOr("pillars", []any{}))
		id, ok := c.Value("id").(string)
		if !ok {
			return configErr("%s: a control needs a text id", path)
		}
		byID.set(id, c)
	}
	return nil
}

// controlIndex holds the catalog's controls by id in first-seen order (a replaced control keeps its place).
type controlIndex struct {
	ids  []string
	byID map[string]*pv.Map
}

func (x *controlIndex) set(id string, c *pv.Map) {
	if _, ok := x.byID[id]; !ok {
		x.ids = append(x.ids, id)
	}
	x.byID[id] = c
}

func applyOverrides(byID *controlIndex, overrides any) error {
	if !pv.Truthy(overrides) {
		return nil
	}
	o, ok := overrides.(*pv.Map)
	if !ok {
		return configErr("scorecard.overrides must be a mapping")
	}
	for _, id := range o.Keys() {
		c, found := byID.byID[id]
		if !found {
			continue
		}
		patch, ok := o.Value(id).(*pv.Map)
		if !ok {
			return configErr("scorecard.overrides.%s must be a mapping", id)
		}
		c.Update(patch)
	}
	return nil
}
