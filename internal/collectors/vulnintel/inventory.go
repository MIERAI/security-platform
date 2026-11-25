package vulnintel

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

const (
	inventorySchema  = "security-platform/inventory/v1"
	maxInventoryFile = 256 << 20
)

// invFile is one inventory/v1 document of the input directory.
type invFile struct {
	name string
	doc  *pyjson.Object
}

// readInventories reads every inventory.*.json of the input directory (the runner's latest/), sorted by name.
// One that cannot be read fails the run, as in the Python collector: a guessed inventory must not retire anything.
func readInventories(dir string) ([]invFile, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "inventory.*.json"))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errInventory, err)
	}
	sort.Strings(paths)
	var out []invFile
	for _, p := range paths {
		data, err := rundoc.ReadLimited(p, maxInventoryFile)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errInventory, err)
		}
		v, err := pyjson.Decode(data)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", errInventory, filepath.Base(p), err)
		}
		if o := obj(v); o != nil && sget(o, "schema") == inventorySchema {
			out = append(out, invFile{filepath.Base(p), o})
		}
	}
	return out, nil
}

// items is every item of the inventories of one kind, in file order.
func items(inv []invFile, kind string) []*pyjson.Object {
	var out []*pyjson.Object
	for _, f := range inv {
		if sget(f.doc, "kind") == kind {
			for _, it := range lget(f.doc, "items") {
				if o := obj(it); o != nil {
					out = append(out, o)
				}
			}
		}
	}
	return out
}

// imageCompleteness is image_inventory(): complete only when at least one container-image inventory exists and
// every one says `complete: true`; otherwise the reasons it is partial.
func imageCompleteness(inv []invFile) (complete bool, partial []string) {
	n := 0
	for _, f := range inv {
		if sget(f.doc, "kind") != "container-image" {
			continue
		}
		n++
		if c, _ := get(f.doc, "complete").(bool); c {
			continue
		}
		partial = append(partial, f.name+": "+partialReason(oget(f.doc, "sources")))
	}
	return n > 0 && len(partial) == 0, partial
}

// partialReason names the sources of an inventory that were not read completely (sorted by source).
func partialReason(srcs *pyjson.Object) string {
	var bad []string
	if srcs != nil {
		for _, k := range srcs.SortedKeys() {
			if v, _ := srcs.Get(k); v != "complete" {
				bad = append(bad, k+" "+pystr(v))
			}
		}
	}
	if len(bad) == 0 {
		return "completeness not declared"
	}
	return strings.Join(bad, ", ")
}

// image is one running image, merged over clusters.
type image struct {
	first    *pyjson.Object // the first inventory item of the image
	clusters map[string]bool
	exposed  bool
	prod     bool
	sbom     string
	report   *pyjson.Object
}

func (im *image) clusterList() []string {
	out := make([]string, 0, len(im.clusters))
	for c := range im.clusters {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func (im *image) meta() *matchMeta {
	return &matchMeta{exposed: im.exposed, prod: im.prod, clusters: im.clusterList()}
}

// json is the image's evidence entry: the first item, clusters sorted, exposure and production merged, the SBOM.
func (im *image) json() *pyjson.Object {
	o := pyjson.NewObject()
	for _, k := range im.first.Keys() {
		v, _ := im.first.Get(k)
		o.Set(k, v)
	}
	o.Set("clusters", list(im.clusterList()))
	o.Set("exposed", im.exposed)
	o.Set("prod", im.prod)
	if im.sbom != "" {
		o.Set("sbom", im.sbom)
	}
	return o
}

type imageSet struct {
	order []string
	byRef map[string]*image
}

// sboms are the OSV matcher's targets among the images: those with an SBOM.
func (s *imageSet) sboms() []sbomTarget {
	var out []sbomTarget
	for _, ref := range s.order {
		if im := s.byRef[ref]; im.sbom != "" {
			out = append(out, sbomTarget{asset: "image:" + ref, rel: im.sbom, meta: im.meta()})
		}
	}
	return out
}

// images merges the container-image inventories, declares a complete one, and scans every image.
func (c *collector) images(ctx context.Context, inv []invFile) *imageSet {
	complete, partial := imageCompleteness(inv)
	if complete {
		c.doc.OK("inventory:container-image", "image:")
	} else if len(partial) > 0 {
		c.partialNote(partial)
	}
	set := &imageSet{byRef: map[string]*image{}}
	for _, it := range items(inv, "container-image") {
		ref := pystr(get(it, "image"))
		im := set.byRef[ref]
		if im == nil {
			im = &image{first: it, clusters: map[string]bool{}}
			set.byRef[ref] = im
			set.order = append(set.order, ref)
		}
		im.clusters[pystr(get(it, "cluster"))] = true
		im.exposed = im.exposed || truthy(it, "exposed")
		im.prod = im.prod || truthy(it, "prod")
	}
	firsts := make([]*pyjson.Object, len(set.order))
	for i, ref := range set.order {
		firsts[i] = set.byRef[ref].first
	}
	for i, res := range c.scanImages(ctx, firsts) {
		im := set.byRef[set.order[i]]
		if res.report == nil {
			c.doc.Gap("image:"+set.order[i], res.note, nil)
			continue
		}
		c.doc.OK("image:"+set.order[i], "")
		im.report, im.sbom = res.report, res.note
	}
	return set
}

type repoScan struct {
	name   string
	report *pyjson.Object
}

// scanRepos scans the configured local repositories (intel.repos).
func (c *collector) scanRepos(ctx context.Context) []repoScan {
	var out []repoScan
	for _, p := range rundoc.Strings(c.cfg.Value("repos")) {
		name := filepath.Base(strings.TrimRight(p, "/"))
		rep, note := c.scanRepo(ctx, p)
		if rep == nil {
			c.doc.Gap("repo:"+name, note, nil)
		} else {
			c.doc.OK("repo:"+name, "")
		}
		out = append(out, repoScan{name, rep})
	}
	return out
}
