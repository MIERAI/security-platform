package ledger

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MIERAI/security-platform/internal/ledger/fileio"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/ledger/yamlcfg"
)

// Size limits of the files read (docs/go.md: bounded reads).
const (
	MaxLedgerBytes   = 2 << 30   // DATA/ledger.json
	MaxDocumentBytes = 512 << 20 // one findings document
	MaxYAMLBytes     = 16 << 20  // exceptions.yaml, catalog-review.yaml, the instance config
)

// ErrNotObject is returned for a ledger or configuration file whose top level is not an object.
var ErrNotObject = errors.New("top level is not an object")

// document is one valid findings document of a run.
type document struct {
	obj       *pyjson.Object
	collector string
	version   string
	finished  string
	coverage  []*pyjson.Object
	findings  []*pyjson.Object
}

// readFile reads a whole file through a size limit.
func readFile(path string, limit int64) ([]byte, error) {
	data, err := fileio.Read(path, limit)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return data, nil
}

// loadLedger reads the previous ledger; absent: an empty one.
func loadLedger(path string) (*pyjson.Object, error) {
	data, err := readFile(path, MaxLedgerBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return pyjson.ObjectOf("schema", Schema, "entries", pyjson.NewObject(), "runs", []pyjson.Value{}), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read previous ledger: %w", err)
	}
	v, err := pyjson.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("previous ledger %s: %w", path, err)
	}
	o, ok := v.(*pyjson.Object)
	if !ok {
		return nil, fmt.Errorf("previous ledger %s: %w", path, ErrNotObject)
	}
	return o, nil
}

// findingsFiles lists dir/*.findings.json in file-name order (hidden files excluded, as a shell glob).
func findingsFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil // as a glob: nothing there
	}
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", dir, err)
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, ".") && strings.HasSuffix(n, ".findings.json") && !e.IsDir() {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}

// loadDocuments reads and validates dir/*.findings.json: the valid documents, and file name -> first five
// errors of the invalid ones (a document that is not JSON at all is invalid too).
func (m *merger) loadDocuments(dir string) ([]document, *pyjson.Object, error) {
	names, err := findingsFiles(dir)
	if err != nil {
		return nil, nil, err
	}
	var docs []document
	invalid := pyjson.NewObject()
	for _, n := range names {
		d, errs := m.loadDocument(filepath.Join(dir, n))
		if len(errs) > 0 {
			if len(errs) > 5 {
				errs = errs[:5]
			}
			list := make([]pyjson.Value, len(errs))
			for i, e := range errs {
				list[i] = e
			}
			invalid.Set(n, list)
			continue
		}
		docs = append(docs, d)
	}
	return docs, invalid, nil
}

func (m *merger) loadDocument(path string) (document, []string) {
	data, err := readFile(path, MaxDocumentBytes)
	if err != nil {
		return document{}, []string{fmt.Sprintf("unreadable: %v", errors.Unwrap(err))}
	}
	v, err := pyjson.Decode(data)
	if err != nil {
		return document{}, []string{fmt.Sprintf("not a JSON document: %v", err)}
	}
	if errs := m.validator.Validate(v); len(errs) > 0 {
		return document{}, errs
	}
	o, _ := v.(*pyjson.Object) // Validate accepted it: an object
	d := document{obj: o, collector: o.Obj("collector").Str("name"), version: o.Obj("collector").Str("version"),
		finished: o.Obj("run").Str("finished_at")}
	for _, x := range o.List("coverage") {
		c, _ := x.(*pyjson.Object) // validated: objects
		d.coverage = append(d.coverage, c)
	}
	for _, x := range o.List("findings") {
		f, _ := x.(*pyjson.Object) // validated: objects
		d.findings = append(d.findings, f)
	}
	return d, nil
}

// loadYAMLObject reads an optional YAML file whose top level is a mapping: absent or empty is an empty
// object; another top level is ignored with a warning; a syntax error is an error (as the reference, which
// stops rather than merge without the humans' exceptions).
func loadYAMLObject(path string, warn func(string, ...any)) (*pyjson.Object, error) {
	data, err := readFile(path, MaxYAMLBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return pyjson.NewObject(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	v, err := yamlcfg.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if v == nil {
		return pyjson.NewObject(), nil
	}
	o, ok := v.(*pyjson.Object)
	if !ok {
		warn("%s: ignored: %v", filepath.Base(path), ErrNotObject)
		return pyjson.NewObject(), nil
	}
	return o, nil
}
