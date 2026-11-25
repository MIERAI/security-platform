package cloud

import (
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// Finding is one finding as the cloud collector builds it (attributes as Go values, see rundoc.JSON).
type Finding struct {
	Layer, Asset, Check, Title, Severity, Evidence, Remediation string
	NeedsHuman                                                  bool
	Refs                                                        []string
	Attributes                                                  map[string]any
}

// finding is f as the document records it.
func finding(f *Finding) *rundoc.Finding {
	var refs []pyjson.Value
	for _, r := range f.Refs {
		refs = append(refs, r)
	}
	return &rundoc.Finding{Layer: f.Layer, Asset: f.Asset, Check: f.Check, Title: f.Title, Severity: f.Severity,
		Evidence: f.Evidence, Remediation: f.Remediation, NeedsHuman: f.NeedsHuman, Refs: refs,
		Attributes: rundoc.Attributes(f.Attributes)}
}
