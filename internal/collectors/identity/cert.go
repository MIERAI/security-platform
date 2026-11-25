package identity

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"regexp"
	"strings"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// orgRE is the Python adapter's regular expression over `openssl x509 -noout -enddate -subject`.
var orgRE = regexp.MustCompile(`O ?= ?([^,/\n]+)`)

// certNotAfter is the expiry and the organisations (Kubernetes groups) of a PUBLIC client certificate given as
// kubeconfig's base64 client-certificate-data; (nil, []) when it cannot be read. The Python adapter asks openssl;
// the subject is rebuilt here in OpenSSL's one-line form and read with the same expression, so both agree.
func certNotAfter(data any) (pyjson.Value, []string) {
	s, ok := data.(string)
	if !ok {
		return nil, []string{}
	}
	raw, ok := pyB64Decode(s)
	if !ok {
		return nil, []string{}
	}
	cert := firstCert(raw)
	if cert == nil {
		return nil, []string{}
	}
	exp := cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z")
	groups := []string{}
	for _, m := range orgRE.FindAllStringSubmatch("subject="+oneline(cert.Subject), -1) {
		groups = append(groups, strings.TrimSpace(m[1]))
	}
	return exp, groups
}

const b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// pyB64Decode is base64.b64decode without validation: characters outside the alphabet are skipped, the data
// ends at the first padding, and incomplete groups need their padding.
func pyB64Decode(s string) ([]byte, bool) {
	var b strings.Builder
	pads := 0
	for _, r := range s {
		switch {
		case r > 0x7f:
			return nil, false // b64decode refuses non-ASCII text
		case r == '=':
			pads++
		case pads == 0 && strings.ContainsRune(b64Alphabet, r):
			b.WriteRune(r)
		}
	}
	data := b.String()
	if rem := len(data) % 4; rem == 1 || rem != 0 && pads < 4-rem {
		return nil, false
	}
	out, err := base64.RawStdEncoding.DecodeString(data)
	if err != nil {
		return nil, false
	}
	return out, true
}

// firstCert is the first PEM certificate block (as `openssl x509` reads it).
func firstCert(data []byte) *x509.Certificate {
	for {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			return nil
		}
		switch blk.Type {
		case "CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE":
			cert, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil
			}
			return cert
		}
	}
}

// oneline is the subject as OpenSSL 3 prints it: "SN=value, SN=value" in certificate order.
func oneline(n pkix.Name) string {
	parts := make([]string, 0, len(n.Names))
	for _, atv := range n.Names {
		v, _ := atv.Value.(string) // non-string attribute values are left empty
		parts = append(parts, shortName(atv.Type)+"="+v)
	}
	return strings.Join(parts, ", ")
}

func shortName(oid asn1.ObjectIdentifier) string {
	names := map[string]string{"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O",
		"2.5.4.11": "OU", "2.5.4.5": "serialNumber", "2.5.4.9": "street", "2.5.4.17": "postalCode",
		"1.2.840.113549.1.9.1": "emailAddress", "0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID"}
	if s, ok := names[oid.String()]; ok {
		return s
	}
	return oid.String()
}
