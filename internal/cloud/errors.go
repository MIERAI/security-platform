package cloud

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
)

// Error is an authentication or authorisation failure. Its text is a short reason without any secret: the
// collector records it as the coverage gap's reason ("never no findings").
type Error struct {
	Reason string
}

func (e *Error) Error() string { return e.Reason }

// failf returns an *Error with a formatted reason.
func failf(format string, args ...any) error {
	return &Error{Reason: fmt.Sprintf(format, args...)}
}

// Reason is the coverage-gap reason of err: the reason of an *Error in its chain, else its text.
func Reason(err error) string {
	var ce *Error
	if errors.As(err, &ce) {
		return ce.Reason
	}
	return err.Error()
}

// ErrText is a short reason from a provider's error body: STS/IAM XML (Code: Message), Google/ARM JSON
// ({"error": {"status"|"code", "message"}}), OAuth JSON ({"error", "error_description"}), else the start of the
// body. Error bodies carry codes and messages, never credentials.
func ErrText(body []byte) string {
	if code, msg, ok := xmlError(body); ok {
		return dyn.Cut(code+": "+msg, 200)
	}
	if v, err := dyn.Decode(body); err == nil {
		if d, ok := v.(map[string]any); ok {
			return jsonError(d)
		}
	}
	return dyn.Cut(dyn.ValidUTF8(string(body[:min(len(body), 120)])), 120)
}

func jsonError(d map[string]any) string {
	if e, ok := d["error"].(map[string]any); ok {
		head := dyn.Or(dyn.Text(e, "status"), dyn.Text(e, "code"))
		if head == "" {
			head = "None"
		}
		return dyn.Cut(head+": "+dyn.Str(e["message"]), 200)
	}
	head := dyn.Str(d["error"])
	if d["error"] == nil {
		head = "None"
	}
	return dyn.Cut(head+": "+dyn.Str(d["error_description"]), 200)
}

// xmlError finds the first <Code> and <Message> elements (any namespace, any depth) of a well-formed XML body.
func xmlError(body []byte) (code, msg string, ok bool) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	var cur string
	seenRoot := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return code, msg, seenRoot
		}
		if err != nil {
			return "", "", false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			seenRoot = true
			cur = t.Name.Local
		case xml.EndElement:
			cur = ""
		case xml.CharData:
			code, msg = xmlText(cur, string(t), code, msg)
		}
	}
}

func xmlText(elem, text, code, msg string) (newCode, newMsg string) {
	switch {
	case elem == "Code" && code == "":
		return text, msg
	case elem == "Message" && msg == "":
		return code, text
	}
	return code, msg
}
