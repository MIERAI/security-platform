package detection

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/MIERAI/security-platform/internal/collectors/credential"
	"github.com/MIERAI/security-platform/internal/collectors/execadapter"
	"github.com/MIERAI/security-platform/internal/collectors/roclient"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const (
	defaultTimeout = 60 * time.Second
	execGrace      = 15 * time.Second
	maxResponse    = 64 << 20
	maxReasonText  = 100
	maxStderrText  = 120
)

// pyError is an error described the way the reference describes it in a gap reason: "<type>: <text>".
type pyError struct{ typ, msg string }

func (e *pyError) Error() string { return e.typ + ": " + e.msg }

// reason is f"{type(e).__name__}: {str(e)[:100]}".
func reason(err error) string {
	var pe *pyError
	if errors.As(err, &pe) {
		return pe.typ + ": " + rundoc.Cut(pe.msg, maxReasonText)
	}
	return rundoc.Cut(err.Error(), maxReasonText+20)
}

func keyError(k string) error { return &pyError{"KeyError", pyvalue.Repr(k)} }

// endpoint is a JSON read API: reached directly (url + optional bearer token file) or from a host through the exec
// adapter (curl there: the store may listen on that host's loopback only).
type endpoint struct {
	base      string
	exec      any // the exec adapter config (nil: direct)
	tokenFile string
	home      string
	client    *roclient.Client
	timeout   time.Duration
}

var errNoURL = errors.New("url missing")

func (c *collector) endpoint(cfg any) (*endpoint, error) {
	m, ok := cfg.(*pyvalue.Map)
	if !ok {
		return nil, errNoURL
	}
	u, ok := m.Value("url").(string)
	if !ok {
		return nil, errNoURL
	}
	e := &endpoint{base: strings.TrimRight(u, "/"), home: c.home, timeout: c.httpT}
	if x := m.Value("exec"); pyvalue.Truthy(x) {
		e.exec = x
	}
	e.tokenFile, _ = m.Value("token_file").(string) // absent or not text: no token
	cl, err := roclient.New(roclient.Options{Timeout: e.timeout, MaxBody: maxResponse})
	if err != nil {
		return nil, fmt.Errorf("http client: %w", err)
	}
	e.client = cl
	return e, nil
}

// get reads a JSON document: GET <base><path>?<params>.
func (e *endpoint) get(ctx context.Context, path string, params url.Values) (any, error) {
	q := e.base + path
	if len(params) > 0 {
		q += "?" + params.Encode()
	}
	var body []byte
	var err error
	if e.exec != nil {
		body, err = e.viaExec(ctx, q)
	} else {
		body, err = e.direct(ctx, q)
	}
	if err != nil {
		return nil, err
	}
	v, err := pyvalue.DecodeJSON(body)
	if err != nil {
		return nil, &pyError{"JSONDecodeError", jsonErrorText(body)}
	}
	return v, nil
}

// jsonErrorText is Python's json error for the common case (an empty or non-JSON body); other errors are described
// less precisely than Python does.
func jsonErrorText(body []byte) string {
	if strings.TrimSpace(string(body)) == "" || !strings.ContainsAny(strings.TrimSpace(string(body))[:1], "{[\"-0123456789tfnNI") {
		return "Expecting value: line 1 column 1 (char 0)"
	}
	return "invalid JSON document"
}

func (e *endpoint) viaExec(ctx context.Context, q string) ([]byte, error) {
	ex, err := execadapter.New(e.exec, nil)
	if err != nil {
		return nil, &pyError{"NotImplementedError", execadapter.Reason(err)}
	}
	secs := strconv.Itoa(int(e.timeout / time.Second))
	res := ex.Output(ctx, []string{"curl", "-sf", "--max-time", secs, "--", q}, e.timeout+execGrace)
	if res.RC != 0 {
		return nil, &pyError{"RuntimeError", fmt.Sprintf("curl rc=%d %s", res.RC, rundoc.Cut(strings.TrimSpace(res.Err), maxStderrText))}
	}
	return []byte(res.Out), nil
}

func (e *endpoint) direct(ctx context.Context, q string) ([]byte, error) {
	var hdr http.Header
	if e.tokenFile != "" {
		tok, err := e.token()
		if err != nil {
			return nil, err
		}
		hdr = http.Header{"Authorization": {"Bearer " + tok}}
	}
	res, err := e.client.Do(ctx, http.MethodGet, q, hdr)
	if err != nil {
		return nil, urlError(err)
	}
	if res.Status < 200 || res.Status >= 300 {
		return nil, &pyError{"HTTPError", fmt.Sprintf("HTTP Error %d: %s", res.Status, http.StatusText(res.Status))}
	}
	return res.Body, nil
}

// token reads the bearer token: only from a file that grants nothing to group and others (DETECTION-D1). Neither
// the value nor a part of it is ever in an error.
func (e *endpoint) token() (string, error) {
	p := rundoc.ExpandUser(e.tokenFile, e.home)
	tok, err := credential.File(p)
	switch {
	case err == nil:
		return tok, nil
	case errors.Is(err, fs.ErrNotExist):
		return "", &pyError{"FileNotFoundError", "[Errno 2] No such file or directory: " + pyvalue.Repr(p)}
	case errors.Is(err, credential.ErrPermissive):
		return "", &pyError{"PermissionError", "token_file readable by group/others (chmod 600), refused: " + p}
	default:
		return "", &pyError{"OSError", "token_file " + p + ": unusable"}
	}
}

// urlError describes a transport failure as urllib does: "<urlopen error [Errno N] Text>".
func urlError(err error) error {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return &pyError{"URLError", fmt.Sprintf("<urlopen error [Errno %d] %s>", int(errno), capitalize(errno.Error()))}
	}
	if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
		return &pyError{"URLError", "<urlopen error timed out>"}
	}
	return &pyError{"URLError", "<urlopen error " + err.Error() + ">"}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

// apiResult is doc["data"]["result"] of a Prometheus-style query answer.
func apiResult(doc any) ([]any, error) {
	m, ok := doc.(*pyvalue.Map)
	if !ok {
		return nil, &pyError{"TypeError", "the answer is not a JSON object"}
	}
	data, ok := m.Get("data")
	if !ok {
		return nil, keyError("data")
	}
	dm, ok := data.(*pyvalue.Map)
	if !ok {
		return nil, &pyError{"TypeError", "data is not a JSON object"}
	}
	res, ok := dm.Get("result")
	if !ok {
		return nil, keyError("result")
	}
	l, ok := res.([]any)
	if !ok {
		return nil, &pyError{"TypeError", "result is not a list"}
	}
	return l, nil
}

// vector reads {metric: {label: value}, value: [t, "number"]} samples into label value -> number.
func vector(res []any, key string) (map[string]float64, error) {
	out := map[string]float64{}
	for _, r := range res {
		m, ok := r.(*pyvalue.Map)
		if !ok {
			return nil, &pyError{"TypeError", "a sample is not a JSON object"}
		}
		k := pyvalue.Str(rundoc.MapOr(m.Value("metric")).GetOr(key, ""))
		val := rundoc.List(m.Value("value"))
		if len(val) < 2 {
			return nil, &pyError{"IndexError", "list index out of range"}
		}
		f, err := pyvalue.ToFloat(val[1])
		if err != nil {
			var pe *pyvalue.Error
			if errors.As(err, &pe) {
				return nil, &pyError{pe.Type, pe.Msg}
			}
			return nil, &pyError{"ValueError", err.Error()}
		}
		out[k] = f
	}
	return out, nil
}
