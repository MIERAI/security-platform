package scorecard

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	pv "github.com/MIERAI/security-platform/internal/pyvalue"
)

// gitTimeout bounds the git call that finds when an evidence file was last reviewed.
const gitTimeout = 10 * time.Second

// evalFile checks an evidence document: it exists (relative paths are in the product tree); with max_age it was
// changed (git commit date, else modification time) within max_age; with contains its text matches the regular
// expression (multi-line); with mode_max its permission bits are within that octal mode.
func evalFile(e *evaluator, src *pv.Map) (outcome, error) {
	raw, err := item(src, "path")
	if err != nil {
		return outcome{}, err
	}
	shown, ok := raw.(string)
	if !ok {
		return outcome{}, pv.TypeError("expected str, bytes or os.PathLike object, not " + pv.TypeName(raw))
	}
	p := expandUser(shown, e.home)
	if !filepath.IsAbs(p) {
		p = filepath.Join(e.product, p)
	}
	if !fileExists(p) {
		return outcome{"fail", shown + " missing"}, nil
	}
	var notes []string
	for _, check := range []fileCheck{fileAge, fileText, fileMode} {
		note, failure, err := check(e, p, shown, src)
		if err != nil || failure != "" {
			return outcome{"fail", failure}, err
		}
		if note != "" {
			notes = append(notes, note)
		}
	}
	if len(notes) > 0 {
		return outcome{"pass", shown + " present (" + strings.Join(notes, ", ") + ")"}, nil
	}
	return outcome{"pass", shown + " present"}, nil
}

// fileCheck is one of the evidence checks: a note for the pass detail, or the failure.
type fileCheck func(e *evaluator, path, shown string, src *pv.Map) (note, failure string, err error)

func fileAge(e *evaluator, p, shown string, src *pv.Map) (note, failure string, err error) {
	maxAge := src.Value("max_age")
	if !pv.Truthy(maxAge) {
		return "", "", nil
	}
	changed, lerr := e.lastChanged(p)
	if lerr != nil {
		return "", "", lerr
	}
	age := e.now - changed
	limit, derr := duration(maxAge, 0)
	if derr != nil {
		return "", "", derr
	}
	if age > limit {
		return "", shown + " not reviewed for " + ageText(age) + " (max " + pv.Str(maxAge) + ")", nil
	}
	return "changed " + ageText(age) + " ago", "", nil
}

// lastChanged is the git commit time of the path when it is in a git work tree, else its modification time.
func (e *evaluator) lastChanged(p string) (float64, error) {
	dir := filepath.Dir(p)
	if fi, err := os.Stat(p); err == nil && fi.IsDir() {
		dir = p
	}
	if out := strings.TrimFunc(e.gitLog(e.ctx, dir, p), isSpace); out != "" {
		return pv.ToFloat(out)
	}
	fi, err := os.Stat(p)
	if err != nil {
		return 0, &pv.Error{Type: "OSError", Msg: err.Error()}
	}
	t := fi.ModTime()
	return float64(t.Unix()) + float64(t.Nanosecond())*1e-9, nil
}

func fileText(_ *evaluator, p, shown string, src *pv.Map) (note, failure string, err error) {
	pattern := src.Value("contains")
	if !pv.Truthy(pattern) {
		return "", "", nil
	}
	text := ""
	if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
		data, rerr := readFile(p)
		if rerr != nil {
			return "", "", &pv.Error{Type: "OSError", Msg: rerr.Error()}
		}
		text = string(normalizeNewlines(decodeReplacing(data)))
	}
	re, cerr := regexp.Compile(`(?m)` + pv.Str(pattern))
	if cerr != nil {
		return "", "", &pv.Error{Type: "error", Msg: cerr.Error()}
	}
	if !re.MatchString(text) {
		return "", shown + " lacks /" + pv.Str(pattern) + "/", nil
	}
	return "", "", nil
}

// decodeReplacing replaces every byte that is not part of valid UTF-8 with U+FFFD.
func decodeReplacing(data []byte) []byte {
	if utf8.Valid(data) {
		return data
	}
	out := make([]byte, 0, len(data))
	for len(data) > 0 {
		r, n := utf8.DecodeRune(data)
		out = utf8.AppendRune(out, r)
		data = data[n:]
	}
	return out
}

func fileMode(_ *evaluator, p, shown string, src *pv.Map) (note, failure string, err error) {
	limit := src.Value("mode_max")
	if !pv.Truthy(limit) {
		return "", "", nil
	}
	fi, serr := os.Stat(p)
	if serr != nil {
		return "", "", &pv.Error{Type: "OSError", Msg: serr.Error()}
	}
	mode := int64(fi.Mode().Perm())
	allowed, perr := pv.ParseInt(pv.Str(limit), 8)
	if perr != nil {
		return "", "", perr
	}
	text := "0o" + strconv.FormatInt(mode, 8)
	if mode&^allowed != 0 {
		return "", shown + " mode " + text + " exceeds " + pv.Str(limit), nil
	}
	return "mode " + text, "", nil
}

// RunGitLog asks git for the commit time of the last commit that touched path, with a time limit; "" when git
// is missing, fails or the path is not in a work tree.
func RunGitLog(ctx context.Context, dir, path string) string {
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	// #nosec G204 -- an argument vector, no shell; the path comes after "--"
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "log", "-1", "--format=%ct", "--", path)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(out)
}
