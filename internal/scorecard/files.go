package scorecard

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	pv "github.com/MIERAI/security-platform/internal/pyvalue"
)

// readFile reads a whole input file, at most maxInputFile bytes.
func readFile(path string) (data []byte, err error) {
	f, err := os.Open(path) // #nosec G304 -- the operator's own catalog, instance and data files
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close %s: %w", path, cerr)
		}
	}()
	data, err = io.ReadAll(io.LimitReader(f, maxInputFile+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxInputFile {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrConfig, path, maxInputFile)
	}
	return data, nil
}

// readYAMLFile reads a configuration file (YAML, which includes JSON).
func readYAMLFile(path string) (any, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	v, err := pv.DecodeYAML(normalizeNewlines(data))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrConfig, path, err)
	}
	return v, nil
}

// normalizeNewlines turns CRLF and lone CR line ends into LF, as text files are read.
func normalizeNewlines(data []byte) []byte {
	s := strings.ReplaceAll(string(data), "\r\n", "\n")
	return []byte(strings.ReplaceAll(s, "\r", "\n"))
}

// readJSONFile reads a data document; a missing, unreadable or malformed file gives def.
func readJSONFile(path string, def any) any {
	data, err := readFile(path)
	if err != nil {
		return def
	}
	v, err := pv.DecodeJSON(data)
	if err != nil {
		return def
	}
	return v
}

// orEmpty is a value that must be a mapping when it is truthy (`x or {}`): an empty mapping for a falsy value,
// false for a truthy non-mapping.
func orEmpty(v any) (*pv.Map, bool) {
	if !pv.Truthy(v) {
		return pv.NewMap(), true
	}
	m, ok := v.(*pv.Map)
	return m, ok
}

// section is m[key] as a mapping (`m.get(key) or {}`); a truthy non-mapping is a configuration error.
func section(m *pv.Map, key, where string) (*pv.Map, error) {
	s, ok := orEmpty(m.Value(key))
	if !ok {
		return nil, configErr("%s%s must be a mapping", where, key)
	}
	return s, nil
}

// jsonFiles lists dir/*.json (hidden files excluded), sorted; none when dir is missing.
func jsonFiles(dir, suffix string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, ".") && strings.HasSuffix(n, suffix) {
			out = append(out, filepath.Join(dir, n))
		}
	}
	return out
}

// fileExists reports whether path names an existing file or directory (symbolic links followed; any error
// counts as absent).
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
