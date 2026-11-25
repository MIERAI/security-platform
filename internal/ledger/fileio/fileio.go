// Package fileio reads files through a size limit and writes them so that a reader never sees a partial one:
// a temporary file in the same directory, then a rename over the target (on Windows too: os.Rename replaces an
// existing file).
package fileio

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

// Write writes data to path through a temporary file in the same directory and a rename, mode 0600
// whatever the umask. A stale temporary file of an interrupted run is replaced.
func Write(path string, data []byte) error {
	return write(path, data, false)
}

// WriteDurable is Write plus a flush to stable storage before the rename: for the files that are the
// platform's memory (ledger.json, tracker/items.json), which a power loss must not leave empty.
func WriteDurable(path string, data []byte) error {
	return write(path, data, true)
}

func write(path string, data []byte, durable bool) error {
	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove stale %s: %w", tmp, err)
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- inside the data dir
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	_, werr := f.Write(data)
	var serr error
	if durable {
		serr = f.Sync()
	}
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return fmt.Errorf("write %s: %w", tmp, errors.Join(err, os.Remove(tmp)))
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// ErrTooLarge is returned for input longer than its limit.
var ErrTooLarge = errors.New("input exceeds its size limit")

// ReadLimited reads all of r, failing with ErrTooLarge beyond limit bytes.
func ReadLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, ErrTooLarge
	}
	return data, nil
}

// Read reads a whole file through a size limit. A missing file's error wraps fs.ErrNotExist.
func Read(path string, limit int64) (data []byte, err error) {
	f, err := os.Open(path) // #nosec G304 -- callers pass paths inside the operator's directories
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			data, err = nil, fmt.Errorf("close %s: %w", path, cerr)
		}
	}()
	data, err = ReadLimited(f, limit)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return data, nil
}
