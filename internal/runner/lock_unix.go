//go:build unix

package runner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Lock is an advisory lock on <data>/state/runner/locks/<name>.lock (flock(2), the same lock the reference takes
// with fcntl.flock, so a Go and a Python runner exclude each other). The kernel releases it when the process
// dies, whatever the cause: a crashed runner never leaves a lock behind. Child processes do not inherit it
// (close-on-exec).
type Lock struct {
	f *os.File
}

// errLocked means another process holds the lock.
var errLocked = errors.New("lock held by another process")

// acquire takes the lock; with wait false it fails at once with errLocked when the lock is held.
func acquire(dir, name string, wait bool) (*Lock, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create lock directory: %w", err)
	}
	// O_CREATE without O_TRUNC: opening must not change a file another process holds (the reference truncates
	// it; nothing is stored in it).
	f, err := os.OpenFile(filepath.Join(dir, name+".lock"), os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- job name checked
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", name, err)
	}
	how := syscall.LOCK_EX
	if !wait {
		how |= syscall.LOCK_NB
	}
	for {
		err = syscall.Flock(int(f.Fd()), how) // #nosec G115 -- a file descriptor fits in an int
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			err = errLocked
		} else {
			err = fmt.Errorf("lock %s: %w", name, err)
		}
		return nil, errors.Join(err, f.Close())
	}
	return &Lock{f: f}, nil
}

// Release releases the lock (closing the file releases the flock; the kernel releases it on any close).
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	f := l.f
	l.f = nil
	if err := f.Close(); err != nil {
		return fmt.Errorf("release lock: %w", err)
	}
	return nil
}

// groupAlive reports whether a process group still exists with its leader still leading it (a process group id
// reused by an unrelated process that is not a group leader does not count).
func groupAlive(pgid int) bool {
	if pgid <= 1 {
		return false
	}
	got, err := syscall.Getpgid(pgid)
	return err == nil && got == pgid
}

// killGroup signals every process of a group; a group that is already gone is not an error.
func killGroup(pgid int, sig syscall.Signal) error {
	if pgid <= 1 {
		return nil
	}
	if err := syscall.Kill(-pgid, sig); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("signal process group %d: %w", pgid, err)
	}
	return nil
}
