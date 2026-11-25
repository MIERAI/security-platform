package events

import (
	"errors"
	"os"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// pyError is a source failure as the reference reports it in the summary and the log: the Python exception class
// and its message ("RuntimeError: command rc=1: ..."), so that summaries read the same whichever shipper ran.
type pyError struct{ typ, msg string }

func (e *pyError) Error() string { return e.typ + ": " + e.msg }

func pyErr(typ, msg string) error { return &pyError{typ: typ, msg: msg} }

func keyError(key string) error { return pyErr("KeyError", pyvalue.Repr(key)) }

// describe is f"{type(e).__name__}: {str(e)[:200]}".
func describe(err error) string {
	var pe *pyError
	if errors.As(err, &pe) {
		return pe.typ + ": " + rundoc.Cut(pe.msg, 200)
	}
	return "RuntimeError: " + rundoc.Cut(err.Error(), 200)
}

// osError names an operating-system error as Python's OSError subclasses do.
func osError(err error, path string) error {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return pyErr("FileNotFoundError", "[Errno 2] No such file or directory: "+pyvalue.Repr(path))
	case errors.Is(err, os.ErrPermission):
		return pyErr("PermissionError", "[Errno 13] Permission denied: "+pyvalue.Repr(path))
	}
	return pyErr("OSError", err.Error())
}
