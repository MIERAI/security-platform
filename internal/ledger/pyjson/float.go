package pyjson

import (
	"math"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// FloatRepr is Python's repr(float) ("14.0", "1e+16", "1.5e-05", "inf", "nan"): pyvalue.FloatRepr, the one
// implementation of the reference's number printing shared by the Go components.
func FloatRepr(f float64) string {
	return pyvalue.FloatRepr(f)
}

// FloatJSON is how json.dumps writes a float: repr, with NaN and the infinities as JavaScript literals.
func FloatJSON(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	return FloatRepr(f)
}

// FormatG is Python's f"{x:g}" (pyvalue.FormatG).
func FormatG(f float64) string {
	return pyvalue.FormatG(f)
}

// Round is Python's round(x, n) for a float (pyvalue.Round: the exact binary value, ties to even).
func Round(f float64, n int) float64 {
	return pyvalue.Round(f, n)
}
