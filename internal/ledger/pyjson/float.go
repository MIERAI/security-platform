package pyjson

import (
	"math"
	"strconv"
	"strings"
)

// FloatRepr is Python's repr(float): the shortest digits that round-trip, positional between 1e-4 and 1e16
// (always with a fractional part), scientific outside it ("1e+16", "1.5e-05"); "inf", "-inf", "nan".
func FloatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	sci := strconv.FormatFloat(f, 'e', -1, 64) // [-]d[.ddd]e±XX
	mant, exp, _ := strings.Cut(sci, "e")
	e, err := strconv.Atoi(exp)
	if err != nil {
		return sci // unreachable: FormatFloat always writes a decimal exponent
	}
	sign := ""
	if strings.HasPrefix(mant, "-") {
		sign, mant = "-", mant[1:]
	}
	digits := strings.Replace(mant, ".", "", 1)
	if e < -4 || e >= 16 {
		return sign + sciRepr(digits, e)
	}
	return sign + fixedRepr(digits, e)
}

func sciRepr(digits string, e int) string {
	m := digits[:1]
	if len(digits) > 1 {
		m += "." + digits[1:]
	}
	es := "+"
	if e < 0 {
		es, e = "-", -e
	}
	ex := strconv.Itoa(e)
	if len(ex) < 2 {
		ex = "0" + ex
	}
	return m + "e" + es + ex
}

func fixedRepr(digits string, e int) string {
	if e < 0 {
		return "0." + strings.Repeat("0", -e-1) + digits
	}
	if len(digits) <= e+1 {
		return digits + strings.Repeat("0", e+1-len(digits)) + ".0"
	}
	return digits[:e+1] + "." + digits[e+1:]
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

// FormatG is Python's f"{x:g}" (six significant digits, trailing zeros removed).
func FormatG(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	return strconv.FormatFloat(f, 'g', 6, 64)
}

// Round is Python's round(x, n) for a float: the correctly rounded decimal (ties to even on the exact binary
// value), as a float.
func Round(f float64, n int) float64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return f
	}
	r, err := strconv.ParseFloat(strconv.FormatFloat(f, 'f', n, 64), 64)
	if err != nil {
		return f // unreachable for a finite input
	}
	return r
}
