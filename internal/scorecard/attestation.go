package scorecard

import (
	pv "github.com/MIERAI/security-platform/internal/scorecard/pyvalue"
)

// expiringSoon: an attestation that expires within 14 days counts as expiring.
const expiringSoon = 14 * day

// outcome is an evaluation result: a status and its one-line detail.
type outcome struct {
	status, detail string
}

// attested is an attestation's verdict and the expiry it used (hasExpiry false when none).
type attested struct {
	outcome
	expires   float64
	hasExpiry bool
}

// attestationStatus decides an attested control from its attestation (SPEC §3.3).
func attestationStatus(c *Control, a any, now float64) (attested, error) {
	if !pv.Truthy(a) {
		q := c.raw.GetOr("question", c.get("title"))
		return attested{outcome: outcome{"unattested", "not attested: a human answers \"" + pv.Str(q) +
			"\" (scorecard.py attest)"}}, nil
	}
	m, ok := a.(*pv.Map)
	if !ok {
		return attested{}, pv.AttributeError(a, "get")
	}
	by := m.Value("attested_by")
	if !pv.Truthy(by) {
		return attested{outcome: outcome{"unattested", "attestation without attested_by is ignored"}}, nil
	}
	exp, has, err := attestationExpiry(c, m)
	if err != nil || !has {
		return attested{outcome: outcome{"unattested", "attestation without a date (at/expires) is ignored"}}, err
	}
	return attested{outcome: judge(m, pv.Str(by), exp, now), expires: exp, hasExpiry: true}, nil
}

// attestationExpiry is `expires`, else `at` + the control's validity; none without a date.
func attestationExpiry(c *Control, m *pv.Map) (float64, bool, error) {
	var at float64
	if v := m.Value("at"); pv.Truthy(v) {
		t, err := timestamp(v)
		if err != nil {
			return 0, false, err
		}
		at = t
	}
	if v := m.Value("expires"); pv.Truthy(v) {
		t, err := timestamp(v)
		return t, err == nil, err
	}
	if at == 0 {
		return 0, false, nil
	}
	if !c.raw.Has("validity") {
		return 0, false, pv.KeyError("validity")
	}
	d, err := duration(c.get("validity"), 0)
	if err != nil {
		return 0, false, err
	}
	if c.get("validity") == nil {
		return 0, false, pv.TypeError("unsupported operand type(s) for +: 'float' and 'NoneType'")
	}
	return at + d, true, nil
}

func judge(m *pv.Map, by string, exp, now float64) outcome {
	if exp <= now {
		return outcome{"expired", "attestation by " + by + " expired " + gmDate(exp) + ": re-attest"}
	}
	if v, ok := m.Value("value").(bool); ok && !v {
		d := "attested as NOT holding by " + by
		if note := m.Value("note"); pv.Truthy(note) {
			d += ": " + pv.Str(note)
		}
		return outcome{"fail", d}
	}
	soon := ""
	if exp-now < expiringSoon {
		soon = " (expires within 14 days)"
	}
	return outcome{"pass", "attested by " + by + " until " + gmDate(exp) + soon}
}

// humanNotApplicable is the reason of a human's not_applicable attestation that is still valid (nil
// otherwise) and who approved it.
func humanNotApplicable(a any, now float64) (reason, by any, err error) {
	if !pv.Truthy(a) {
		return nil, nil, nil
	}
	m, ok := a.(*pv.Map)
	if !ok {
		return nil, nil, configErr("an attestation is not a mapping: %s", pv.Repr(a))
	}
	na, by := m.Value("not_applicable"), m.Value("attested_by")
	if !pv.Truthy(na) || !pv.Truthy(by) || !pv.Truthy(m.Value("expires")) {
		return nil, nil, nil
	}
	exp, err := timestamp(m.Value("expires"))
	if err != nil {
		return nil, nil, configErr("attestation expires: %v", err)
	}
	if exp > now {
		return na, by, nil
	}
	return nil, nil, nil
}
