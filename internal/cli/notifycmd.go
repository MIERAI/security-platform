package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/MIERAI/security-platform/internal/cli/flags"
	"github.com/MIERAI/security-platform/internal/notifier"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// maxNotifyErr bounds a failure message (characters).
const maxNotifyErr = 160

func runNotify(ctx context.Context, s *session, a *flags.Result) (int, error) {
	if err := s.locate(); err != nil {
		return 0, err
	}
	inst, err := s.instance()
	if err != nil {
		return 0, err
	}
	var cfgs []any
	if v := inst.Value("notify"); pyvalue.Truthy(v) {
		cfgs = pyvalue.AsList(v)
	}
	if len(cfgs) == 0 {
		return 0, die(ExitFail, "no notifiers configured (instance `notify:`; see docs/instance-reference.md)")
	}
	text, err := s.digest(a.Int("days"))
	if err != nil {
		return 0, err
	}
	if a.Bool("dry-run") {
		return ExitOK, emitf(s.env.Stdout, "%s\n\n(dry run: %d notifier(s) not called)\n", text, len(cfgs))
	}
	nenv := notifier.Env{Stdout: s.env.Stdout, Getenv: s.env.Getenv}
	rc := ExitOK
	for i, c := range cfgs {
		cfg, _ := c.(*pyvalue.Map)
		name := fmt.Sprintf("%d-%s", i, str(field(cfg, "type")))
		// one failing notifier must not stop the others; the message never holds a secret (package notifier)
		if serr := notifier.Send(ctx, nenv, cfg, text); serr != nil {
			rc = ExitFail
			if err := emitf(s.env.Stderr, "notifier %s failed: %s\n", name, safe(head(reason(serr), maxNotifyErr))); err != nil {
				return rc, err
			}
			continue
		}
		if err := emitf(s.env.Stdout, "sent via %s\n", name); err != nil {
			return rc, err
		}
	}
	return rc, nil
}

// reason is an error without the notifier package's class prefix.
func reason(err error) string {
	msg := err.Error()
	for _, class := range []error{notifier.ErrConfig, notifier.ErrDelivery} {
		if errors.Is(err, class) {
			msg = strings.TrimPrefix(msg, class.Error()+": ")
		}
	}
	return msg
}
