package rundoc

import (
	"context"
	"fmt"
	"io"

	"github.com/MIERAI/security-platform/internal/textsafe"
)

// Collector is one Go collector behind the collector protocol.
type Collector struct {
	Name    string // the collector's own name (SP_COLLECTOR_NAME overrides it per run)
	Version string // collectors/<name>/VERSION
	// Collect runs one collection into run; gaps go into run.Doc, an error fails the run (ErrUsage: exit 2).
	// It writes nothing itself: the caller writes the document after it returns nil.
	Collect func(ctx context.Context, run *Run, env *Env) error
}

// Main is `sp <name> collect|version`: exit 0 done, 1 failed, 2 usage or configuration error.
func Main(ctx context.Context, c *Collector, args []string, env *Env, stdout io.Writer) int {
	usage := "usage: sp " + c.Name + " collect   run the " + c.Name +
		" collector (collector protocol: SP_RUN_DIR, SP_INSTANCE, SP_DATA, SP_INPUT_DIR)\n" +
		"       sp " + c.Name + " version   print the collector's version"
	switch {
	case len(args) == 1 && args[0] == "collect":
		err := collect(ctx, c, env)
		if err != nil {
			_, _ = fmt.Fprintln(env.Errout(), "sp "+c.Name+" collect: "+textsafe.Line(err.Error())) // the status says it too
		}
		return ExitStatus(err)
	case len(args) == 1 && args[0] == "version":
		if _, err := fmt.Fprintln(stdout, c.Version); err != nil {
			return 1
		}
		return 0
	default:
		_, _ = fmt.Fprintln(env.Errout(), usage) // nowhere else to report a failed write
		return 2
	}
}

func collect(ctx context.Context, c *Collector, env *Env) error {
	run, err := Start(env, c.Name, c.Version)
	if err != nil {
		return err
	}
	if err := c.Collect(ctx, run, env); err != nil {
		return err
	}
	return run.Doc.Write(run.Dir, env.Errout())
}
