//go:build unix

package runner

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// args is a parsed command line.
type args struct {
	cmd      string
	jobs     []string
	instance string
	data     string
	now      float64
	dir      string
	port     int
}

var errUsage = errors.New("usage")

func commands() map[string]bool {
	return map[string]bool{"tick": true, "run": true, "status": true, "metrics": true, "serve-metrics": true, "version": true}
}

// parseArgs parses options anywhere among the positional arguments (as argparse does); `--` ends the options.
func parseArgs(argv []string) (args, error) {
	a := args{port: 9851}
	var pos []string
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			pos = append(pos, argv[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			pos = append(pos, arg)
			continue
		}
		name, val, inline := strings.Cut(arg, "=")
		if !inline {
			if i+1 >= len(argv) {
				return a, fmt.Errorf("%w: %s needs a value", errUsage, name)
			}
			i++
			val = argv[i]
		}
		if err := a.set(name, val); err != nil {
			return a, err
		}
	}
	if len(pos) == 0 || !commands()[pos[0]] {
		return a, fmt.Errorf("%w: a command is required (tick, run, status, metrics, serve-metrics, version)", errUsage)
	}
	a.cmd, a.jobs = pos[0], pos[1:]
	err := a.check()
	return a, err
}

func (a *args) set(name, val string) error {
	switch name {
	case "--instance":
		a.instance = val
	case "--data":
		a.data = val
	case "--dir":
		a.dir = val
	case "--now", "--port":
		return a.setNumber(name, val)
	default:
		return fmt.Errorf("%w: unknown option %s (jobs are positional: JOB ...)", errUsage, name)
	}
	return nil
}

func (a *args) setNumber(name, val string) error {
	f, err := strconv.ParseFloat(val, 64)
	if name == "--now" {
		if err != nil || f < 0 || f > 1e12 {
			return fmt.Errorf("%w: --now wants epoch seconds, got %q", errUsage, val)
		}
		a.now = f
		return nil
	}
	p, err := strconv.Atoi(val)
	if err != nil || p < 0 || p > 65535 {
		return fmt.Errorf("%w: --port wants a port number, got %q", errUsage, val)
	}
	a.port = p
	return nil
}

func (a *args) check() error {
	switch a.cmd {
	case "version":
		return nil
	case "serve-metrics":
		if a.dir == "" {
			return fmt.Errorf("%w: serve-metrics needs --dir", errUsage)
		}
		return nil
	}
	if a.instance == "" || a.data == "" {
		return fmt.Errorf("%w: %s needs --instance and --data", errUsage, a.cmd)
	}
	if len(a.jobs) > 0 && (a.cmd == "status" || a.cmd == "metrics") {
		return fmt.Errorf("%w: %s takes no job names", errUsage, a.cmd)
	}
	return nil
}
