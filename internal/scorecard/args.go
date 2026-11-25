package scorecard

import (
	"errors"
	"fmt"
	"strings"
)

// The command line of the scorecard (SPEC §1), parsed the way the reference implementation parses it: options
// and positional arguments in any order, --opt=value or --opt value, a unique prefix of an option name, `--`
// ending the options, repeated --catalog collected, the last of other repeated options winning.

// Usage is the one-line synopsis printed with usage errors.
const Usage = "usage: scorecard [-h] [--data DATA] [--instance INSTANCE] [--now NOW] [--catalog CATALOG]\n" +
	"                 [--dimension DIMENSION] [--by BY] [--note NOTE] [--days DAYS] [--expires EXPIRES] [--false]\n" +
	"                 [--not-applicable NA]\n" +
	"                 {compute,attest,lint,list,version} [control]"

// ErrUsage is a malformed command line.
var ErrUsage = errors.New("usage error")

// ErrHelp is returned for -h / --help.
var ErrHelp = errors.New("help requested")

// Args is a parsed command line.
type Args struct {
	Command   string
	Control   string
	Data      string
	Instance  string
	Now       string
	Catalogs  []string
	Dimension string
	Values    map[string]string // the remaining options (by, note, days, expires, not-applicable)
	False     bool
}

func optionNames() []string {
	return []string{"--data", "--instance", "--now", "--catalog", "--dimension", "--by", "--note", "--days",
		"--expires", "--not-applicable", "--false", "--help"}
}

func commands() []string { return []string{"compute", "attest", "lint", "list", "version"} }

// ParseArgs parses the scorecard's arguments.
func ParseArgs(argv []string) (Args, error) {
	a := Args{Values: map[string]string{}}
	var positional []string
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			positional = append(positional, argv[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" || isNegativeNumber(arg) {
			positional = append(positional, arg)
			continue
		}
		n, err := a.option(argv, i)
		if err != nil {
			return a, err
		}
		i += n
	}
	err := a.positionals(positional)
	return a, err
}

// option applies the option at argv[i] and returns how many following arguments it used.
func (a *Args) option(argv []string, i int) (int, error) {
	name, value, inline := strings.Cut(argv[i], "=")
	if name == "-h" {
		name = "--help"
	}
	full, err := resolveOption(name)
	if err != nil {
		return 0, err
	}
	if full == "--help" || full == "--false" {
		if inline {
			return 0, fmt.Errorf("%w: argument %s: ignored explicit argument %q", ErrUsage, full, value)
		}
		if full == "--help" {
			return 0, ErrHelp
		}
		a.False = true
		return 0, nil
	}
	used := 0
	if !inline {
		if i+1 >= len(argv) || (strings.HasPrefix(argv[i+1], "-") && !isNegativeNumber(argv[i+1])) {
			return 0, fmt.Errorf("%w: argument %s: expected one argument", ErrUsage, full)
		}
		value, used = argv[i+1], 1
	}
	a.set(full, value)
	return used, nil
}

func (a *Args) set(name, value string) {
	switch name {
	case "--data":
		a.Data = value
	case "--instance":
		a.Instance = value
	case "--now":
		a.Now = value
	case "--catalog":
		a.Catalogs = append(a.Catalogs, value)
	case "--dimension":
		a.Dimension = value
	default:
		a.Values[strings.TrimPrefix(name, "--")] = value
	}
}

// resolveOption expands a unique prefix of an option name.
func resolveOption(name string) (string, error) {
	var matches []string
	for _, o := range optionNames() {
		if o == name {
			return o, nil
		}
		if strings.HasPrefix(o, name) && strings.HasPrefix(name, "--") && len(name) > 2 {
			matches = append(matches, o)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", fmt.Errorf("%w: unrecognized arguments: %s", ErrUsage, name)
	}
	return "", fmt.Errorf("%w: ambiguous option: %s could match %s", ErrUsage, name, strings.Join(matches, ", "))
}

func isNegativeNumber(s string) bool {
	if len(s) < 2 || s[0] != '-' {
		return false
	}
	dot := false
	for _, r := range s[1:] {
		switch {
		case r == '.' && !dot:
			dot = true
		case r < '0' || r > '9':
			return false
		}
	}
	return true
}

func (a *Args) positionals(p []string) error {
	if len(p) == 0 {
		return fmt.Errorf("%w: the following arguments are required: cmd", ErrUsage)
	}
	if !oneOfText(p[0], commands()) {
		return fmt.Errorf("%w: argument cmd: invalid choice: %q (choose from %s)", ErrUsage, p[0],
			strings.Join(commands(), ", "))
	}
	a.Command = p[0]
	if len(p) > 1 {
		a.Control = p[1]
	}
	if len(p) > 2 {
		return fmt.Errorf("%w: unrecognized arguments: %s", ErrUsage, strings.Join(p[2:], " "))
	}
	return nil
}

func oneOfText(s string, options []string) bool {
	for _, o := range options {
		if s == o {
			return true
		}
	}
	return false
}
