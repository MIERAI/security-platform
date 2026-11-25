// Package flags parses the command lines of `sp` the way the reference (Python argparse) accepts them, so that
// every invocation that worked keeps working: options and positionals in any order, `--opt value` and
// `--opt=value`, long options abbreviated to any unique prefix, `--` before positionals that start with a dash,
// negative numbers as values, -h/--help anywhere.
package flags

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Kind is the type of an option's value.
type Kind int

// Option kinds.
const (
	Bool   Kind = iota // a switch, no value
	String             // one value
	Int                // one integer value (Python int(): sign, spaces, underscores)
)

// Option is one long option (`--name`).
type Option struct {
	Name    string // without the dashes
	Kind    Kind
	Choices []string // String: the allowed values (empty: any)
	Metavar string   // in the usage line (default: the name in capitals)
	Help    string
	Default int64 // Int: the value when the option is absent
}

// Positional is one positional argument.
type Positional struct {
	Name     string
	Variadic bool // zero or more values (only the last positional)
	Help     string
}

// Spec is one command's syntax.
type Spec struct {
	Prog        string // e.g. "sp findings"
	Summary     string
	Options     []Option
	Positionals []Positional
	Width       int // text width of usage and help (0: DefaultWidth)
}

// Result is a parsed command line.
type Result struct {
	Help  bool // -h/--help was given: print Spec.Help and exit 0
	set   map[string]bool
	str   map[string]string
	ints  map[string]int64
	args  map[string][]string
	order []string // positional names in order
}

// Bool reports whether a switch was given.
func (r *Result) Bool(name string) bool { return r.set[name] }

// String returns an option's value, "" when absent.
func (r *Result) String(name string) string { return r.str[name] }

// Int returns an integer option's value (its default when absent).
func (r *Result) Int(name string) int64 { return r.ints[name] }

// Arg returns the value of a single positional.
func (r *Result) Arg(name string) string {
	if v := r.args[name]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// Args returns the values of a variadic positional.
func (r *Result) Args(name string) []string { return slices.Clone(r.args[name]) }

// UsageError is a command line the spec does not accept; the message is argparse's wording.
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

func usageErr(format string, args ...any) error {
	return &UsageError{Msg: fmt.Sprintf(format, args...)}
}

// negativeNumber is a value that looks like an option but is a number (argparse: '^-\d+$|^-\d*\.\d+$').
var negativeNumber = regexp.MustCompile(`^-\d+$|^-\d*\.\d+$`)

func looksLikeOption(s string) bool {
	return strings.HasPrefix(s, "-") && s != "-" && !negativeNumber.MatchString(s)
}

// Parse parses args (after the command name).
func Parse(spec *Spec, args []string) (*Result, error) {
	r := &Result{set: map[string]bool{}, str: map[string]string{}, ints: map[string]int64{}, args: map[string][]string{}}
	for _, o := range spec.Options {
		if o.Kind == Int {
			r.ints[o.Name] = o.Default
		}
	}
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			pos = append(pos, args[i+1:]...)
			i = len(args)
		case a == "-h":
			r.Help = true
			return r, nil
		case strings.HasPrefix(a, "--") && len(a) > 2:
			next, err := parseLong(spec, r, args, i)
			if err != nil || r.Help {
				return r, err
			}
			i = next
		case looksLikeOption(a):
			return nil, usageErr("unrecognized arguments: %s", a)
		default:
			pos = append(pos, a)
		}
	}
	return r, assign(spec, r, pos)
}

// parseLong handles args[i] = --name[=value]; it returns the index of the last argument it consumed.
func parseLong(spec *Spec, r *Result, args []string, i int) (int, error) {
	name, val, hasVal := strings.Cut(args[i][2:], "=")
	o, err := lookup(spec, name, args[i])
	if err != nil {
		return i, err
	}
	if o == nil { // --help
		r.Help = true
		return i, nil
	}
	if o.Kind == Bool {
		if hasVal {
			return i, usageErr("argument --%s: ignored explicit argument %s", o.Name, pyvalue.Repr(val))
		}
		r.set[o.Name] = true
		return i, nil
	}
	if !hasVal {
		if i+1 >= len(args) || looksLikeOption(args[i+1]) {
			return i, usageErr("argument --%s: expected one argument", o.Name)
		}
		i++
		val = args[i]
	}
	return i, store(r, o, val)
}

// lookup finds the option a --name (or a unique prefix of it) means; nil for --help.
func lookup(spec *Spec, name, arg string) (*Option, error) {
	var hits []string
	byName := map[string]*Option{}
	for k := range spec.Options {
		o := &spec.Options[k]
		if o.Name == name {
			return o, nil
		}
		if strings.HasPrefix(o.Name, name) {
			hits = append(hits, "--"+o.Name)
			byName["--"+o.Name] = o
		}
	}
	if strings.HasPrefix("help", name) { //nolint:gocritic // argOrder: is name a prefix of "help" (an abbreviation)
		hits = append([]string{"--help"}, hits...)
	}
	switch {
	case len(hits) == 1:
		return byName[hits[0]], nil // nil for --help
	case len(hits) > 1:
		return nil, usageErr("ambiguous option: %s could match %s", arg, strings.Join(hits, ", "))
	}
	return nil, usageErr("unrecognized arguments: %s", arg)
}

func store(r *Result, o *Option, val string) error {
	switch o.Kind {
	case Int:
		n, err := pyvalue.ParseInt(val, 10)
		if err != nil {
			return usageErr("argument --%s: invalid int value: %s", o.Name, pyvalue.Repr(val))
		}
		r.ints[o.Name] = n
	case String:
		if len(o.Choices) > 0 && !slices.Contains(o.Choices, val) {
			return usageErr("argument --%s: invalid choice: %s (choose from %s)", o.Name, pyvalue.Repr(val),
				strings.Join(o.Choices, ", "))
		}
		r.str[o.Name] = val
	case Bool:
		return errors.New("flags: a switch takes no value") // not reached: parseLong handles switches
	}
	r.set[o.Name] = true
	return nil
}

// assign distributes the positional values: one for each required positional in order, the rest to a variadic
// last one.
func assign(spec *Spec, r *Result, pos []string) error {
	var missing []string
	for _, p := range spec.Positionals {
		r.order = append(r.order, p.Name)
		switch {
		case p.Variadic:
			r.args[p.Name] = pos
			pos = nil
		case len(pos) > 0:
			r.args[p.Name] = pos[:1]
			pos = pos[1:]
		default:
			missing = append(missing, p.Name)
		}
	}
	if len(missing) > 0 {
		return usageErr("the following arguments are required: %s", strings.Join(missing, ", "))
	}
	if len(pos) > 0 {
		return usageErr("unrecognized arguments: %s", strings.Join(pos, " "))
	}
	return nil
}

// DefaultWidth is the text width of usage and help (argparse: the terminal's columns, 80 by default, minus 2).
const DefaultWidth = 78

// maxHelpPosition is the column where option help starts at the latest (argparse's max_help_position).
const maxHelpPosition = 24

func (s *Spec) width() int {
	if s.Width > 0 {
		return s.Width
	}
	return DefaultWidth
}

// usageParts are the synopsis items of the options and of the positionals.
func (s *Spec) usageParts() (opts, pos []string) {
	opts = []string{"[-h]"}
	for _, o := range s.Options {
		if o.Kind == Bool {
			opts = append(opts, "[--"+o.Name+"]")
		} else {
			opts = append(opts, "[--"+o.Name+" "+o.valueName()+"]")
		}
	}
	for _, p := range s.Positionals {
		if p.Variadic {
			pos = append(pos, "["+p.Name+" ...]")
		} else {
			pos = append(pos, p.Name)
		}
	}
	return opts, pos
}

// Usage is the synopsis, wrapped as argparse wraps it.
func (s *Spec) Usage() string {
	opts, pos := s.usageParts()
	return FormatUsage(s.Prog, opts, pos, s.width())
}

// FormatUsage lays out "usage: PROG OPTS POS" like argparse: one line when it fits the width, else the options and
// then the positionals wrapped under the first one.
func FormatUsage(prog string, opts, pos []string, width int) string {
	const prefix = "usage: "
	all := append(append([]string{prog}, opts...), pos...)
	if one := strings.Join(all, " "); len(prefix)+len(one) <= width {
		return prefix + one
	}
	indent := strings.Repeat(" ", len(prefix)+len(prog)+1)
	var lines []string
	if len(opts) > 0 {
		lines = wrapParts(append([]string{prog}, opts...), indent, len(prefix), width)
		lines[0] = strings.TrimPrefix(lines[0], indent)
		lines = append(lines, wrapParts(pos, indent, len(indent), width)...)
	} else {
		lines = wrapParts(append([]string{prog}, pos...), indent, len(prefix), width)
		lines[0] = strings.TrimPrefix(lines[0], indent)
	}
	return prefix + strings.Join(lines, "\n")
}

// wrapParts is argparse's get_lines: greedy lines of space-separated parts, each starting with indent.
func wrapParts(parts []string, indent string, start, width int) []string {
	var lines, line []string
	n := start - 1
	for _, p := range parts {
		if n+1+len(p) > width && len(line) > 0 {
			lines = append(lines, indent+strings.Join(line, " "))
			line, n = nil, len(indent)-1
		}
		line = append(line, p)
		n += len(p) + 1
	}
	if len(line) > 0 {
		lines = append(lines, indent+strings.Join(line, " "))
	}
	return lines
}

// valueName is how an option's value is shown: {a,b,...} for choices, else the metavar.
func (o *Option) valueName() string {
	if len(o.Choices) > 0 {
		return "{" + strings.Join(o.Choices, ",") + "}"
	}
	if o.Metavar != "" {
		return o.Metavar
	}
	return strings.ToUpper(o.Name)
}

// Help is the full help text, laid out as argparse lays it out: synopsis, positional arguments, options.
func (s *Spec) Help() string {
	type item struct{ inv, help string }
	var pos, opts []item
	for _, p := range s.Positionals {
		pos = append(pos, item{p.Name, p.Help})
	}
	opts = append(opts, item{"-h, --help", "show this help message and exit"})
	for _, o := range s.Options {
		inv := "--" + o.Name
		if o.Kind != Bool {
			inv += " " + o.valueName()
		}
		opts = append(opts, item{inv, o.Help})
	}
	longest := 0
	for _, it := range append(append([]item(nil), pos...), opts...) {
		longest = max(longest, len(it.inv)+2)
	}
	col := min(longest+2, maxHelpPosition)
	var b strings.Builder
	b.WriteString(s.Usage() + "\n")
	if s.Summary != "" {
		b.WriteString("\n" + s.Summary + "\n")
	}
	section := func(title string, items []item) {
		if len(items) == 0 {
			return
		}
		b.WriteString("\n" + title + ":\n")
		for _, it := range items {
			b.WriteString(helpRow(it.inv, it.help, col))
		}
	}
	section("positional arguments", pos)
	section("options", opts)
	return b.String()
}

// helpRow is one argument's line(s): the help after the invocation when it fits before col, else on the next line.
func helpRow(inv, help string, col int) string {
	switch {
	case help == "":
		return "  " + inv + "\n"
	case len(inv) <= col-4:
		return "  " + inv + strings.Repeat(" ", col-2-len(inv)) + help + "\n"
	}
	return "  " + inv + "\n" + strings.Repeat(" ", col) + help + "\n"
}
