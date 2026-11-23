package main

import (
	"flag"
	"fmt"
	"slices"
	"strings"
)

// parseInterspersed parses fs from args, allowing flags before and after
// positional arguments (PRD §8 shows "scan-repo <path> [--format ...]").
// A literal "--" ends flag parsing; everything after it is positional.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		consumed := len(args) - len(rest)
		if consumed > 0 && args[consumed-1] == "--" {
			return append(pos, rest...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// enumValue is a string flag restricted to a fixed set of values, so an
// invalid value is reported as a usage error during parsing.
type enumValue struct {
	allowed []string
	value   string
}

func newEnum(fs *flag.FlagSet, name, def, usage string, allowed ...string) *enumValue {
	e := &enumValue{allowed: allowed, value: def}
	// Backquotes make flag.PrintDefaults show the allowed values as the placeholder.
	fs.Var(e, name, fmt.Sprintf("%s (`%s`)", usage, strings.Join(allowed, "|")))
	return e
}

func (e *enumValue) String() string {
	if e == nil {
		return ""
	}
	return e.value
}

func (e *enumValue) Set(s string) error {
	if !slices.Contains(e.allowed, s) {
		return fmt.Errorf("must be one of %s", strings.Join(e.allowed, ", "))
	}
	e.value = s
	return nil
}
