package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/Breaktroughf1/lockward/internal/exitcode"
)

// env is what a command action may touch. It grows as commands are implemented.
type env struct {
	stdout io.Writer
	stderr io.Writer
}

// action runs a command after flags are parsed. It returns nil for a clean
// result or an error carrying an exitcode.Code.
type action func(e *env, args []string) error

// command describes one PRD §8 subcommand.
type command struct {
	name    string
	usage   string // synopsis after "lockward "
	summary string
	// define registers the command's flags on fs and returns its action.
	define func(fs *flag.FlagSet) action
}

// commands lists the v0.1 CLI surface from PRD §8, in documented order.
var commands = []*command{
	{
		name:    "init",
		usage:   "init",
		summary: "Write a default lockward.policy.yaml and .lockwardignore.",
		define: func(*flag.FlagSet) action {
			return func(_ *env, args []string) error {
				if err := noArgs(args); err != nil {
					return err
				}
				return notImplemented(5) // LW-FR-17
			}
		},
	},
	{
		name:    "lock",
		usage:   "lock [--scope user|project|all]",
		summary: "Discover agent assets and write lockward.lock.",
		define: func(fs *flag.FlagSet) action {
			newEnum(fs, "scope", "all", "which assets to lock", "user", "project", "all")
			return func(_ *env, args []string) error {
				if err := noArgs(args); err != nil {
					return err
				}
				return notImplemented(3) // LW-FR-03
			}
		},
	},
	{
		name:    "verify",
		usage:   "verify [--frozen] [--format text|json|sarif]",
		summary: "Compare live agent assets with the lockfile and evaluate policy.",
		define: func(fs *flag.FlagSet) action {
			fs.Bool("frozen", false, "fail on any difference from the lockfile")
			newEnum(fs, "format", "text", "output format", "text", "json", "sarif")
			return func(_ *env, args []string) error {
				if err := noArgs(args); err != nil {
					return err
				}
				return notImplemented(4) // LW-FR-08
			}
		},
	},
	{
		name:    "diff",
		usage:   "diff [<id>]",
		summary: "Show file-level and sentence-level changes since the lockfile.",
		define: func(*flag.FlagSet) action {
			return func(_ *env, args []string) error {
				if len(args) > 1 {
					return exitcode.New(exitcode.Usage, "accepts at most one entry id, got %d", len(args))
				}
				if err := nonEmpty(args); err != nil {
					return err
				}
				return notImplemented(4) // LW-FR-09
			}
		},
	},
	{
		name:    "approve",
		usage:   "approve <id>... | --all",
		summary: "Accept current state for the given lockfile entries.",
		define: func(fs *flag.FlagSet) action {
			all := fs.Bool("all", false, "approve every changed entry")
			return func(_ *env, args []string) error {
				switch {
				case *all && len(args) > 0:
					return exitcode.New(exitcode.Usage, "pass entry ids or --all, not both")
				case !*all && len(args) == 0:
					return exitcode.New(exitcode.Usage, "pass at least one entry id, or --all")
				}
				if err := nonEmpty(args); err != nil {
					return err
				}
				return notImplemented(4) // LW-FR-10
			}
		},
	},
	{
		name:    "status",
		usage:   "status",
		summary: "Print a one-line summary for prompts and scripts.",
		define: func(*flag.FlagSet) action {
			return func(_ *env, args []string) error {
				if err := noArgs(args); err != nil {
					return err
				}
				return notImplemented(4) // LW-FR-15
			}
		},
	},
	{
		name:    "scan-repo",
		usage:   "scan-repo <path> [--format text|json|sarif]",
		summary: "Report files an agent would auto-load from a repository, without executing anything.",
		define: func(fs *flag.FlagSet) action {
			newEnum(fs, "format", "text", "output format", "text", "json", "sarif")
			return func(_ *env, args []string) error {
				if len(args) != 1 {
					return exitcode.New(exitcode.Usage, "requires exactly one repository path, got %d", len(args))
				}
				if err := nonEmpty(args); err != nil {
					return err
				}
				return notImplemented(6) // LW-FR-12
			}
		},
	},
	{
		name:    "bom",
		usage:   "bom [--format cyclonedx]",
		summary: "Export an AI-BOM of locked agent assets.",
		define: func(fs *flag.FlagSet) action {
			newEnum(fs, "format", "cyclonedx", "output format", "cyclonedx")
			return func(_ *env, args []string) error {
				if err := noArgs(args); err != nil {
					return err
				}
				return notImplemented(6) // LW-FR-13
			}
		},
	},
	{
		name:    "version",
		usage:   "version",
		summary: "Print the lockward version.",
		define: func(*flag.FlagSet) action {
			return func(e *env, args []string) error {
				if err := noArgs(args); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(e.stdout, "lockward %s\n", resolveVersion()); err != nil {
					return fmt.Errorf("write version: %w", err)
				}
				return nil
			}
		},
	},
}

func lookup(name string) (*command, bool) {
	for _, c := range commands {
		if c.name == name {
			return c, true
		}
	}
	return nil, false
}

func noArgs(args []string) error {
	if len(args) > 0 {
		return exitcode.New(exitcode.Usage, "unexpected argument %q", args[0])
	}
	return nil
}

func nonEmpty(args []string) error {
	for _, a := range args {
		if a == "" {
			return exitcode.New(exitcode.Usage, "empty argument")
		}
	}
	return nil
}

// notImplemented is returned by stubbed commands. It deliberately maps to a
// non-zero exit code so a stub can never be mistaken for a clean result in CI.
func notImplemented(week int) error {
	return exitcode.New(exitcode.Internal, "not implemented yet (planned for roadmap week %d)", week)
}
