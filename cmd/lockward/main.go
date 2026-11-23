// Command lockward is an offline, cross-agent lockfile and policy gate for
// AI-agent assets. This package contains CLI wiring only (ADR-0005); all
// behaviour lives under internal/.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/exitcode"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the CLI with args (excluding the program name) and returns the
// process exit code documented in PRD §8.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return int(exitcode.Usage)
	}
	name, rest := args[0], args[1:]
	switch name {
	case "-h", "-help", "--help":
		printUsage(stdout)
		return int(exitcode.Clean)
	case "help":
		return runHelp(rest, stdout, stderr)
	}
	cmd, ok := lookup(name)
	if !ok {
		fmt.Fprintf(stderr, "lockward: unknown command %q\nRun 'lockward help' for usage.\n", name)
		return int(exitcode.Usage)
	}
	return runCommand(cmd, rest, stdout, stderr)
}

func runCommand(cmd *command, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet(cmd.name)
	action := cmd.define(fs)
	pos, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		printCommandUsage(stdout, cmd)
		return int(exitcode.Clean)
	}
	if err != nil {
		err = exitcode.New(exitcode.Usage, "%w", err)
	} else {
		err = action(&env{stdout: stdout, stderr: stderr}, pos)
	}
	code := exitcode.From(err)
	if err != nil {
		fmt.Fprintf(stderr, "lockward %s: %v\n", cmd.name, err)
		if code == exitcode.Usage {
			fmt.Fprintf(stderr, "Run 'lockward %s -h' for usage.\n", cmd.name)
		}
	}
	return int(code)
}

func runHelp(args []string, stdout, stderr io.Writer) int {
	switch len(args) {
	case 0:
		printUsage(stdout)
		return int(exitcode.Clean)
	case 1:
		cmd, ok := lookup(args[0])
		if !ok {
			fmt.Fprintf(stderr, "lockward help: unknown command %q\n", args[0])
			return int(exitcode.Usage)
		}
		printCommandUsage(stdout, cmd)
		return int(exitcode.Clean)
	default:
		fmt.Fprintln(stderr, "lockward help: accepts at most one command name")
		return int(exitcode.Usage)
	}
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("lockward "+name, flag.ContinueOnError)
	fs.SetOutput(io.Discard) // run prints errors and usage itself
	return fs
}

func printUsage(w io.Writer) {
	var b strings.Builder
	b.WriteString("Lockward: offline lockfile and policy gate for AI-agent assets.\n\n")
	b.WriteString("Usage:\n  lockward <command> [arguments]\n\nCommands:\n")
	for _, c := range commands {
		fmt.Fprintf(&b, "  %-10s %s\n", c.name, c.summary)
	}
	b.WriteString("\nExit codes: 0 clean, 1 drift, 2 policy violation, 3 usage/config error, 4 internal error.\n")
	b.WriteString("Run 'lockward help <command>' for details on a command.\n")
	_, _ = io.WriteString(w, b.String())
}

func printCommandUsage(w io.Writer, cmd *command) {
	fs := newFlagSet(cmd.name)
	cmd.define(fs)
	var b strings.Builder
	fmt.Fprintf(&b, "Usage: lockward %s\n\n%s\n", cmd.usage, cmd.summary)
	hasFlags := false
	fs.VisitAll(func(*flag.Flag) { hasFlags = true })
	if hasFlags {
		b.WriteString("\nFlags:\n")
		fs.SetOutput(&b)
		fs.PrintDefaults()
	}
	_, _ = io.WriteString(w, b.String())
}
