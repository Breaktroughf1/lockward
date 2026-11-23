// Package exitcode defines the process exit codes documented in PRD §8 and an
// error type that carries one, so internal packages can report an outcome
// without depending on the CLI.
package exitcode

import (
	"errors"
	"fmt"
)

// Code is a lockward process exit code.
type Code int

// Exit codes from PRD §8. They are part of the public interface; do not renumber.
const (
	Clean    Code = 0 // no drift, no policy violations
	Drift    Code = 1 // live state differs from the lockfile
	Policy   Code = 2 // a policy rule was violated
	Usage    Code = 3 // bad arguments or configuration
	Internal Code = 4 // unexpected failure inside lockward
)

// String returns a short name for the code.
func (c Code) String() string {
	switch c {
	case Clean:
		return "clean"
	case Drift:
		return "drift"
	case Policy:
		return "policy"
	case Usage:
		return "usage"
	case Internal:
		return "internal"
	default:
		return fmt.Sprintf("Code(%d)", int(c))
	}
}

// Error pairs an error with the exit code it should produce.
type Error struct {
	Code Code
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return e.Code.String()
	}
	return e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

// New returns an *Error with the given code and formatted message.
func New(code Code, format string, args ...any) error {
	return &Error{Code: code, Err: fmt.Errorf(format, args...)}
}

// From returns the exit code for err: Clean for nil, the carried code for an
// *Error anywhere in the chain, and Internal for any other error.
func From(err error) Code {
	if err == nil {
		return Clean
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return Internal
}
