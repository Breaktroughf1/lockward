package exitcode

import (
	"errors"
	"fmt"
	"testing"
)

func TestFrom(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want Code
	}{
		{"nil is clean", nil, Clean},
		{"plain error is internal", errors.New("boom"), Internal},
		{"carried code", New(Drift, "drift in %s", "x"), Drift},
		{"wrapped carried code", fmt.Errorf("ctx: %w", New(Usage, "bad flag")), Usage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := From(tt.err); got != tt.want {
				t.Errorf("From() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDocumentedValues pins the PRD §8 numbering so it cannot change silently.
func TestDocumentedValues(t *testing.T) {
	want := map[Code]int{Clean: 0, Drift: 1, Policy: 2, Usage: 3, Internal: 4}
	for c, v := range want {
		if int(c) != v {
			t.Errorf("%v = %d, want %d", c, int(c), v)
		}
	}
}

func TestErrorMessage(t *testing.T) {
	if got := New(Policy, "rule %s", "LW001").Error(); got != "rule LW001" {
		t.Errorf("Error() = %q", got)
	}
	if got := (&Error{Code: Drift}).Error(); got != "drift" {
		t.Errorf("Error() with nil Err = %q", got)
	}
	inner := errors.New("inner")
	if !errors.Is(&Error{Code: Internal, Err: inner}, inner) {
		t.Error("Unwrap does not expose inner error")
	}
}
