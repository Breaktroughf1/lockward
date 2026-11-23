package textscan

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
)

type hit struct {
	line int
	text string
}

func collect(t *testing.T, input string, needle string) []hit {
	t.Helper()
	var out []hit
	err := Scan(strings.NewReader(input), func(b []byte) bool { return bytes.Contains(b, []byte(needle)) },
		func(n int, b []byte) {
			if bytes.Contains(b, []byte(needle)) {
				out = append(out, hit{n, string(b)})
			}
		})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLineNumbersAcrossBlocks(t *testing.T) {
	var sb strings.Builder
	for i := 1; i <= 20000; i++ {
		if i == 7 || i == 15000 || i == 20000 {
			sb.WriteString("NEEDLE here\n")
		} else {
			sb.WriteString("filler line of text\n")
		}
	}
	got := collect(t, sb.String(), "NEEDLE")
	want := []hit{{7, "NEEDLE here"}, {15000, "NEEDLE here"}, {20000, "NEEDLE here"}}
	if !slices.Equal(got, want) {
		t.Errorf("hits = %v, want %v", got, want)
	}
}

func TestNoTrailingNewline(t *testing.T) {
	if got := collect(t, "a\nb\nlast NEEDLE", "NEEDLE"); !slices.Equal(got, []hit{{3, "last NEEDLE"}}) {
		t.Errorf("hits = %v", got)
	}
	if got := collect(t, "", "x"); got != nil {
		t.Errorf("empty input hits = %v", got)
	}
}

// TestPaddedLongLine: a needle after many megabytes on one line, and one
// straddling a block boundary, are both found.
func TestPaddedLongLine(t *testing.T) {
	long := strings.Repeat(" ", 5<<20) + "NEEDLE at the end\n"
	if got := collect(t, long, "NEEDLE"); len(got) == 0 || got[0].line != 1 {
		t.Errorf("padded needle not found: %v", len(got))
	}
	straddle := strings.Repeat("x", BlockSize-3) + "NEEDLE" + strings.Repeat("y", 3*BlockSize) + "\n"
	if got := collect(t, straddle, "NEEDLE"); len(got) == 0 {
		t.Error("needle straddling a window boundary not found")
	}
}

func TestPrefilterSkipsBlocks(t *testing.T) {
	calls := 0
	err := Scan(strings.NewReader(strings.Repeat("nothing to see\n", 50000)),
		func([]byte) bool { return false },
		func(int, []byte) { calls++ })
	if err != nil || calls != 0 {
		t.Errorf("line called %d times with a rejecting prefilter (err %v)", calls, err)
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestReadError(t *testing.T) {
	if err := Scan(failReader{}, func([]byte) bool { return true }, func(int, []byte) {}); err == nil {
		t.Error("read error not returned")
	}
	_ = io.EOF
}
