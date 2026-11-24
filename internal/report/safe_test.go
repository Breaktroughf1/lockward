package report

import (
	"strings"
	"testing"
)

func TestSafe(t *testing.T) {
	for in, want := range map[string]string{
		"plain text: a/b.md":          "plain text: a/b.md",
		"héllo wörld ✓":               "héllo wörld ✓",
		"\x1b[2J\x1b[32mclean\x1b[0m": `\x1b[2J\x1b[32mclean\x1b[0m`,
		"line\n::error::spoofed":      `line\n::error::spoofed`,
		"a\rb\tc\x00d\x7f":            `a\rb\tc\x00d\x7f`,
		"\u009b31m":                   `\u{009b}31m`,
		"admin\u202e\u2066txt.exe":    `admin\u{202e}\u{2066}txt.exe`,
		"zero\u200bwidth\ufeff":       `zero\u{200b}width\u{feff}`,
		"bad \xff byte":               `bad \xff byte`,
	} {
		if got := Safe(in); got != want {
			t.Errorf("Safe(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzSafe(f *testing.F) {
	f.Add("\x1b[31mred\n::warning::x\u202e")
	f.Fuzz(func(t *testing.T, s string) {
		out := Safe(s)
		for _, r := range out {
			if r < 0x20 || r == 0x7f || unsafeRune(r) {
				t.Fatalf("Safe(%q) = %q still contains %U", s, out, r)
			}
		}
		if strings.ContainsRune(out, '\n') {
			t.Fatal("newline survived")
		}
	})
}
