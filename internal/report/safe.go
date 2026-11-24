package report

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Safe makes untrusted text inert for terminals and CI logs. Paths, ids,
// commands and file contents come from scanned repositories; printed raw,
// escape sequences could clear the screen or fake a "clean" result, a newline
// could inject GitHub Actions workflow commands ("::error::"), and
// bidirectional or invisible characters could disguise text ("Trojan
// Source"). Such characters are shown as visible escapes instead.
func Safe(s string) string {
	if isPlain(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case unsafeRune(r):
			fmt.Fprintf(&b, `\u{%04x}`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

func isPlain(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

// unsafeRune reports C1 controls, bidirectional controls and invisible
// formatting characters.
func unsafeRune(r rune) bool {
	switch {
	case r >= 0x80 && r <= 0x9f: // C1 controls (CSI 0x9b, OSC 0x9d, ...)
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x200e, r == 0x200f, r == 0x061c: // bidi
		return true
	case r >= 0x200b && r <= 0x200d, r == 0x2060, r == 0xfeff, r == 0x2028, r == 0x2029, r == 0x00ad: // invisible
		return true
	}
	return false
}
