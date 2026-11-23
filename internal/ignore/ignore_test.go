package ignore

import "testing"

func TestMatch(t *testing.T) {
	m, err := Parse([]byte(`# comment

*.log
!keep.log
build/
/root-only.txt
docs/**/*.tmp
**/.git/
a?c
[ab]x
[!z]y
\#hash
`))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path  string
		isDir bool
		want  bool
	}{
		{"x.log", false, true},
		{"deep/dir/x.log", false, true},
		{"keep.log", false, false},
		{"build", true, true},
		{"build", false, false},
		{"build/out.bin", false, true},
		{"sub/build/out.bin", false, true},
		{"root-only.txt", false, true},
		{"sub/root-only.txt", false, false},
		{"docs/a/b/c.tmp", false, true},
		{"docs/c.tmp", false, true},
		{"other/c.tmp", false, false},
		{"skills/s/.git/HEAD", false, true},
		{"abc", false, true},
		{"abbc", false, false},
		{"ax", false, true},
		{"cx", false, false},
		{"ay", false, true},
		{"zy", false, false},
		{"#hash", false, true},
		{"SKILL.md", false, false},
	}
	for _, tt := range tests {
		if got := m.Match(tt.path, tt.isDir); got != tt.want {
			t.Errorf("Match(%q, dir=%v) = %v, want %v", tt.path, tt.isDir, got, tt.want)
		}
	}
	if len(m.Patterns) != 10 {
		t.Errorf("patterns = %d, want 10: %q", len(m.Patterns), m.Patterns)
	}
}

func TestNilAndEmpty(t *testing.T) {
	var m *Matcher
	if m.Match("x", false) || !m.Empty() {
		t.Error("nil matcher must match nothing")
	}
	e, _ := Parse([]byte("# only comments\n"))
	if !e.Empty() || e.Match("x", false) {
		t.Error("comment-only file must match nothing")
	}
}

func TestParentDirIgnoredCannotBeReincluded(t *testing.T) {
	m, _ := Parse([]byte("vendor/\n!vendor/keep.md\n"))
	if !m.Match("vendor/keep.md", false) {
		t.Error("file inside an ignored directory must stay ignored (gitignore semantics)")
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"[abc\n", "!\n", "/\n"} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("Parse(%q) accepted", in)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add("*.log\n!a\n**/x/\n[a-z]?\n")
	f.Fuzz(func(_ *testing.T, s string) {
		m, err := Parse([]byte(s))
		if err != nil {
			return
		}
		_ = m.Match("a/b/c.log", false)
	})
}
