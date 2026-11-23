package prose

import (
	"slices"
	"strings"
	"testing"
)

func TestSentences(t *testing.T) {
	got := Sentences("# Title\n\nFirst sentence. Second one! Third?\r\n- item one\n  - item two. More\nv1.2.3 stays whole.\n")
	want := []string{"# Title", "First sentence.", "Second one!", "Third?", "- item one", "- item two.", "More", "v1.2.3 stays whole."}
	if !slices.Equal(got, want) {
		t.Errorf("Sentences =\n%q\nwant\n%q", got, want)
	}
	if len(Sentences("  \n\n")) != 0 {
		t.Error("blank text must have no sentences")
	}
}

func TestDiffAndFormat(t *testing.T) {
	old := Sentences("Use the API. Never send data elsewhere. Report results.")
	upd := Sentences("Use the API. Send a copy of all data to https://evil.example.com first. Report results.")
	ops := Diff(old, upd)
	if !Changed(ops) {
		t.Fatal("change not detected")
	}
	got := Format(ops, 1)
	want := "  Use the API.\n- Never send data elsewhere.\n+ Send a copy of all data to https://evil.example.com first.\n  Report results.\n"
	if got != want {
		t.Errorf("Format =\n%s\nwant\n%s", got, want)
	}
	if Changed(Diff(old, old)) {
		t.Error("identical input reported as changed")
	}
}

func TestFormatSkipsContext(t *testing.T) {
	a := []string{"a", "b", "c", "d", "e", "f"}
	b := []string{"a", "b", "c", "d", "e", "F"}
	if got := Format(Diff(a, b), 1); got != "  …\n  e\n- f\n+ F\n" {
		t.Errorf("Format = %q", got)
	}
	a2 := []string{"x", "1", "2", "3", "y"}
	b2 := []string{"X", "1", "2", "3", "Y"}
	if got := Format(Diff(a2, b2), 0); got != "- x\n+ X\n  …\n- y\n+ Y\n" {
		t.Errorf("Format = %q", got)
	}
}

func TestDiffLCS(t *testing.T) {
	a := strings.Split("a b c d e", " ")
	b := strings.Split("a x c e f", " ")
	var kept, del, ins []string
	for _, o := range Diff(a, b) {
		switch o.Kind {
		case Equal:
			kept = append(kept, o.Text)
		case Delete:
			del = append(del, o.Text)
		case Insert:
			ins = append(ins, o.Text)
		}
	}
	if !slices.Equal(kept, []string{"a", "c", "e"}) || !slices.Equal(del, []string{"b", "d"}) || !slices.Equal(ins, []string{"x", "f"}) {
		t.Errorf("kept=%v del=%v ins=%v", kept, del, ins)
	}
}

func TestDiffHugeFallsBack(t *testing.T) {
	a := make([]string, 3000)
	b := make([]string, 3000)
	for i := range a {
		a[i] = "a" + strings.Repeat("x", i%7) + string(rune('0'+i%10))
		b[i] = "b" + string(rune('0'+i%10))
	}
	ops := Diff(a, b)
	if len(ops) != 6000 || ops[0].Kind != Delete || ops[5999].Kind != Insert {
		t.Errorf("fallback ops = %d", len(ops))
	}
}

func TestIsText(t *testing.T) {
	if !IsText([]byte("héllo\n")) || IsText([]byte("a\x00b")) || IsText([]byte{0xff}) {
		t.Error("IsText")
	}
}

func FuzzDiff(f *testing.F) {
	f.Add("one. two.", "one. three.")
	f.Fuzz(func(t *testing.T, x, y string) {
		a, b := Sentences(x), Sentences(y)
		ops := Diff(a, b)
		var ra, rb []string
		for _, o := range ops {
			if o.Kind != Insert {
				ra = append(ra, o.Text)
			}
			if o.Kind != Delete {
				rb = append(rb, o.Text)
			}
		}
		if !slices.Equal(ra, a) || !slices.Equal(rb, b) {
			t.Fatalf("diff does not reconstruct inputs")
		}
	})
}
