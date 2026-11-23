package hash

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}

func TestCanonicalizeJSON(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"sorted keys and indent", `{"b":1,"a":{"d":[1,2],"c":true}}`,
			"{\n  \"a\": {\n    \"c\": true,\n    \"d\": [\n      1,\n      2\n    ]\n  },\n  \"b\": 1\n}\n"},
		{"empty containers", `{"a":[],"b":{}}`, "{\n  \"a\": [],\n  \"b\": {}\n}\n"},
		{"null", `null`, "null\n"},
		{"numbers keep literal", `[1.0,1e3,-0]`, "[\n  1.0,\n  1e3,\n  -0\n]\n"},
		{"escapes", `"q\" b\\ n\n r\r t\t \u0001 \u007f <&> é  "`,
			"\"q\\\" b\\\\ n\\n r\\r t\\t \\u0001 \\u007f <&> é  \"\n"},
		{"bytewise key order", `{"b":0,"B":0,"a":0,"é":0}`, "{\n  \"B\": 0,\n  \"a\": 0,\n  \"b\": 0,\n  \"é\": 0\n}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CanonicalizeJSON([]byte(tt.in))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("got\n%s\nwant\n%s", got, tt.want)
			}
			again, err := CanonicalizeJSON(got)
			if err != nil || !bytes.Equal(again, got) {
				t.Errorf("not idempotent: %q, %v", again, err)
			}
		})
	}
}

func TestCanonicalizeJSONErrors(t *testing.T) {
	for name, in := range map[string]string{
		"invalid utf8":  "\"\xff\"",
		"trailing data": `{} {}`,
		"syntax":        `{"a":`,
		"too deep":      strings.Repeat("[", maxDepth+2) + strings.Repeat("]", maxDepth+2),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := CanonicalizeJSON([]byte(in)); err == nil {
				t.Error("expected error")
			}
		})
	}
	if _, err := CanonicalJSON(map[string]string{"k": "\xff"}); err == nil {
		t.Error("invalid UTF-8 in a Go string must fail, not be replaced")
	}
}

func TestCanonicalJSONStructTagsAndOrder(t *testing.T) {
	type s struct {
		Z string   `json:"z"`
		A []string `json:"a,omitempty"`
	}
	got, err := CanonicalJSON(s{Z: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "{\n  \"z\": \"x\"\n}\n" {
		t.Errorf("got %q", got)
	}
}

func TestObjectDigestStable(t *testing.T) {
	a, _ := Object(map[string]any{"x": 1, "y": []string{"a"}})
	b, _ := Object(map[string]any{"y": []string{"a"}, "x": 1})
	if a != b {
		t.Errorf("key order changed digest: %s vs %s", a, b)
	}
	c, _ := Object(map[string]any{"x": 2, "y": []string{"a"}})
	if a == c {
		t.Error("value change did not change digest")
	}
}

// zeroReader yields n zero bytes followed by tail, without allocating n bytes.
type zeroReader struct {
	n    int64
	tail []byte
}

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.n > 0 {
		k := min(int64(len(p)), z.n)
		clear(p[:k])
		z.n -= k
		return int(k), nil
	}
	if len(z.tail) == 0 {
		return 0, io.EOF
	}
	k := copy(p, z.tail)
	z.tail = z.tail[k:]
	return k, nil
}

// TestInvariant_PaddedFileFullyHashed covers US-7 / THREAT_MODEL T3: a payload
// after 22 MB of padding still changes the digest.
func TestInvariant_PaddedFileFullyHashed(t *testing.T) {
	const pad = 22 << 20
	d1, n1, err := Reader(&zeroReader{n: pad, tail: []byte("benign")})
	if err != nil {
		t.Fatal(err)
	}
	d2, _, _ := Reader(&zeroReader{n: pad, tail: []byte("evil!!")})
	if d1 == d2 {
		t.Fatal("payload after padding did not change digest")
	}
	if n1 != pad+6 {
		t.Errorf("size = %d, want %d", n1, pad+6)
	}
}

func TestSum(t *testing.T) {
	if got := SumString(""); got != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("SumString(\"\") = %s", got)
	}
}

func TestCheckPath(t *testing.T) {
	for p, ok := range map[string]bool{
		"a/b.md": true, "with space/é.txt": true, ".hidden": true,
		"bad\nname": false, "tab\there": false, "del\x7f": false, "\xff": false,
	} {
		if err := CheckPath(p); (err == nil) != ok {
			t.Errorf("CheckPath(%q) err = %v, want ok=%v", p, err, ok)
		}
		if err := CheckPath(p); err != nil && !errors.Is(err, ErrUnsafePath) {
			t.Errorf("CheckPath(%q) error not ErrUnsafePath: %v", p, err)
		}
	}
}

// writeTree creates files under root. Keys ending in "@x" are made executable.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		mode := os.FileMode(0o644)
		if before, ok := strings.CutSuffix(name, "@x"); ok {
			name, mode = before, 0o755
		}
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
}

func rootFS(t *testing.T, dir string) fs.FS {
	t.Helper()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r.FS()
}

func TestTreeDigestMatchesSpecFormat(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"skill/SKILL.md":         "# Skill\n",
		"skill/scripts/run.sh@x": "echo hi\n",
		"skill/.hidden":          "dot",
	})
	tree, err := TreeDigest(rootFS(t, dir), "skill", TreeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	runMode := "0755"
	if runtime.GOOS == "windows" {
		runMode = "0644"
	}
	want := sha(
		"f 0644 .hidden " + sha("dot") + "\n" +
			"f 0644 SKILL.md " + sha("# Skill\n") + "\n" +
			"f " + runMode + " scripts/run.sh " + sha("echo hi\n") + "\n")
	if tree.Digest != want {
		t.Errorf("digest = %s, want %s", tree.Digest, want)
	}
	if len(tree.Members) != 3 || tree.Members[0].Path != ".hidden" || tree.Members[2].Size != 8 {
		t.Errorf("members = %+v", tree.Members)
	}
}

// TestInvariant_AnyByteChangeChangesTreeDigest is THREAT_MODEL §6 invariant 3.
func TestInvariant_AnyByteChangeChangesTreeDigest(t *testing.T) {
	base := map[string]string{
		"s/SKILL.md":          "instructions",
		"s/data.bin":          "\x00\x01\x02",
		"s/archive.zip":       "PK\x03\x04zip",
		"s/__pycache__/x.pyc": "\x55\x0d\x0d\x0a",
	}
	digest := func(files map[string]string) string {
		dir := t.TempDir()
		writeTree(t, dir, files)
		tree, err := TreeDigest(rootFS(t, dir), "s", TreeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return tree.Digest
	}
	orig := digest(base)
	for name, content := range base {
		for i := range len(content) {
			mutated := map[string]string{}
			for k, v := range base {
				mutated[k] = v
			}
			b := []byte(content)
			b[i] ^= 0x01
			mutated[name] = string(b)
			if digest(mutated) == orig {
				t.Errorf("flipping byte %d of %s did not change the digest", i, name)
			}
		}
	}
	added := map[string]string{".evil": ""}
	for k, v := range base {
		added[k] = v
	}
	added["s/.evil"] = ""
	delete(added, ".evil")
	if digest(added) == orig {
		t.Error("adding an empty dotfile did not change the digest")
	}
	renamed := map[string]string{}
	for k, v := range base {
		renamed[k] = v
	}
	delete(renamed, "s/data.bin")
	renamed["s/data2.bin"] = base["s/data.bin"]
	if digest(renamed) == orig {
		t.Error("renaming a file did not change the digest")
	}
}

func TestTreeDigestModeChange(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("execute bits are not tracked on Windows")
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"s/run.sh": "x"})
	fsys := rootFS(t, dir)
	a, _ := TreeDigest(fsys, "s", TreeOptions{})
	if err := os.Chmod(filepath.Join(dir, "s", "run.sh"), 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := TreeDigest(fsys, "s", TreeOptions{})
	if a.Digest == b.Digest {
		t.Error("making a file executable did not change the digest")
	}
	if err := os.Chmod(filepath.Join(dir, "s", "run.sh"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := TreeDigest(fsys, "s", TreeOptions{})
	if a.Digest != c.Digest {
		t.Error("non-execute permission change altered the digest; modes must be normalised")
	}
}

func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

// TestInvariant_SymlinksRecordedNotFollowed is THREAT_MODEL §6 invariant 4.
func TestInvariant_SymlinksRecordedNotFollowed(t *testing.T) {
	outer := t.TempDir()
	if err := os.WriteFile(filepath.Join(outer, "secret.txt"), []byte("top secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(outer, "root")
	writeTree(t, dir, map[string]string{"s/SKILL.md": "x", "s/sub/a.txt": "a"})
	symlinkOrSkip(t, "../../secret.txt", filepath.Join(dir, "s", "leak"))
	symlinkOrSkip(t, "sub", filepath.Join(dir, "s", "loop"))

	tree, err := TreeDigest(rootFS(t, dir), "s", TreeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]Member{}
	for _, m := range tree.Members {
		byPath[m.Path] = m
	}
	leak := byPath["leak"]
	if leak.Kind != KindSymlink || leak.Target != "../../secret.txt" || leak.Digest != "" {
		t.Errorf("leak member = %+v, want recorded symlink", leak)
	}
	if _, ok := byPath["loop/a.txt"]; ok {
		t.Error("walk followed a directory symlink")
	}
	// Retargeting a symlink changes the digest.
	if err := os.Remove(filepath.Join(dir, "s", "leak")); err != nil {
		t.Fatal(err)
	}
	symlinkOrSkip(t, "../../other.txt", filepath.Join(dir, "s", "leak"))
	tree2, _ := TreeDigest(rootFS(t, dir), "s", TreeOptions{})
	if tree2.Digest == tree.Digest {
		t.Error("retargeting a symlink did not change the digest")
	}
}

// TestLineCannotBeForged checks that crafted names and targets cannot make
// two different trees produce the same digest input.
func TestLineCannotBeForged(t *testing.T) {
	a := []Member{{Path: "a b", Kind: KindSymlink, Mode: "0777", Target: "c"}}
	b := []Member{{Path: "a", Kind: KindSymlink, Mode: "0777", Target: "b c"}}
	if MembersDigest(a) == MembersDigest(b) {
		t.Error("symlink path/target split is ambiguous")
	}
	for _, m := range append(a, b...) {
		if strings.Count(m.Line(), "\n") != 1 {
			t.Errorf("line %q is not a single line", m.Line())
		}
	}
}

func TestTreeDigestIgnoreAndLimit(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"s/a": "1", "s/b": "2", "s/.git/HEAD": "ref", "s/.git/x": "y"})
	fsys := rootFS(t, dir)
	tree, err := TreeDigest(fsys, "s", TreeOptions{Ignore: func(p string, isDir bool) bool { return isDir && p == "s/.git" }})
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Members) != 2 || tree.Ignored != 1 {
		t.Errorf("members=%d ignored=%d, want 2 and 1", len(tree.Members), tree.Ignored)
	}
	_, err = TreeDigest(fsys, "s", TreeOptions{MaxMembers: 3})
	if !errors.Is(err, ErrTooManyMembers) {
		t.Errorf("err = %v, want ErrTooManyMembers", err)
	}
}

func TestTreeDigestErrors(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"file": "x"})
	fsys := rootFS(t, dir)
	if _, err := TreeDigest(fsys, "file", TreeOptions{}); err == nil {
		t.Error("hashing a file as a tree should fail")
	}
	if _, err := TreeDigest(fsys, "missing", TreeOptions{}); err == nil {
		t.Error("missing dir should fail")
	}
	if _, _, err := File(fsys, "missing"); err == nil {
		t.Error("missing file should fail")
	}
}

func TestTreeDigestRejectsUnsafeNames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("control characters are not valid in Windows file names")
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"s/ok": "x"})
	if err := os.WriteFile(filepath.Join(dir, "s", "evil\nf 0644 x"), nil, 0o644); err != nil {
		t.Skipf("cannot create file with newline: %v", err)
	}
	if _, err := TreeDigest(rootFS(t, dir), "s", TreeOptions{}); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("err = %v, want ErrUnsafePath", err)
	}
}

func TestSingleFileAndSymlinkedTree(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"skills/loose.md": "hello"})
	tree, err := SingleFile(rootFS(t, dir), "skills/loose.md")
	if err != nil {
		t.Fatal(err)
	}
	if want := sha("f 0644 loose.md " + sha("hello") + "\n"); tree.Digest != want {
		t.Errorf("digest = %s, want %s", tree.Digest, want)
	}
	if SymlinkedTreeDigest("a", tree.Digest) == SymlinkedTreeDigest("b", tree.Digest) {
		t.Error("symlink target not part of digest")
	}
	if SymlinkedTreeDigest("a", "") == SymlinkedTreeDigest("a", tree.Digest) {
		t.Error("tree digest not part of digest")
	}
}

func TestNormalizeMode(t *testing.T) {
	for m, want := range map[fs.FileMode]string{0o644: "0644", 0o600: "0644", 0o755: "0755", 0o744: "0755", 0o701: "0755"} {
		if got := NormalizeMode(m); got != want {
			t.Errorf("NormalizeMode(%o) = %s, want %s", m, got, want)
		}
	}
}

func FuzzCanonicalizeJSON(f *testing.F) {
	for _, s := range []string{`{}`, `[]`, `{"a":[1,"x",null,true]}`, `"\u0000"`, `1e999`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		out, err := CanonicalizeJSON(in)
		if err != nil {
			return
		}
		again, err := CanonicalizeJSON(out)
		if err != nil {
			t.Fatalf("canonical output does not re-parse: %v\n%s", err, out)
		}
		if !bytes.Equal(out, again) {
			t.Fatalf("not idempotent:\n%s\n%s", out, again)
		}
	})
}

func TestCanonicalJSONReplacementCharHandling(t *testing.T) {
	if _, err := CanonicalJSON("genuine � is fine"); err != nil {
		t.Errorf("genuine U+FFFD rejected: %v", err)
	}
	if _, err := CanonicalJSON(`literal � text`); err != nil {
		t.Errorf("escaped backslash sequence rejected: %v", err)
	}
	if _, err := CanonicalJSON("bad \xc3"); err == nil {
		t.Error("invalid UTF-8 accepted")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestReaderError(t *testing.T) {
	if _, _, err := Reader(errReader{}); err == nil {
		t.Error("read error not propagated")
	}
}

func TestValidUTF8Walk(t *testing.T) {
	type inner struct {
		S      string
		hidden string
	}
	type outer struct {
		P  *inner
		I  any
		A  [1]string
		M  map[string]int
		B  []byte
		NP *inner
	}
	good := outer{P: &inner{S: "ok", hidden: "\xff"}, I: "x", A: [1]string{"y"}, M: map[string]int{"k": 1}, B: []byte{0xff}}
	if _, err := CanonicalJSON(good); err != nil {
		t.Errorf("valid value rejected: %v", err)
	}
	for name, v := range map[string]any{
		"pointer": outer{P: &inner{S: "\xff"}},
		"iface":   outer{I: "\xff"},
		"array":   outer{A: [1]string{"\xff"}},
		"map key": outer{M: map[string]int{"\xff": 1}},
	} {
		if _, err := CanonicalJSON(v); err == nil {
			t.Errorf("%s: invalid UTF-8 accepted", name)
		}
	}
	if _, err := CanonicalJSON(make(chan int)); err == nil {
		t.Error("unmarshalable value accepted")
	}
	if _, err := Object(make(chan int)); err == nil {
		t.Error("Object accepted unmarshalable value")
	}
}

func TestSingleFileErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := SingleFile(rootFS(t, dir), "missing"); err == nil {
		t.Error("missing file accepted")
	}
}

func TestSymlinkMemberViaSingleFile(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"skills/real.md": "x"})
	symlinkOrSkip(t, "real.md", filepath.Join(dir, "skills", "link.md"))
	tree, err := SingleFile(rootFS(t, dir), "skills/link.md")
	if err != nil {
		t.Fatal(err)
	}
	if m := tree.Members[0]; m.Kind != KindSymlink || m.Target != "real.md" {
		t.Errorf("member = %+v", m)
	}
}
