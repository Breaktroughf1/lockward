package policy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/asset"
)

// Rule describes a built-in rule.
type Rule struct {
	ID      string
	Name    string
	Summary string
	Help    string // remediation guidance
	Default Severity
}

// Rules lists the built-in rules (PRD §6.1).
var Rules = []Rule{
	{"LW001", "unpinned-mcp-package", "MCP server launched from a package without an exact version or image digest",
		"Pin an exact version (npx pkg@1.2.3, uvx pkg==1.2.3) or an image digest (image@sha256:...).", SeverityError},
	{"LW002", "source-not-allowed", "Skill or MCP source is not in allow.sources",
		"Add the source to allow.sources in lockward.policy.yaml after review, or remove the asset.", SeverityError},
	{"LW003", "hook-executes-network", "Hook command or script invokes a network tool",
		"Remove network access from the hook, or add an exception with a reason after review.", SeverityError},
	{"LW004", "external-url-reference", "Prose instructs fetching or executing from a domain not in allow.domains",
		"Review the instruction; add the domain to allow.domains if it is trusted.", SeverityWarning},
	{"LW005", "secret-path-reference", "References credential stores such as ~/.ssh, ~/.aws, .env, keychains or browser profiles",
		"Confirm the reference is legitimate; otherwise remove the asset.", SeverityWarning},
	{"LW006", "executable-in-skill", "Skill contains a compiled, bytecode or binary executable, or an archive",
		"Remove the file, or add an exception with a reason after reviewing it.", SeverityError},
	{"LW007", "env-value-inline", "Secret written inline in an MCP or hook config instead of an environment reference",
		"Move the value to an environment variable and reference it (e.g. \"${API_KEY}\"); rotate the exposed secret.", SeverityError},
	{"LW008", "auto-approve-tools", "Agent settings auto-approve tools or commands without confirmation",
		"Remove the auto-approval, or narrow it to specific read-only tools.", SeverityError},
}

// RuleByID looks up a rule.
func RuleByID(id string) (Rule, bool) {
	for _, r := range Rules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

func ruleIDs() []string {
	out := make([]string, len(Rules))
	for i, r := range Rules {
		out[i] = r.ID
	}
	return out
}

// Finding is one policy violation.
type Finding struct {
	Rule        string
	Name        string
	Severity    Severity
	EntryID     string
	Path        string // file the finding points at, relative to the scope root
	Line        int    // 1-based; 0 when not applicable
	Message     string
	Remediation string
}

// Input is what Evaluate inspects.
type Input struct {
	FS      fs.FS
	Entries []asset.Entry
	Assets  map[string]*asset.Asset
}

// Result holds findings and the number suppressed by exceptions.
type Result struct {
	Findings   []Finding
	Suppressed int
}

// Errors counts error-severity findings.
func (r Result) Errors() int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == SeverityError {
			n++
		}
	}
	return n
}

// maxMatchesPerFile bounds repeated findings for one rule in one file.
const maxMatchesPerFile = 5

// Evaluate runs every enabled rule over the input.
func Evaluate(c *Config, in Input) (Result, error) {
	ev := &evaluator{cfg: c, in: in, seen: map[string]bool{}}
	for i := range in.Entries {
		e := &in.Entries[i]
		a := in.Assets[e.ID]
		if err := ev.entry(e, a); err != nil {
			return Result{}, fmt.Errorf("policy: %s: %w", e.ID, err)
		}
	}
	sort.SliceStable(ev.res.Findings, func(i, j int) bool {
		a, b := ev.res.Findings[i], ev.res.Findings[j]
		if a.EntryID != b.EntryID {
			return a.EntryID < b.EntryID
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Message < b.Message
	})
	return ev.res, nil
}

type evaluator struct {
	cfg  *Config
	in   Input
	res  Result
	seen map[string]bool
}

func (ev *evaluator) add(rule string, e *asset.Entry, p string, line int, msg string) {
	sev := ev.cfg.Severity(rule)
	if sev == SeverityOff {
		return
	}
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s", rule, e.ID, p, line, msg)
	if ev.seen[key] {
		return
	}
	ev.seen[key] = true
	if ev.cfg.Excepted(rule, e.ID) {
		ev.res.Suppressed++
		return
	}
	r, _ := RuleByID(rule)
	ev.res.Findings = append(ev.res.Findings, Finding{
		Rule: rule, Name: r.Name, Severity: sev, EntryID: e.ID, Path: p, Line: line,
		Message: msg, Remediation: r.Help,
	})
}

func (ev *evaluator) on(rule string) bool { return ev.cfg.Severity(rule) != SeverityOff }

func (ev *evaluator) entry(e *asset.Entry, a *asset.Asset) error {
	file, _, _ := strings.Cut(e.Path, "#")
	if a != nil {
		for _, s := range a.AutoApprove {
			ev.add("LW008", e, file, 0, s)
		}
	}
	switch e.Surface {
	case asset.SurfaceMCP:
		ev.mcp(e, a, file)
	case asset.SurfaceHook:
		return ev.hook(e, a, file)
	case asset.SurfaceSkill:
		return ev.skill(e, a)
	case asset.SurfaceRules:
		if a != nil && a.ContentPath != "" && (ev.on("LW004") || ev.on("LW005")) {
			return ev.scanFile(e, a.ContentPath, e.Path, true, true, false)
		}
	}
	return nil
}

func serverName(e *asset.Entry) string {
	_, _, name, _ := asset.ParseID(e.ID)
	return name
}

func (ev *evaluator) mcp(e *asset.Entry, a *asset.Asset, file string) {
	s := e.Server
	if s == nil {
		return
	}
	if p := s.Package; p != nil && !p.Pinned() {
		what := p.Spec
		if what == "" {
			what = s.Command + " (no package argument)"
		}
		kind := "an exact version"
		if p.Ecosystem == "oci" {
			kind = "an image digest"
		}
		ev.add("LW001", e, file, 0, fmt.Sprintf("MCP server %q runs %s package %q without %s", serverName(e), p.Ecosystem, what, kind))
	}
	if e.Source != nil && !ev.cfg.SourceAllowed(e.Source.String()) {
		ev.add("LW002", e, file, 0, fmt.Sprintf("MCP server %q source %q is not in allow.sources", serverName(e), e.Source.String()))
	}
	if a != nil {
		for _, loc := range a.InlineSecrets {
			ev.add("LW007", e, file, 0, fmt.Sprintf("MCP server %q has an inline secret in %s (value not shown)", serverName(e), loc))
		}
	}
	text := strings.Join(append([]string{s.Command}, s.Args...), " ")
	ev.scanText(e, file, 0, text, true, true, false)
}

func (ev *evaluator) hook(e *asset.Entry, a *asset.Asset, file string) error {
	if a != nil {
		for _, loc := range a.InlineSecrets {
			ev.add("LW007", e, file, 0, fmt.Sprintf("hook has an inline secret in %s (value not shown)", loc))
		}
	}
	for _, c := range e.Hook.Commands() {
		ev.scanText(e, file, 0, c, false, true, true)
	}
	if e.Hook.URL != "" && ev.on("LW003") {
		ev.add("LW003", e, file, 0, fmt.Sprintf("HTTP hook sends events to %s", e.Hook.URL))
	}
	for _, r := range e.ReferencedFiles {
		if err := ev.scanFile(e, r.Path, r.Path, false, true, true); err != nil {
			return err
		}
	}
	return nil
}

func (ev *evaluator) skill(e *asset.Entry, a *asset.Asset) error {
	if a != nil && a.Source != nil && !ev.cfg.SourceAllowed(a.Source.String()) {
		ev.add("LW002", e, e.Path, 0, fmt.Sprintf("skill source %q is not in allow.sources", a.Source.String()))
	}
	if a == nil || a.ContentPath == "" {
		return nil
	}
	for _, f := range e.Files {
		if f.Digest == "" { // symlinks and special files have no content
			continue
		}
		content := path.Join(a.ContentPath, f.Path)
		display := path.Join(e.Path, f.Path)
		if ev.on("LW006") {
			if kind, err := executableKind(ev.in.FS, content, f.Path); err != nil {
				return err
			} else if kind != "" {
				ev.add("LW006", e, display, 0, fmt.Sprintf("skill contains %s: %s", kind, f.Path))
			}
		}
		if ev.on("LW004") || ev.on("LW005") {
			if err := ev.scanFile(e, content, display, true, true, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// --- text patterns -------------------------------------------------------

var (
	urlPattern = regexp.MustCompile(`https?://([A-Za-z0-9.-]+)`)
	// fetchExec marks a line that tells the agent to fetch or execute something.
	fetchExec = regexp.MustCompile(`(?i)(\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|start-bitstransfer|fetch|download|downloads|eval|exec)\b|\bpip3? install\b|\bnpm (i|install)\b|\b(npx|uvx|bunx)\b|\bpnpm dlx\b|\bgit clone\b|\|\s*(ba|z)?sh\b|\b(bash|sh|zsh|python3?|node) -c\b|\bsource\s+<\()`)
	// networkTool matches network tools invoked by hooks (LW003).
	networkTool = regexp.MustCompile(`(?i)(^|[\s;|&(\x60"'/=])(curl|wget|nc|ncat|netcat|socat|telnet|ftp|tftp|scp|sftp|rsync|ssh|invoke-webrequest|invoke-restmethod|iwr|irm|start-bitstransfer|certutil|bitsadmin)(\.exe)?($|[\s;|&)\x60"'])|/dev/(tcp|udp)/|\burllib\.request\b|\brequests\.(get|post|put)\(|\bhttp\.client\b|\bfetch\(|\bnet\.connect\(|\bsocket\.socket\(`)
	// secretPath matches references to credential stores (LW005).
	secretPath = regexp.MustCompile(`(?i)(~|\$home|\$\{home\}|%userprofile%)?[/\\]\.(ssh|aws|gnupg|kube|azure|docker[/\\]config\.json|netrc|npmrc|pypirc|git-credentials|config[/\\]gcloud|config[/\\]gh[/\\]hosts\.yml)\b|\bid_(rsa|dsa|ecdsa|ed25519)\b|(^|[\s"'=/(\x60])\.env(\.[A-Za-z0-9_-]+)?($|[\s"'\x60),;:])|\blogin\.keychain\b|\bsecurity (find|dump)-(generic|internet)-password\b|\b(google[/\\]chrome|chromium|brave-browser|microsoft[/\\]edge)[/\\](user data|default)\b|\bLogin Data\b|\.mozilla[/\\]firefox\b|/etc/shadow\b`)
)

// scanText applies the selected rules to an in-memory string.
func (ev *evaluator) scanText(e *asset.Entry, file string, line int, text string, urls, secrets, network bool) {
	ev.matchLine(e, file, line, []byte(text), urls, secrets, network, map[string]int{})
}

// Literal prefilters: a segment is only handed to the (slower) regular
// expressions when it contains a substring the pattern needs. This keeps
// whole-file scanning fast on padded files (LW-NFR-04).
var (
	secretHints = [][]byte{
		[]byte(".ssh"), []byte(".aws"), []byte(".gnupg"), []byte(".kube"), []byte(".azure"), []byte(".docker"),
		[]byte(".netrc"), []byte(".npmrc"), []byte(".pypirc"), []byte(".git-credentials"), []byte("gcloud"),
		[]byte("hosts.yml"), []byte("id_"), []byte(".env"), []byte("keychain"), []byte("-password"),
		[]byte("chrome"), []byte("chromium"), []byte("brave-browser"), []byte("edge"), []byte("login data"),
		[]byte("firefox"), []byte("/etc/shadow"),
	}
	networkHints = [][]byte{
		[]byte("curl"), []byte("wget"), []byte("nc"), []byte("socat"), []byte("telnet"), []byte("ftp"),
		[]byte("scp"), []byte("rsync"), []byte("ssh"), []byte("invoke-"), []byte("iwr"), []byte("irm"),
		[]byte("bits"), []byte("certutil"), []byte("/dev/"), []byte("urllib"), []byte("requests."),
		[]byte("http.client"), []byte("fetch("), []byte("connect("), []byte("socket"),
	}
)

func containsAny(lower []byte, hints [][]byte) bool {
	for _, h := range hints {
		if bytes.Contains(lower, h) {
			return true
		}
	}
	return false
}

func (ev *evaluator) matchLine(e *asset.Entry, file string, line int, b []byte, urls, secrets, network bool, counts map[string]int) {
	urls = urls && bytes.Contains(b, []byte("://"))
	if secrets || network {
		lower := bytes.ToLower(b)
		secrets = secrets && containsAny(lower, secretHints)
		network = network && containsAny(lower, networkHints)
	}
	if urls && ev.on("LW004") && fetchExec.Match(b) {
		for _, m := range urlPattern.FindAllSubmatch(b, -1) {
			host := strings.TrimSuffix(string(m[1]), ".")
			if host == "" || ev.cfg.DomainAllowed(host) || counts["LW004"] >= maxMatchesPerFile {
				continue
			}
			counts["LW004"]++
			ev.add("LW004", e, file, line, fmt.Sprintf("instructs fetching or executing from %s", host))
		}
	}
	if secrets && ev.on("LW005") && counts["LW005"] < maxMatchesPerFile {
		if m := secretPath.Find(b); m != nil {
			counts["LW005"]++
			ev.add("LW005", e, file, line, fmt.Sprintf("references a credential location (%s)", strings.TrimSpace(string(m))))
		}
	}
	if network && ev.on("LW003") && counts["LW003"] < maxMatchesPerFile {
		if m := networkTool.Find(b); m != nil {
			counts["LW003"]++
			ev.add("LW003", e, file, line, fmt.Sprintf("invokes a network tool (%s)", strings.Trim(strings.TrimSpace(string(m)), `"'();|&`+"`")))
		}
	}
}

// segment is the maximum bytes examined at once; longer lines are scanned in
// overlapping windows so a pattern cannot hide across a boundary.
const (
	segment = 64 << 10
	overlap = 1 << 10
)

// scanFile streams a whole file (no size cap, THREAT_MODEL T3) through the
// selected rules, line by line, with bounded memory.
func (ev *evaluator) scanFile(e *asset.Entry, name, display string, urls, secrets, network bool) error {
	f, err := ev.in.FS.Open(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // vanished since discovery; drift is reported separately
		}
		return err
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return err
	}
	r := bufio.NewReaderSize(f, segment)
	counts := map[string]int{}
	line := 1
	var carry []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(chunk) > 0 {
			buf := append(append([]byte{}, carry...), chunk...)
			ev.matchLine(e, display, line, buf, urls, secrets, network, counts)
			if errors.Is(err, bufio.ErrBufferFull) {
				carry = append(carry[:0], tail(chunk, overlap)...)
			} else {
				carry = carry[:0]
			}
			line += bytes.Count(chunk, []byte{'\n'})
		}
		switch {
		case err == nil, errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			return nil
		default:
			return err
		}
	}
}

func tail(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[len(b)-n:]
}

// executableKind classifies a file by magic bytes and extension (LW006).
func executableKind(fsys fs.FS, file, name string) (string, error) {
	lower := strings.ToLower(name)
	for ext, kind := range map[string]string{
		".pyc": "Python bytecode", ".pyo": "Python bytecode", ".class": "Java bytecode", ".jar": "a Java archive",
		".whl": "a Python wheel", ".egg": "a Python egg", ".exe": "a Windows executable", ".dll": "a Windows library",
		".so": "a shared library", ".dylib": "a macOS library", ".wasm": "a WebAssembly module",
		".docx": "an Office document (ZIP archive)", ".xlsx": "an Office document (ZIP archive)",
		".pptx": "an Office document (ZIP archive)", ".docm": "a macro-enabled Office document",
		".xlsm": "a macro-enabled Office document", ".msi": "a Windows installer", ".deb": "a Debian package",
		".rpm": "an RPM package", ".apk": "an Android package", ".dmg": "a macOS disk image",
	} {
		if strings.HasSuffix(lower, ext) {
			return kind, nil
		}
	}
	f, err := fsys.Open(file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()
	head := make([]byte, 512)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return "", err
	}
	return magicKind(head[:n]), nil
}

func magicKind(h []byte) string {
	has := func(p string) bool { return bytes.HasPrefix(h, []byte(p)) }
	switch {
	case has("\x7fELF"):
		return "an ELF executable"
	case has("\xfe\xed\xfa\xce"), has("\xfe\xed\xfa\xcf"), has("\xce\xfa\xed\xfe"), has("\xcf\xfa\xed\xfe"):
		return "a Mach-O executable"
	case has("\xca\xfe\xba\xbe"):
		return "a Mach-O universal binary or Java class"
	case has("MZ"):
		return "a Windows (PE) executable"
	case has("\x00asm"):
		return "a WebAssembly module"
	case has("PK\x03\x04"), has("PK\x05\x06"):
		return "a ZIP archive"
	case has("\x1f\x8b"):
		return "a gzip archive"
	case has("BZh"):
		return "a bzip2 archive"
	case has("\xfd7zXZ\x00"):
		return "an xz archive"
	case has("7z\xbc\xaf\x27\x1c"):
		return "a 7-Zip archive"
	case has("Rar!\x1a\x07"):
		return "a RAR archive"
	case has("\x28\xb5\x2f\xfd"):
		return "a zstd archive"
	case len(h) > 262 && string(h[257:262]) == "ustar":
		return "a tar archive"
	case len(h) >= 8 && h[1] >= 0x0b && h[1] <= 0x0e && h[2] == '\r' && h[3] == '\n' && bytes.IndexByte(h[4:8], 0) >= 0:
		// CPython 3 .pyc header: 2-byte magic, \r\n, then flags (usually zero).
		return "Python bytecode"
	}
	return ""
}
