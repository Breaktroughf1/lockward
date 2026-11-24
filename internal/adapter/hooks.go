package adapter

import (
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/asset"
	"github.com/Breaktroughf1/lockward/internal/redact"
)

// HookOptions describes where hook definitions live.
type HookOptions struct {
	Agent    string
	LoadedBy []string
	File     string   // config file, relative to the scope root
	Pointer  []string // JSON pointer tokens to the events map, e.g. {"hooks"}
	BaseDir  string   // directory relative hook paths resolve against ("" = scope root)
}

// Hooks parses an events map. Two shapes are accepted:
//
//	{"Event": [{"matcher": "...", "hooks": [{handler}, ...]}]}  (Claude Code, Gemini CLI, Codex, Devin)
//	{"event": [{handler}, ...]}                                   (Cursor, GitHub Copilot)
func Hooks(events map[string]any, o HookOptions) Result {
	var r Result
	for _, event := range SortedKeys(events) {
		items, ok := events[event].([]any)
		if !ok {
			r.Problem(o.Agent, o.File+"#"+Pointer(append(append([]string{}, o.Pointer...), event)...), "hook event value is not an array; skipped")
			continue
		}
		for i, it := range items {
			item, ok := it.(map[string]any)
			if !ok {
				continue
			}
			gi := strconv.Itoa(i)
			if handlers, nested := item["hooks"].([]any); nested {
				matcher := Str(item, "matcher")
				for j, h := range handlers {
					hm, ok := h.(map[string]any)
					if !ok {
						continue
					}
					tokens := append(append([]string{}, o.Pointer...), event, gi, "hooks", strconv.Itoa(j))
					r.Assets = append(r.Assets, hookAsset(o, event, matcher, hm, tokens, event+"/"+gi+"/"+strconv.Itoa(j)))
				}
				continue
			}
			tokens := append(append([]string{}, o.Pointer...), event, gi)
			r.Assets = append(r.Assets, hookAsset(o, event, Str(item, "matcher"), item, tokens, event+"/"+gi))
		}
	}
	return r
}

func hookAsset(o HookOptions, event, matcher string, m map[string]any, tokens []string, name string) asset.Asset {
	h := &asset.Hook{Event: event, Matcher: matcher, Type: Str(m, "type")}
	var secrets []string
	str := func(key string) string {
		v := Str(m, key)
		if r := redact.String(v); r != v {
			secrets = append(secrets, key)
			return r
		}
		return v
	}
	h.Command, h.Bash, h.PowerShell, h.Exec = str("command"), str("bash"), str("powershell"), str("exec")
	h.Shell, h.Cwd, h.Prompt, h.Server, h.Tool = Str(m, "shell"), Str(m, "cwd"), str("prompt"), Str(m, "server"), Str(m, "tool")
	if args, masked := redact.Args(Strings(m, "args")); len(args) > 0 {
		h.Args = args
		for _, i := range masked {
			secrets = append(secrets, fmt.Sprintf("args[%d]", i))
		}
	}
	if u := Str(m, "url"); u != "" {
		var changed bool
		h.URL, changed = redact.URL(u)
		if changed {
			secrets = append(secrets, "url")
		}
	}
	for _, hk := range []string{"headers", "env"} {
		for k, v := range Obj(m, hk) {
			if s, ok := v.(string); ok && redact.InlineSecret(k, s) {
				secrets = append(secrets, hk+"."+k)
			}
		}
	}
	return asset.Asset{
		Surface:       asset.SurfaceHook,
		Agent:         o.Agent,
		LoadedBy:      o.LoadedBy,
		Name:          o.File + "#" + name,
		Path:          o.File + "#" + Pointer(tokens...),
		File:          o.File,
		Hook:          h,
		HookBaseDir:   o.BaseDir,
		InlineSecrets: secrets,
	}
}

// scriptExts mark a bare token as a script path even without a slash.
var scriptExts = []string{".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".ps1", ".bat", ".cmd", ".php", ".lua"}

// rootVars expand to the scope root inside hook commands.
var rootVars = []string{
	"$CLAUDE_PROJECT_DIR", "${CLAUDE_PROJECT_DIR}", "$GEMINI_PROJECT_DIR", "${GEMINI_PROJECT_DIR}",
	"$CURSOR_PROJECT_DIR", "${CURSOR_PROJECT_DIR}", "${workspaceFolder}", "$PWD", "${PWD}",
}

// homeVars expand to the user home (the user scope root).
var homeVars = []string{"~", "$HOME", "${HOME}", "%USERPROFILE%"}

// ReferencedFiles returns the regular files inside the scope root that a
// hook's commands reference, as sorted root-relative paths (SPEC §4.3). It
// only reads metadata; nothing is executed.
func ReferencedFiles(src *Source, h *asset.Hook, baseDir string) []string {
	seen := map[string]bool{}
	for _, cmd := range h.Commands() {
		for _, tok := range shellTokens(cmd) {
			if p, ok := resolveToken(src, tok, baseDir); ok {
				seen[p] = true
			}
		}
	}
	out := SortedKeys(seen)
	sort.Strings(out)
	return out
}

func shellTokens(cmd string) []string {
	f := func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == ';' || r == '|' || r == '&' || r == '>' || r == '<' || r == '(' || r == ')' || r == '`'
	}
	var out []string
	for _, t := range strings.FieldsFunc(cmd, f) {
		t = strings.NewReplacer(`"`, "", `'`, "").Replace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func resolveToken(src *Source, tok, baseDir string) (string, bool) {
	if !strings.Contains(tok, "/") && !strings.Contains(tok, `\`) && !hasAnySuffix(strings.ToLower(tok), scriptExts) {
		return "", false
	}
	if strings.HasPrefix(tok, "-") || strings.Contains(tok, "://") {
		return "", false
	}
	if _, after, ok := strings.Cut(tok, "="); ok && strings.HasPrefix(tok, "-") {
		tok = after
	}
	tok = strings.ReplaceAll(tok, `\`, "/")
	rel := ""
	anchored := false
	for _, v := range rootVars {
		if rest, ok := strings.CutPrefix(tok, v); ok {
			rel, anchored = rest, true
			break
		}
	}
	if !anchored && src.Scope == asset.ScopeUser {
		for _, v := range homeVars {
			if rest, ok := strings.CutPrefix(tok, v); ok && (rest == "" || rest[0] == '/') {
				rel, anchored = rest, true
				break
			}
		}
	}
	switch {
	case anchored:
	case strings.HasPrefix(tok, "/") || filepath.IsAbs(filepath.FromSlash(tok)):
		if src.RootDir == "" {
			return "", false
		}
		r, err := filepath.Rel(src.RootDir, filepath.FromSlash(tok))
		if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
			return "", false
		}
		rel = filepath.ToSlash(r)
	case strings.Contains(tok, "$") || strings.Contains(tok, "%"):
		return "", false
	default:
		rel = path.Join(baseDir, tok)
	}
	rel = strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(rel, "/")), "/")
	if rel == "" || rel == "." {
		return "", false
	}
	if !fs.ValidPath(rel) {
		return "", false
	}
	if k, escaped := src.Resolve(rel); k != RegularFile || escaped {
		return "", false
	}
	return rel, true
}
