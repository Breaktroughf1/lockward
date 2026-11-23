// Package asset defines the types shared across discovery, hashing, locking,
// policy and reporting: Asset (what an adapter discovered) and Entry (what the
// lockfile records, SPEC §4).
package asset

import (
	"fmt"
	"slices"
	"strings"
)

// Surface is the kind of agent asset (SPEC §4).
type Surface string

// Surfaces.
const (
	SurfaceSkill    Surface = "skill"
	SurfaceMCP      Surface = "mcp"
	SurfaceHook     Surface = "hook"
	SurfaceRules    Surface = "rules"
	SurfaceSettings Surface = "settings"
)

// Surfaces lists every surface in display order.
var Surfaces = []Surface{SurfaceSkill, SurfaceMCP, SurfaceHook, SurfaceRules, SurfaceSettings}

// Valid reports whether s is a known surface.
func (s Surface) Valid() bool { return slices.Contains(Surfaces, s) }

// Scope is where an asset lives (SPEC §1).
type Scope string

// Scopes.
const (
	ScopeUser    Scope = "user"
	ScopeProject Scope = "project"
)

// Agent identifiers used in Entry.Agent (SPEC §4).
const (
	AgentClaudeCode = "claude-code"
	AgentCursor     = "cursor"
	AgentCodex      = "codex"
	AgentGeminiCLI  = "gemini-cli"
	AgentWindsurf   = "windsurf"
	AgentCopilot    = "copilot"
	AgentGeneric    = "generic"
)

// Agents lists the valid values of Entry.Agent.
var Agents = []string{AgentClaudeCode, AgentCursor, AgentCodex, AgentGeminiCLI, AgentWindsurf, AgentCopilot, AgentGeneric}

// File is one member of a skill tree (SPEC §4.1).
type File struct {
	Path    string `json:"path"`
	Digest  string `json:"digest,omitempty"`
	Size    *int64 `json:"size,omitempty"`
	Mode    string `json:"mode,omitempty"`
	Symlink string `json:"symlink,omitempty"`
	Special string `json:"special,omitempty"`
}

// FileRef pins a file referenced by a hook command (SPEC §4.3).
type FileRef struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

// Source is optional provenance (SPEC §4).
type Source struct {
	Type     string `json:"type"`
	Ref      string `json:"ref,omitempty"`
	Resolved string `json:"resolved,omitempty"`
}

// String renders the source as "<type>:<ref>", the form matched by policy
// allow.sources patterns.
func (s *Source) String() string {
	if s == nil {
		return ""
	}
	return s.Type + ":" + s.Ref
}

// Package identifies the package an MCP server is launched from.
type Package struct {
	Ecosystem string `json:"ecosystem"` // npm | pypi | oci
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"` // exact version, if pinned
	Digest    string `json:"digest,omitempty"`  // OCI image digest, if pinned
	Spec      string `json:"spec,omitempty"`    // the raw specifier, e.g. "pkg@latest"
}

// Pinned reports whether the package is pinned to an exact version or digest.
func (p *Package) Pinned() bool {
	if p == nil {
		return false
	}
	if p.Ecosystem == "oci" {
		return p.Digest != ""
	}
	return p.Version != ""
}

// MCPServer is the recorded definition of an MCP server (SPEC §4.2). Secret
// values never appear here: env and header values are reduced to names, and
// secret-looking arguments are replaced with "[REDACTED]".
type MCPServer struct {
	Transport    string   `json:"transport"` // stdio | http | sse | ws
	Command      string   `json:"command,omitempty"`
	Args         []string `json:"args,omitempty"`
	Cwd          string   `json:"cwd,omitempty"`
	Package      *Package `json:"package,omitempty"`
	URL          string   `json:"url,omitempty"`
	EnvKeys      []string `json:"env_keys,omitempty"`
	HeaderKeys   []string `json:"header_keys,omitempty"`
	Trust        bool     `json:"trust,omitempty"`         // Gemini CLI: bypasses all confirmations
	ApprovalMode string   `json:"approval_mode,omitempty"` // Codex default_tools_approval_mode
	Disabled     bool     `json:"disabled,omitempty"`
}

// Hook is the recorded definition of one hook handler (SPEC §4.3).
type Hook struct {
	Event      string   `json:"event"`
	Matcher    string   `json:"matcher,omitempty"`
	Type       string   `json:"type,omitempty"`
	Command    string   `json:"command,omitempty"`
	Bash       string   `json:"bash,omitempty"`
	PowerShell string   `json:"powershell,omitempty"`
	Exec       string   `json:"exec,omitempty"`
	Args       []string `json:"args,omitempty"`
	Shell      string   `json:"shell,omitempty"`
	Cwd        string   `json:"cwd,omitempty"`
	URL        string   `json:"url,omitempty"`
	Prompt     string   `json:"prompt,omitempty"`
	Server     string   `json:"server,omitempty"`
	Tool       string   `json:"tool,omitempty"`
}

// Commands returns every command string the hook may execute.
func (h *Hook) Commands() []string {
	if h == nil {
		return nil
	}
	var out []string
	for _, c := range []string{h.Command, h.Bash, h.PowerShell, h.Exec} {
		if c != "" {
			out = append(out, c)
		}
	}
	if len(h.Args) > 0 {
		out = append(out, strings.Join(h.Args, " "))
	}
	return out
}

// Approval records who approved an entry (SPEC §4). No timestamp.
type Approval struct {
	By string `json:"by"`
}

// Entry is one lockfile entry (SPEC §4). Field order is irrelevant: entries
// are encoded as canonical JSON with sorted keys.
type Entry struct {
	ID               string         `json:"id"`
	Surface          Surface        `json:"surface"`
	Agent            string         `json:"agent"`
	LoadedBy         []string       `json:"loaded_by,omitempty"`
	Path             string         `json:"path"`
	Digest           string         `json:"digest"`
	Symlink          string         `json:"symlink,omitempty"`
	Source           *Source        `json:"source,omitempty"`
	Approved         *Approval      `json:"approved,omitempty"`
	Files            []File         `json:"files,omitempty"`
	Server           *MCPServer     `json:"server,omitempty"`
	ToolsFingerprint string         `json:"tools_fingerprint,omitempty"`
	Hook             *Hook          `json:"hook,omitempty"`
	ReferencedFiles  []FileRef      `json:"referenced_files,omitempty"`
	Settings         map[string]any `json:"settings,omitempty"`
}

// MakeID builds "<surface>:<agent>:<name>".
func MakeID(s Surface, agent, name string) string {
	return string(s) + ":" + agent + ":" + name
}

// ParseID splits an id into its parts.
func ParseID(id string) (s Surface, agent, name string, err error) {
	parts := strings.SplitN(id, ":", 3)
	if len(parts) != 3 || parts[2] == "" {
		return "", "", "", fmt.Errorf("invalid entry id %q: want <surface>:<agent>:<name>", id)
	}
	s = Surface(parts[0])
	if !s.Valid() {
		return "", "", "", fmt.Errorf("invalid entry id %q: unknown surface %q", id, parts[0])
	}
	return s, parts[1], parts[2], nil
}

// Asset is something an adapter discovered. It carries the data that becomes
// an Entry plus ephemeral facts for policy evaluation that are never written
// to any output.
type Asset struct {
	Surface  Surface
	Agent    string   // owning agent (Entry.Agent)
	LoadedBy []string // every agent that loads it, including Agent
	Name     string   // id name component; discovery resolves collisions
	Path     string   // relative to the scope root; objects use "file#/json/pointer"
	File     string   // the file (or skill directory) on disk, relative to the scope root

	// Exactly one of the following describes the content.
	SkillDir bool           // Path is a skill directory (or a loose file in a skills dir)
	Server   *MCPServer     // mcp
	Hook     *Hook          // hook
	Settings map[string]any // settings (security-relevant subset of a config file)
	Raw      bool           // pin File's bytes (rules files, unparseable configs)

	Source *Source

	// HookBaseDir is the directory hook-relative paths resolve against.
	HookBaseDir string

	// ContentPath is where the content actually lives after resolving
	// symlinks within the root (set by discovery; empty if not pinned).
	ContentPath string

	// Facts for policy only; never serialised.
	InlineSecrets []string // locations like "env.API_KEY"; values are never kept
	AutoApprove   []string // human-readable auto-approval settings found
}

// Problem is a non-fatal discovery issue, reported to the user and never
// silently ignored (e.g. a malformed config that was pinned as raw bytes).
type Problem struct {
	Agent   string
	Path    string
	Message string
}

func (p Problem) String() string {
	return fmt.Sprintf("%s: %s: %s", p.Agent, p.Path, p.Message)
}
