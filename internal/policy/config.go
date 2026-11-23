// Package policy loads lockward.policy.yaml and evaluates the built-in rules
// LW001–LW008 (PRD §6.1). Evaluation is deterministic and rule-based; there
// is no LLM anywhere in the decision path (ADR-0003).
//
// Requirements: LW-FR-11.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/Breaktroughf1/lockward/internal/hash"
)

// FileName is the project policy file (PRD §6, LW-FR-11).
const FileName = "lockward.policy.yaml"

// Severity of a rule.
type Severity string

// Severities. Only error findings fail verify (exit code 2).
const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityOff     Severity = "off"
)

// Config is a parsed policy file.
type Config struct {
	Version    int                 `yaml:"version"`
	Rules      map[string]Severity `yaml:"rules"`
	Allow      Allow               `yaml:"allow"`
	Exceptions []Exception         `yaml:"exceptions"`
}

// Allow lists approved sources (LW002) and domains (LW004).
type Allow struct {
	Sources []string `yaml:"sources"`
	Domains []string `yaml:"domains"`
}

// Exception suppresses one rule for matching entries. A reason is required
// so every exception is reviewable.
type Exception struct {
	Rule   string `yaml:"rule"`
	ID     string `yaml:"id"`
	Reason string `yaml:"reason"`
}

// Default returns the policy used when no policy file exists.
func Default() *Config {
	return &Config{Version: 1}
}

// MaxSize bounds the policy file size.
const MaxSize = 1 << 20

// Parse decodes and validates a policy file. Unknown keys are errors, so a
// typo cannot silently weaken the policy.
func Parse(b []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: empty policy file (expected at least \"version: 1\")", FileName)
		}
		return nil, fmt.Errorf("%s: %w", FileName, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("%s: unsupported version %d (want 1)", FileName, c.Version)
	}
	for id, sev := range c.Rules {
		if _, ok := RuleByID(id); !ok {
			return fmt.Errorf("%s: unknown rule %q (valid: %s)", FileName, id, strings.Join(ruleIDs(), ", "))
		}
		if sev != SeverityError && sev != SeverityWarning && sev != SeverityOff {
			return fmt.Errorf("%s: rule %s: severity must be error, warning or off, got %q", FileName, id, sev)
		}
	}
	for _, s := range c.Allow.Sources {
		typ, ref, ok := strings.Cut(s, ":")
		if !ok || typ == "" || ref == "" {
			return fmt.Errorf("%s: allow.sources entry %q must look like <type>:<pattern> (e.g. npm:@modelcontextprotocol/*)", FileName, s)
		}
		if _, err := path.Match(s, ""); err != nil {
			return fmt.Errorf("%s: allow.sources entry %q: %w", FileName, s, err)
		}
	}
	for _, d := range c.Allow.Domains {
		if d == "" || strings.ContainsAny(d, "/:") || (strings.Contains(d, "*") && !strings.HasPrefix(d, "*.")) {
			return fmt.Errorf("%s: allow.domains entry %q must be a host name or *.example.com", FileName, d)
		}
	}
	for i, e := range c.Exceptions {
		if _, ok := RuleByID(e.Rule); !ok {
			return fmt.Errorf("%s: exceptions[%d]: unknown rule %q", FileName, i, e.Rule)
		}
		if e.ID == "" {
			return fmt.Errorf("%s: exceptions[%d]: id is required", FileName, i)
		}
		if strings.TrimSpace(e.Reason) == "" {
			return fmt.Errorf("%s: exceptions[%d] (%s %s): a reason is required", FileName, i, e.Rule, e.ID)
		}
		if _, err := path.Match(e.ID, ""); err != nil {
			return fmt.Errorf("%s: exceptions[%d]: id pattern %q: %w", FileName, i, e.ID, err)
		}
	}
	return nil
}

// Severity returns the effective severity of a rule.
func (c *Config) Severity(id string) Severity {
	if s, ok := c.Rules[id]; ok {
		return s
	}
	r, _ := RuleByID(id)
	return r.Default
}

// Excepted reports whether rule is suppressed for entry id.
func (c *Config) Excepted(rule, id string) bool {
	for _, e := range c.Exceptions {
		if e.Rule != rule {
			continue
		}
		if e.ID == id {
			return true
		}
		if ok, _ := path.Match(e.ID, id); ok {
			return true
		}
	}
	return false
}

// SourceAllowed reports whether src ("<type>:<ref>") matches allow.sources.
// An empty list allows everything (LW002 is inactive until configured).
func (c *Config) SourceAllowed(src string) bool {
	if len(c.Allow.Sources) == 0 {
		return true
	}
	for _, p := range c.Allow.Sources {
		if p == src {
			return true
		}
		if ok, _ := path.Match(p, src); ok {
			return true
		}
	}
	return false
}

// DomainAllowed reports whether host matches allow.domains exactly or via a
// "*.example.com" wildcard (which matches subdomains, not the apex).
func (c *Config) DomainAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return slices.ContainsFunc(c.Allow.Domains, func(d string) bool {
		d = strings.ToLower(d)
		if suffix, ok := strings.CutPrefix(d, "*"); ok {
			return strings.HasSuffix(host, suffix)
		}
		return host == d
	})
}

// Load reads the policy at p. found is false (with the default policy) when
// the file does not exist. digest identifies the policy file for reporting
// (THREAT_MODEL T7).
func Load(p string) (c *Config, digest string, found bool, err error) {
	f, err := os.Open(p) //nolint:gosec // policy path chosen by the user
	if errors.Is(err, os.ErrNotExist) {
		return Default(), "", false, nil
	}
	if err != nil {
		return nil, "", false, fmt.Errorf("read policy: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return nil, "", true, fmt.Errorf("read policy %s: %w", p, err)
	}
	if len(b) > MaxSize {
		return nil, "", true, fmt.Errorf("read policy %s: larger than %d bytes", p, MaxSize)
	}
	c, err = Parse(b)
	if err != nil {
		return nil, "", true, err
	}
	return c, hash.Sum(b), true, nil
}

// DefaultFile is the policy written by "lockward init".
const DefaultFile = `# Lockward policy. Reference: https://github.com/Breaktroughf1/lockward/blob/main/docs/POLICY.md
version: 1

# Severity per rule: error (fails verify with exit code 2), warning, or off.
# Defaults are shown; uncomment a line to change it.
rules:
  # LW001: error    # unpinned-mcp-package
  # LW002: error    # source-not-allowed (active only when allow.sources is set)
  # LW003: error    # hook-executes-network
  # LW004: warning  # external-url-reference
  # LW005: warning  # secret-path-reference
  # LW006: error    # executable-in-skill
  # LW007: error    # env-value-inline
  # LW008: error    # auto-approve-tools

allow:
  # Approved MCP and skill sources as <type>:<pattern>. Types: npm, pypi, oci, url, local.
  # Leave empty to disable LW002.
  sources: []
  #  - npm:@modelcontextprotocol/*
  #  - oci:ghcr.io/github/*
  #  - url:mcp.example.com
  #  - local:*

  # Domains that skills and rules may fetch from or execute (LW004).
  domains: []
  #  - github.com
  #  - "*.example.com"

# Suppress a rule for one entry. A reason is required.
exceptions: []
#  - rule: LW006
#    id: skill:claude-code:pdf-tools
#    reason: Ships a reviewed helper binary (ticket SEC-123)
`
