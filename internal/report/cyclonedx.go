package report

import (
	"crypto/sha1" //nolint:gosec // UUIDv5 (RFC 9562) is defined over SHA-1; used for a stable id, not security
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/Breaktroughf1/lockward/internal/asset"
	"github.com/Breaktroughf1/lockward/internal/hash"
)

// CycloneDX 1.6 types (only the fields Lockward emits).
type cdxBOM struct {
	Schema       string         `json:"$schema"`
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     cdxMetadata    `json:"metadata"`
	Components   []cdxComponent `json:"components"`
}

type cdxMetadata struct {
	Tools      cdxTools      `json:"tools"`
	Component  *cdxComponent `json:"component,omitempty"`
	Properties []cdxProperty `json:"properties"`
}

type cdxTools struct {
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type               string        `json:"type"`
	BOMRef             string        `json:"bom-ref,omitempty"`
	Name               string        `json:"name"`
	Version            string        `json:"version,omitempty"`
	Description        string        `json:"description,omitempty"`
	PURL               string        `json:"purl,omitempty"`
	Hashes             []cdxHash     `json:"hashes,omitempty"`
	ExternalReferences []cdxExtRef   `json:"externalReferences,omitempty"`
	Properties         []cdxProperty `json:"properties,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxExtRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// bomNamespace is the UUIDv5 namespace for Lockward BOM serial numbers.
var bomNamespace = [16]byte{0x6c, 0x6f, 0x63, 0x6b, 0x77, 0x61, 0x72, 0x64, 0x2d, 0x62, 0x6f, 0x6d, 0x2d, 0x76, 0x31, 0x00}

// BOMOptions configures CycloneDX output.
type BOMOptions struct {
	Version string      // lockward version
	Scope   asset.Scope // scope of the entries
	Name    string      // name of the described project (metadata.component)
}

// CycloneDX renders a CycloneDX 1.6 AI/ML-BOM of lockfile entries (US-6).
// The output is deterministic: no timestamp, and the serial number is a
// UUIDv5 derived from the entries' digests.
func CycloneDX(w io.Writer, entries []asset.Entry, o BOMOptions) error {
	sorted := append([]asset.Entry{}, entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	bom := cdxBOM{
		Schema: "http://cyclonedx.org/schema/bom-1.6.schema.json", BOMFormat: "CycloneDX", SpecVersion: "1.6",
		SerialNumber: serial(sorted), Version: 1,
		Metadata: cdxMetadata{
			Tools: cdxTools{Components: []cdxComponent{{
				Type: "application", Name: "lockward", Version: o.Version,
				ExternalReferences: []cdxExtRef{{Type: "vcs", URL: InformationURI}},
			}}},
			Properties: []cdxProperty{{Name: "lockward:scope", Value: string(o.Scope)}},
		},
		Components: []cdxComponent{},
	}
	if o.Name != "" {
		bom.Metadata.Component = &cdxComponent{Type: "application", BOMRef: "lockward:root", Name: o.Name}
	}
	for _, e := range sorted {
		bom.Components = append(bom.Components, component(e))
	}
	return encode(w, bom)
}

func serial(entries []asset.Entry) string {
	h := sha1.New() //nolint:gosec // see import comment
	_, _ = h.Write(bomNamespace[:])
	for _, e := range entries {
		_, _ = h.Write([]byte(e.ID + "\x00" + e.Digest + "\x00" + e.ToolsFingerprint + "\n"))
	}
	u := h.Sum(nil)[:16]
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 9562 variant
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

func component(e asset.Entry) cdxComponent {
	_, _, name, _ := asset.ParseID(e.ID)
	c := cdxComponent{
		Type:   "application",
		BOMRef: e.ID,
		Name:   name,
		Hashes: []cdxHash{{Alg: "SHA-256", Content: strings.TrimPrefix(e.Digest, hash.Prefix)}},
		Properties: []cdxProperty{
			{Name: "lockward:id", Value: e.ID},
			{Name: "lockward:surface", Value: string(e.Surface)},
			{Name: "lockward:agent", Value: e.Agent},
			{Name: "lockward:path", Value: e.Path},
		},
	}
	if len(e.LoadedBy) > 0 {
		c.Properties = append(c.Properties, cdxProperty{Name: "lockward:loaded_by", Value: strings.Join(e.LoadedBy, ",")})
	}
	if e.Approved != nil {
		c.Properties = append(c.Properties, cdxProperty{Name: "lockward:approved_by", Value: e.Approved.By})
	}
	switch e.Surface {
	case asset.SurfaceSkill:
		c.Description = fmt.Sprintf("Agent skill (%d files)", len(e.Files))
	case asset.SurfaceRules:
		c.Type = "file"
		c.Description = "Agent rules or instruction file"
	case asset.SurfaceSettings:
		c.Type = "data"
		c.Description = "Security-relevant agent settings"
	case asset.SurfaceHook:
		c.Description = "Agent hook"
		if e.Hook != nil {
			c.Properties = append(c.Properties, cdxProperty{Name: "lockward:hook_event", Value: e.Hook.Event})
		}
	case asset.SurfaceMCP:
		c.Description = "MCP server"
		if s := e.Server; s != nil {
			c.Properties = append(c.Properties, cdxProperty{Name: "lockward:transport", Value: s.Transport})
			if p := s.Package; p != nil {
				c.Version = p.Version
				c.PURL = purl(p)
			}
			if s.URL != "" {
				c.ExternalReferences = []cdxExtRef{{Type: "other", URL: s.URL}}
			}
		}
		if e.ToolsFingerprint != "" {
			c.Properties = append(c.Properties, cdxProperty{Name: "lockward:tools_fingerprint", Value: e.ToolsFingerprint})
		}
	}
	return c
}

// purl returns a package URL for pinned npm and PyPI packages.
func purl(p *asset.Package) string {
	if p.Version == "" || strings.Contains(p.Name, "://") || strings.Contains(p.Name, ":") {
		return ""
	}
	switch p.Ecosystem {
	case "npm":
		name := p.Name
		if scope, rest, ok := strings.Cut(name, "/"); ok && strings.HasPrefix(scope, "@") {
			return "pkg:npm/" + purlEscape(scope) + "/" + purlEscape(rest) + "@" + purlEscape(p.Version)
		}
		return "pkg:npm/" + purlEscape(name) + "@" + purlEscape(p.Version)
	case "pypi":
		name := strings.ToLower(strings.ReplaceAll(p.Name, "_", "-"))
		return "pkg:pypi/" + purlEscape(name) + "@" + purlEscape(p.Version)
	}
	return ""
}

// purlEscape percent-encodes a purl segment; "@" must be encoded too
// (package-url spec), which url.PathEscape leaves alone.
func purlEscape(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), "@", "%40")
}
