// Package tools computes MCP tool-description fingerprints (SPEC §5.4) from
// a user-supplied tools/list response. No server is ever launched: the user
// captures the JSON themselves (LW-FR-06, THREAT_MODEL T4).
package tools

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/Breaktroughf1/lockward/internal/hash"
)

// MaxSize bounds a tools/list file.
const MaxSize = 16 << 20

type tool struct {
	Name        string          `json:"name"`
	Description *string         `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// Fingerprint returns the SPEC §5.4 digest of a tools/list response. It
// accepts a JSON-RPC response ({"result":{"tools":[...]}}), a result object
// ({"tools":[...]}) or a bare array. Only name, description and inputSchema
// are kept, sorted by name.
func Fingerprint(b []byte) (string, error) {
	raw, err := toolsArray(b)
	if err != nil {
		return "", err
	}
	var list []tool
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&list); err != nil {
		return "", fmt.Errorf("tools/list: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return "", errors.New("tools/list: trailing data after the tools array")
	}
	seen := map[string]bool{}
	out := make([]map[string]any, 0, len(list))
	for i, t := range list {
		if t.Name == "" {
			return "", fmt.Errorf("tools/list: tool %d has no name", i)
		}
		if seen[t.Name] {
			return "", fmt.Errorf("tools/list: duplicate tool name %q", t.Name)
		}
		seen[t.Name] = true
		m := map[string]any{"name": t.Name}
		if t.Description != nil {
			m["description"] = *t.Description
		}
		if len(t.InputSchema) > 0 && string(t.InputSchema) != "null" {
			var schema any
			d := json.NewDecoder(bytes.NewReader(t.InputSchema))
			d.UseNumber()
			if err := d.Decode(&schema); err != nil {
				return "", fmt.Errorf("tools/list: tool %q inputSchema: %w", t.Name, err)
			}
			m["inputSchema"] = schema
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
	return hash.Object(out)
}

func toolsArray(b []byte) (json.RawMessage, error) {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return trimmed, nil
	}
	var obj struct {
		Tools  json.RawMessage `json:"tools"`
		Result *struct {
			Tools json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return nil, fmt.Errorf("tools/list: %w", err)
	}
	switch {
	case obj.Result != nil && len(obj.Result.Tools) > 0:
		return obj.Result.Tools, nil
	case len(obj.Tools) > 0:
		return obj.Tools, nil
	}
	return nil, errors.New("tools/list: no \"tools\" array found (expected a tools/list response)")
}

// FingerprintFile reads a tools/list JSON file and fingerprints it.
func FingerprintFile(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // file chosen by the user via --tools
	if err != nil {
		return "", fmt.Errorf("tools file: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return "", fmt.Errorf("tools file %s: %w", path, err)
	}
	if len(b) > MaxSize {
		return "", fmt.Errorf("tools file %s: larger than %d bytes", path, MaxSize)
	}
	d, err := Fingerprint(b)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return d, nil
}
