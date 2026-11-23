package adapter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// ParseJSONC parses a JSON object that may contain // and /* */ comments and
// trailing commas (VS Code style JSONC). Numbers are kept as json.Number.
func ParseJSONC(b []byte) (map[string]any, error) {
	clean, err := StripJSONC(b)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(clean))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	if m == nil {
		return nil, errors.New("parse JSON: top level is not an object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse JSON: trailing data after object")
	}
	return m, nil
}

// StripJSONC removes comments and trailing commas outside strings. A UTF-8
// byte order mark is dropped.
func StripJSONC(b []byte) ([]byte, error) {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	out := make([]byte, 0, len(b))
	inStr := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			switch c {
			case '\\':
				if i+1 < len(b) {
					i++
					out = append(out, b[i])
				}
			case '"':
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			if i < len(b) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			end := bytes.Index(b[i+2:], []byte("*/"))
			if end < 0 {
				return nil, errors.New("parse JSON: unterminated block comment")
			}
			i += end + 3
			out = append(out, ' ')
		default:
			out = append(out, c)
		}
	}
	return removeTrailingCommas(out), nil
}

func removeTrailingCommas(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			if c == '\\' && i+1 < len(b) {
				i++
				out = append(out, b[i])
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
		}
		if c == ',' {
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// ParseTOML parses a TOML document into a generic map.
func ParseTOML(b []byte) (map[string]any, error) {
	var m map[string]any
	if err := toml.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse TOML: %w", err)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// Pointer builds a JSON Pointer (RFC 6901) from tokens.
func Pointer(tokens ...string) string {
	var b strings.Builder
	for _, t := range tokens {
		b.WriteByte('/')
		t = strings.ReplaceAll(t, "~", "~0")
		b.WriteString(strings.ReplaceAll(t, "/", "~1"))
	}
	return b.String()
}

// Obj returns m[key] as an object, or nil.
func Obj(m map[string]any, key string) map[string]any {
	v, _ := m[key].(map[string]any)
	return v
}

// Str returns m[key] as a string, or "".
func Str(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

// Bool returns m[key] as a bool, or false.
func Bool(m map[string]any, key string) bool {
	v, _ := m[key].(bool)
	return v
}

// Strings returns m[key] as a string slice; non-string elements are skipped.
func Strings(m map[string]any, key string) []string {
	return toStrings(m[key])
}

func toStrings(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return append([]string{}, t...)
	case string:
		return []string{t}
	}
	return nil
}

// List returns m[key] as a slice, or nil.
func List(m map[string]any, key string) []any {
	v, _ := m[key].([]any)
	return v
}

// SortedKeys returns the keys of m in sorted order.
func SortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Lookup follows a dotted path through nested objects.
func Lookup(m map[string]any, dotted string) (any, bool) {
	if v, ok := m[dotted]; ok {
		return v, true
	}
	cur := any(m)
	for part := range strings.SplitSeq(dotted, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = obj[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}
