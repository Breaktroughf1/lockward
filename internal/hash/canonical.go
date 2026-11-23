package hash

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"unicode/utf8"
)

// CanonicalJSON returns the canonical encoding of v defined in SPEC §2:
// UTF-8, object keys sorted bytewise, two-space indentation, "\n" line endings
// and a trailing newline. v is first marshalled with encoding/json, so struct
// tags (including omitempty) apply. Numbers keep their literal form.
//
// Strings are escaped minimally: '"' and '\' are backslash-escaped, "\n",
// "\r" and "\t" use their short forms, other control characters (U+0000 to
// U+001F and U+007F) use lowercase \u00xx, and everything else is written as
// raw UTF-8. Invalid UTF-8 is an error rather than being silently replaced.
func CanonicalJSON(v any) ([]byte, error) {
	if !validUTF8(reflect.ValueOf(v), 0) {
		return nil, errors.New("canonical json: string is not valid UTF-8")
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical json: marshal: %w", err)
	}
	return CanonicalizeJSON(raw)
}

// validUTF8 walks v and reports whether every string and map key is valid
// UTF-8. encoding/json would otherwise replace invalid bytes silently, which
// could make two different inputs encode identically.
func validUTF8(v reflect.Value, depth int) bool {
	if depth > maxDepth || !v.IsValid() {
		return true
	}
	switch v.Kind() {
	case reflect.String:
		return utf8.ValidString(v.String())
	case reflect.Pointer, reflect.Interface:
		return v.IsNil() || validUTF8(v.Elem(), depth+1)
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 {
			return true // []byte is base64-encoded
		}
		for i := range v.Len() {
			if !validUTF8(v.Index(i), depth+1) {
				return false
			}
		}
	case reflect.Map:
		it := v.MapRange()
		for it.Next() {
			if !validUTF8(it.Key(), depth+1) || !validUTF8(it.Value(), depth+1) {
				return false
			}
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() && !validUTF8(v.Field(i), depth+1) {
				return false
			}
		}
	}
	return true
}

// CanonicalizeJSON re-encodes an arbitrary JSON document canonically.
func CanonicalizeJSON(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("canonical json: input is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var val any
	if err := dec.Decode(&val); err != nil {
		return nil, fmt.Errorf("canonical json: decode: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("canonical json: trailing data after document")
	}
	var b bytes.Buffer
	if err := writeValue(&b, val, 0); err != nil {
		return nil, err
	}
	b.WriteByte('\n')
	return b.Bytes(), nil
}

func writeValue(b *bytes.Buffer, v any, depth int) error {
	if depth > maxDepth {
		return errors.New("canonical json: nesting too deep")
	}
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(t))
	case json.Number:
		b.WriteString(t.String())
	case string:
		return writeString(b, t)
	case []any:
		if len(t) == 0 {
			b.WriteString("[]")
			return nil
		}
		b.WriteString("[\n")
		for i, e := range t {
			indent(b, depth+1)
			if err := writeValue(b, e, depth+1); err != nil {
				return err
			}
			if i < len(t)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		indent(b, depth)
		b.WriteByte(']')
	case map[string]any:
		if len(t) == 0 {
			b.WriteString("{}")
			return nil
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("{\n")
		for i, k := range keys {
			indent(b, depth+1)
			if err := writeString(b, k); err != nil {
				return err
			}
			b.WriteString(": ")
			if err := writeValue(b, t[k], depth+1); err != nil {
				return err
			}
			if i < len(keys)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		indent(b, depth)
		b.WriteByte('}')
	default:
		return fmt.Errorf("canonical json: unsupported type %T", v)
	}
	return nil
}

// maxDepth bounds recursion on hostile input (THREAT_MODEL T8).
const maxDepth = 512

func indent(b *bytes.Buffer, depth int) {
	for range depth {
		b.WriteString("  ")
	}
}

const hexDigits = "0123456789abcdef"

func writeString(b *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return errors.New("canonical json: string is not valid UTF-8")
	}
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c < 0x20 || c == 0x7f:
			b.WriteString(`\u00`)
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0xf])
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return nil
}
