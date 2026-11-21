// Package diff compares two responses: structured JSON diff first, line diff
// as a fallback for non-JSON bodies.
package diff

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"

	"github.com/24Bit-System/kilhook/internal/strx"
)

// Change kinds.
const (
	Added       = "added"
	Removed     = "removed"
	Changed     = "changed"
	TypeChanged = "type_changed"
)

// Change is one field-level difference.
type Change struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

// JSON compares two JSON documents field by field. Array indices are included
// in the path (response.users[3].email).
func JSON(before, after []byte) ([]Change, error) {
	b, err := decode(before)
	if err != nil {
		return nil, fmt.Errorf("baseline is not JSON: %w", err)
	}
	a, err := decode(after)
	if err != nil {
		return nil, fmt.Errorf("current response is not JSON: %w", err)
	}
	var out []Change
	out = walk("response", b, a, out)
	return out, nil
}

func decode(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	// Decoder.More() returns false for a next byte of '}' or ']', so it misses
	// cases like {"a":1}}. A second Decode must reach EOF: any other result
	// means another document (NDJSON) or malformed trailing bytes, both of
	// which would otherwise hide drift in the rest of the file.
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("trailing data after the first JSON value")
	}
	return v, nil
}

func walk(path string, before, after any, out []Change) []Change {
	bType, aType := typeName(before), typeName(after)
	if bType != aType {
		return append(out, Change{
			Path:   path,
			Kind:   TypeChanged,
			Before: render(before),
			After:  render(after),
		})
	}

	switch b := before.(type) {
	case map[string]any:
		a := after.(map[string]any)
		for _, k := range sortedKeys(b) {
			child := path + "." + k
			av, ok := a[k]
			if !ok {
				out = append(out, Change{Path: child, Kind: Removed, Before: render(b[k])})
				continue
			}
			out = walk(child, b[k], av, out)
		}
		for _, k := range sortedKeys(a) {
			if _, ok := b[k]; !ok {
				out = append(out, Change{Path: path + "." + k, Kind: Added, After: render(a[k])})
			}
		}
	case []any:
		a := after.([]any)
		for i := 0; i < len(b) && i < len(a); i++ {
			out = walk(path+"["+strconv.Itoa(i)+"]", b[i], a[i], out)
		}
		for i := len(a); i < len(b); i++ {
			out = append(out, Change{Path: path + "[" + strconv.Itoa(i) + "]", Kind: Removed, Before: render(b[i])})
		}
		for i := len(b); i < len(a); i++ {
			out = append(out, Change{Path: path + "[" + strconv.Itoa(i) + "]", Kind: Added, After: render(a[i])})
		}
	default:
		if !equal(before, after) {
			out = append(out, Change{Path: path, Kind: Changed, Before: render(before), After: render(after)})
		}
	}
	return out
}

func equal(a, b any) bool {
	if an, ok := a.(json.Number); ok {
		if bn, ok := b.(json.Number); ok {
			// Identical literals are equal by definition (and the fast path).
			if an.String() == bn.String() {
				return true
			}
			// Int64 first: float64 rounds silently above 2^53, so snowflake
			// IDs like 1234567890123456789 vs ...790 would compare equal.
			if ai, aerr := an.Int64(); aerr == nil {
				if bi, berr := bn.Int64(); berr == nil {
					return ai == bi
				}
			}
			af, aerr := an.Float64()
			bf, berr := bn.Float64()
			if aerr == nil && berr == nil {
				return af == bf
			}
			return false
		}
	}
	return render(a) == render(b)
}

func typeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case json.Number, float64, int, int64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "unknown"
	}
}

func render(v any) string {
	switch val := v.(type) {
	case nil:
		return "null"
	case string:
		return strconv.Quote(strx.Truncate(val, 200))
	case json.Number:
		return val.String()
	case bool:
		if val {
			return "true"
		}
		return "false"
	case []any:
		return fmt.Sprintf("array(%d)", len(val))
	case map[string]any:
		return fmt.Sprintf("object(%d)", len(val))
	default:
		b, err := json.Marshal(val)
		if err != nil {
			return fmt.Sprint(val)
		}
		return string(b)
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// IsJSON reports whether data parses as JSON.
func IsJSON(data []byte) bool {
	_, err := decode(data)
	return err == nil
}

// Summary renders a one-line description of a change for terminals.
func (c Change) Summary() string {
	switch c.Kind {
	case Added:
		return fmt.Sprintf("+ %s = %s", c.Path, c.After)
	case Removed:
		return fmt.Sprintf("- %s (was %s)", c.Path, c.Before)
	case TypeChanged:
		return fmt.Sprintf("~ %s type %s -> %s", c.Path, c.Before, c.After)
	default:
		return fmt.Sprintf("~ %s %s -> %s", c.Path, c.Before, c.After)
	}
}
