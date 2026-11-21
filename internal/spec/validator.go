package spec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// errUndeclaredStatus marks "the wire status is not in the spec". It is a
// reportable contract violation, not a reason to abort the run: ValidateResponse
// turns it into a Violation and returns a nil error so fuzzing, diffing and the
// report still happen (a 503 from a spec declaring only 200 is precisely what a
// validation tool must surface).
var errUndeclaredStatus = errors.New("no response defined for status")

// Violation is one contract violation in a response.
type Violation struct {
	Path      string `json:"path"`
	Message   string `json:"message"`
	Operation string `json:"operation"`
	Status    int    `json:"status"`
}

// Result is the outcome of validating one response.
type Result struct {
	Operation  string      `json:"operation"`
	SpecPath   string      `json:"spec_path"`
	StatusKey  string      `json:"status_key"`
	MediaType  string      `json:"media_type"`
	Violations []Violation `json:"violations"`
	Skipped    string      `json:"skipped,omitempty"`
	Notes      []string    `json:"notes,omitempty"`
}

// OK reports whether the response satisfied the contract.
func (r *Result) OK() bool { return len(r.Violations) == 0 && r.Skipped == "" }

// ValidateResponse validates body against the matched operation's response
// schema for the given status code and content type.
func (d *Document) ValidateResponse(m *Match, status int, contentType string, body []byte) (*Result, error) {
	if m == nil {
		return nil, fmt.Errorf("no matched operation to validate against")
	}
	res := &Result{
		Operation: fmt.Sprintf("%s %s", strings.ToUpper(m.Method), m.SpecPath),
		SpecPath:  m.SpecPath,
	}
	if m.Stripped > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("matched after dropping %d leading path segment(s) (server base path)", m.Stripped))
	}

	schema, statusKey, mediaType, notes, err := d.responseSchema(m, status, contentType)
	res.StatusKey, res.MediaType = statusKey, mediaType
	res.Notes = append(res.Notes, notes...)
	if err != nil {
		if errors.Is(err, errUndeclaredStatus) {
			res.Violations = append(res.Violations, Violation{
				Path:      "response.status",
				Message:   err.Error(),
				Operation: res.Operation,
				Status:    status,
			})
			return res, nil
		}
		return res, err
	}
	if schema == nil {
		res.Skipped = fmt.Sprintf("no response schema for status %d (%s) on %s", status, statusKey, res.Operation)
		return res, nil
	}

	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		res.Skipped = "response body is not JSON"
		res.Notes = append(res.Notes, err.Error())
		return res, nil
	}

	compiled, err := compileResponseSchema(d, schema)
	if err != nil {
		return res, fmt.Errorf("response schema for %s: %w", res.Operation, err)
	}
	if err := compiled.Validate(instance); err != nil {
		verr, ok := err.(*jsonschema.ValidationError)
		if !ok {
			return res, err
		}
		collectViolations(verr, nil, res, status)
	}
	return res, nil
}

func collectViolations(e *jsonschema.ValidationError, prefix []string, res *Result, status int) {
	// v6 reports instance locations relative to the document root at the leaves,
	// but a cause chain can also carry a relative location. Only glue the parts
	// together when the leaf does not already contain the prefix.
	loc := e.InstanceLocation
	if !hasPrefix(loc, prefix) {
		loc = append(append([]string{}, prefix...), loc...)
	}
	if len(e.Causes) == 0 {
		res.Violations = append(res.Violations, Violation{
			Path:      jsonPath(loc),
			Message:   leafMessage(e),
			Operation: res.Operation,
			Status:    status,
		})
		return
	}
	for _, c := range e.Causes {
		collectViolations(c, loc, res, status)
	}
}

func hasPrefix(loc, prefix []string) bool {
	if len(prefix) == 0 {
		return true
	}
	if len(loc) < len(prefix) {
		return false
	}
	for i := range prefix {
		if loc[i] != prefix[i] {
			return false
		}
	}
	return true
}

// responseSchema digs the raw response schema out of the document tree. Using
// the raw tree keeps $ref values intact so they resolve against
// #/components/schemas inside our generated JSON Schema document.
func (d *Document) responseSchema(m *Match, status int, contentType string) (schema map[string]any, statusKey, mediaType string, notes []string, err error) {
	paths, _ := d.raw["paths"].(map[string]any)
	item, _ := paths[m.SpecPath].(map[string]any)
	op, _ := item[strings.ToLower(m.Method)].(map[string]any)
	responses, _ := op["responses"].(map[string]any)
	if responses == nil {
		return nil, "", "", nil, fmt.Errorf("operation %s %s declares no responses", strings.ToUpper(m.Method), m.SpecPath)
	}

	statusKey = pickStatusKey(responses, status)
	if statusKey == "" {
		return nil, "", "", nil, fmt.Errorf("%w %d (declared: %s)", errUndeclaredStatus, status, joinKeys(responses))
	}
	response, _ := responses[statusKey].(map[string]any)
	if response == nil {
		return nil, statusKey, "", nil, fmt.Errorf("response %q is not an object", statusKey)
	}

	content, _ := response["content"].(map[string]any)
	if len(content) == 0 {
		return nil, statusKey, "", []string{"response declares no content"}, nil
	}

	mediaType = pickMediaType(content, contentType)
	if mediaType == "" {
		return nil, statusKey, "", []string{fmt.Sprintf("no JSON media type for response %s (declared: %s)", statusKey, joinKeys(content))}, nil
	}
	media, _ := content[mediaType].(map[string]any)
	schema, _ = media["schema"].(map[string]any)
	if schema == nil {
		return nil, statusKey, mediaType, []string{fmt.Sprintf("media type %s declares no schema", mediaType)}, nil
	}
	return schema, statusKey, mediaType, notes, nil
}

func pickStatusKey(responses map[string]any, status int) string {
	if _, ok := responses[strconv.Itoa(status)]; ok {
		return strconv.Itoa(status)
	}
	class := fmt.Sprintf("%dXX", status/100)
	if _, ok := responses[class]; ok {
		return class
	}
	// Case-insensitive class fallback (a spec may write "2xx"). This must run
	// before "default": a declared status class is always more specific than a
	// catch-all, whatever casing the spec used.
	keys := make([]string, 0, len(responses))
	for k := range responses {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.EqualFold(k, class) {
			return k
		}
	}
	for _, k := range keys {
		if strings.EqualFold(k, "default") {
			return k
		}
	}
	return ""
}

func pickMediaType(content map[string]any, contentType string) string {
	keys := make([]string, 0, len(content))
	for k := range content {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	base := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if base != "" {
		for _, k := range keys {
			if strings.EqualFold(strings.Split(k, ";")[0], base) {
				return k
			}
		}
	}
	for _, k := range keys {
		if strings.EqualFold(k, "application/json") {
			return k
		}
	}
	for _, k := range keys {
		if strings.Contains(strings.ToLower(k), "json") {
			return k
		}
	}
	return ""
}

func compileResponseSchema(d *Document, schema map[string]any) (*jsonschema.Schema, error) {
	root := map[string]any{}
	if comps, ok := d.raw["components"].(map[string]any); ok {
		if schemas, ok := comps["schemas"].(map[string]any); ok {
			root["components"] = map[string]any{"schemas": convert(schemas)}
		}
	}
	// Convert the whole schema, including a top-level $ref. A special case that
	// copied only the $ref would drop sibling keywords such as nullable, which
	// nested refs already handle through convert(). In JSON Schema 2020-12 a
	// $ref may have siblings, and the components are embedded in root below.
	converted, ok := convert(schema).(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema is not an object")
	}
	for k, v := range converted {
		root[k] = v
	}

	data, err := json.Marshal(root)
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("generated schema is not valid JSON: %w", err)
	}

	c := jsonschema.NewCompiler()
	const url = "https://kilhook.local/response-schema.json"
	if err := c.AddResource(url, doc); err != nil {
		return nil, err
	}
	return c.Compile(url)
}

// convert rewrites OpenAPI 3.0 schema keywords into their JSON Schema
// 2020-12 equivalents. Keywords that are not JSON Schema are dropped so a
// spec-only field can never be mistaken for a validation rule.
func convert(node any) any {
	switch v := node.(type) {
	case map[string]any:
		nullable := false
		if b, ok := v["nullable"].(bool); ok && b {
			nullable = true
		}
		out := make(map[string]any, len(v))
		var exclusiveMin, exclusiveMax bool
		for k, val := range v {
			switch k {
			case "nullable", "xml", "discriminator", "example", "externalDocs":
				continue
			case "exclusiveMinimum":
				if b, ok := val.(bool); ok {
					exclusiveMin = b
					if b {
						if min, ok := v["minimum"]; ok {
							out["exclusiveMinimum"] = convert(min)
						}
					}
					continue
				}
			case "exclusiveMaximum":
				if b, ok := val.(bool); ok {
					exclusiveMax = b
					if b {
						if max, ok := v["maximum"]; ok {
							out["exclusiveMaximum"] = convert(max)
						}
					}
					continue
				}
			case "type":
				if t, ok := val.(string); ok && nullable {
					out["type"] = []any{t, "null"}
					continue
				}
			case "enum":
				if arr, ok := val.([]any); ok && nullable {
					out["enum"] = append(append([]any{}, arr...), nil)
					continue
				}
			case "required":
				if arr, ok := val.([]any); ok {
					out[k] = append([]any{}, arr...)
					continue
				}
			}
			out[k] = convert(val)
		}
		// A numeric exclusive bound replaces the inclusive one it was derived
		// from; leaving both would make the schema stricter than the spec.
		if exclusiveMin {
			delete(out, "minimum")
		}
		if exclusiveMax {
			delete(out, "maximum")
		}
		if nullable {
			if _, hasType := out["type"]; !hasType {
				if _, hasEnum := out["enum"]; !hasEnum {
					return map[string]any{"anyOf": []any{out, map[string]any{"type": "null"}}}
				}
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i := range v {
			out[i] = convert(v[i])
		}
		return out
	default:
		return v
	}
}

func jsonPath(tokens []string) string {
	b := strings.Builder{}
	b.WriteString("response")
	for _, t := range tokens {
		if t == "" {
			continue
		}
		if isIndex(t) {
			b.WriteString("[")
			b.WriteString(t)
			b.WriteString("]")
			continue
		}
		b.WriteString(".")
		b.WriteString(t)
	}
	return b.String()
}

func isIndex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// leafMessage keeps the human part of a jsonschema error and drops the schema
// URL noise, so reports read "expected string, got null".
func leafMessage(e *jsonschema.ValidationError) string {
	s := e.Error()
	if i := strings.LastIndex(s, "': "); i >= 0 {
		return strings.TrimSpace(s[i+3:])
	}
	if i := strings.LastIndex(s, ": "); i >= 0 {
		return strings.TrimSpace(s[i+2:])
	}
	return strings.TrimSpace(s)
}

func parseStatus(key string) int {
	if n, err := strconv.Atoi(key); err == nil {
		return n
	}
	return 0
}

func joinKeys(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}
