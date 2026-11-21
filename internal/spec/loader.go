// Package spec loads an OpenAPI document and validates responses against the
// operation's response schema. kin-openapi parses the document; validation is
// performed by santhosh-tekuri/jsonschema, which owns the response schema rules
// (project.md §6.1, §6.3 step 6).
package spec

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"gopkg.in/yaml.v3"

	"github.com/24Bit-System/kilhook/internal/strx"
)

// MaxSpecBytes bounds the spec read so a hostile or accidental giant file
// cannot exhaust memory.
const MaxSpecBytes = 8 << 20

// Document is a loaded OpenAPI document plus the raw tree used to hand response
// schemas to the JSON Schema compiler.
type Document struct {
	Path     string
	Doc      *openapi3.T
	Warnings []string

	raw map[string]any
}

// Load reads and parses an OpenAPI 3.0 / 3.1 document.
func Load(path string) (*Document, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("spec %s: %w", path, err)
	}
	defer file.Close()
	// Read through the limit instead of Stat-then-ReadFile: the file could
	// grow between the two calls and defeat the bound.
	data, err := io.ReadAll(io.LimitReader(file, MaxSpecBytes+1))
	if err != nil {
		return nil, fmt.Errorf("spec %s: %w", path, err)
	}
	if len(data) > MaxSpecBytes {
		return nil, fmt.Errorf("spec %s: exceeds the %d byte limit", path, MaxSpecBytes)
	}

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = false
	doc, err := loader.LoadFromData(data)
	if err != nil {
		return nil, fmt.Errorf("spec %s: %w", path, err)
	}

	d := &Document{Path: path, Doc: doc}
	if err := doc.Validate(context.Background()); err != nil {
		d.Warnings = append(d.Warnings, "spec does not fully validate: "+strx.Truncate(err.Error(), 300))
	}

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("spec %s: %w", path, err)
	}
	d.raw, _ = normalizeKeys(raw).(map[string]any)
	return d, nil
}

// normalizeKeys rewrites the map[any]any nodes yaml.v3 produces for mappings
// with non-string keys. The standard YAML style for OpenAPI status codes is
// unquoted (`responses:` → `200:`), which yaml.v3 resolves as !!int and
// decodes into map[any]any; without this pass the response lookup silently
// sees no responses at all and json.Marshal of a schema subtree fails.
// kin-openapi normalises its own tree the same way.
func normalizeKeys(v any) any {
	switch node := v.(type) {
	case map[any]any:
		out := make(map[string]any, len(node))
		for k, val := range node {
			out[fmt.Sprint(k)] = normalizeKeys(val)
		}
		return out
	case map[string]any:
		for k, val := range node {
			node[k] = normalizeKeys(val)
		}
		return node
	case []any:
		for i, val := range node {
			node[i] = normalizeKeys(val)
		}
		return node
	default:
		return v
	}
}

// Title returns the spec title, or "" when absent.
func (d *Document) Title() string {
	if d.Doc == nil || d.Doc.Info == nil {
		return ""
	}
	return d.Doc.Info.Title
}

// Match finds the operation for a method and a concrete request path.
type Match struct {
	SpecPath string
	Method   string
	Op       *openapi3.Operation
	Stripped int // path segments dropped to find a match
}

// MatchOperation finds the operation for method + request path. When the
// request carries a server base path that the spec does not declare, leading
// segments are stripped until a template matches.
func (d *Document) MatchOperation(method, requestPath string) (*Match, error) {
	method = strings.ToLower(method)
	segments := splitPath(requestPath)

	// strip <= len(segments) (not <) so a root-path request ("/", zero
	// segments) still gets its strip=0 attempt: login/token endpoints are
	// commonly declared as `post: /`.
	for strip := 0; strip <= 2 && strip <= len(segments); strip++ {
		candidate := "/" + strings.Join(segments[strip:], "/")
		best, bestScore := "", -1
		for _, tmpl := range d.Doc.Paths.Keys() {
			if !pathMatches(tmpl, candidate) {
				continue
			}
			item := d.Doc.Paths.Find(tmpl)
			if item == nil {
				continue
			}
			if item.GetOperation(strings.ToUpper(method)) == nil {
				continue
			}
			// Prefer the template with the most literal segments.
			score := literalScore(tmpl)
			if score > bestScore {
				best, bestScore = tmpl, score
			}
		}
		if best != "" {
			return &Match{
				SpecPath: best,
				Method:   method,
				Op:       d.Doc.Paths.Find(best).GetOperation(strings.ToUpper(method)),
				Stripped: strip,
			}, nil
		}
	}

	available := d.Doc.Paths.Keys()
	sort.Strings(available)
	return nil, fmt.Errorf("no operation %s %s in %s (declared paths: %s)",
		strings.ToUpper(method), requestPath, d.Path, strings.Join(available, ", "))
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// pathMatches reports whether a concrete path fits an OpenAPI path template.
func pathMatches(template, concrete string) bool {
	ts := splitPath(template)
	cs := splitPath(concrete)
	if len(ts) != len(cs) {
		return false
	}
	for i := range ts {
		if strings.HasPrefix(ts[i], "{") && strings.HasSuffix(ts[i], "}") {
			if cs[i] == "" {
				return false
			}
			continue
		}
		if ts[i] != cs[i] {
			return false
		}
	}
	return true
}

func literalScore(template string) int {
	score := 0
	for _, seg := range splitPath(template) {
		if !strings.HasPrefix(seg, "{") {
			score++
		}
	}
	return score
}
