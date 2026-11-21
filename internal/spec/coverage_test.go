package spec

import (
	"path/filepath"
	"strings"
	"testing"
)

// --- loader paths -----------------------------------------------------------

func TestTitle(t *testing.T) {
	d := loadTestSpec(t)
	if got := d.Title(); got != "Kilhook Test Petstore" {
		t.Fatalf("title = %q", got)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected an error for a missing spec")
	}
}

func TestLoadInvalidSpec(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.yaml")
	if err := writeFile(path, "openapi: 3.0.3\npaths: [oops]\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an unparseable spec")
	}
}

func TestLoadKeepsWarningsForLooseSpecs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "loose.yaml")
	// Parses, but is invalid: the path parameter is not declared.
	spec := "openapi: 3.0.3\n" +
		"info:\n  title: Loose\n  version: \"1\"\n" +
		"paths:\n  /pets/{id}:\n    get:\n      responses:\n        \"200\":\n          description: ok\n"
	if err := writeFile(path, spec); err != nil {
		t.Fatal(err)
	}
	d, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Warnings) == 0 {
		t.Fatal("expected a validation warning")
	}
	if len(d.Warnings[0]) > 400 {
		t.Fatalf("warning was not truncated: %d chars", len(d.Warnings[0]))
	}
}

func TestMatchOperationStopsStripping(t *testing.T) {
	d := loadTestSpec(t)
	if _, err := d.MatchOperation("GET", "/a/b/c/pets"); err == nil {
		t.Fatal("expected no match when more than 2 segments would have to be dropped")
	}
	if _, err := d.MatchOperation("GET", "/"); err == nil {
		t.Fatal("expected no match for the root path")
	}
}

func TestSplitPath(t *testing.T) {
	if got := splitPath(""); got != nil {
		t.Fatalf("splitPath(empty) = %v", got)
	}
	if got := splitPath("/a/b/"); len(got) != 2 {
		t.Fatalf("splitPath = %v", got)
	}
}

// --- response schema selection ---------------------------------------------

func TestResponseSchemaMissingPieces(t *testing.T) {
	const header = "openapi: 3.0.3\ninfo:\n  title: T\n  version: \"1\"\npaths:\n  /x:\n    get:\n"

	cases := []struct {
		name       string
		operation  string
		status     int
		ctype      string
		wantErr    string
		wantSkipIn string
	}{
		{
			name:      "no responses",
			operation: "      description: nothing declared\n",
			status:    200,
			wantErr:   "declares no responses",
		},
		{
			name: "no content",
			operation: `      responses:
        "200":
          description: ok
`,
			status:     200,
			wantSkipIn: "no content",
		},
		{
			name: "no json media type",
			operation: `      responses:
        "200":
          description: ok
          content:
            text/html:
              schema:
                type: string
`,
			status:     200,
			ctype:      "application/json",
			wantSkipIn: "no JSON media type",
		},
		{
			name: "no schema",
			operation: `      responses:
        "200":
          description: ok
          content:
            application/json: {}
`,
			status:     200,
			ctype:      "application/json",
			wantSkipIn: "declares no schema",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "s.yaml")
			if err := writeFile(path, header+tc.operation); err != nil {
				t.Fatal(err)
			}
			d, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			m, err := d.MatchOperation("GET", "/x")
			if err != nil {
				t.Fatal(err)
			}
			res, err := d.ValidateResponse(m, tc.status, tc.ctype, []byte(`{}`))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(res.Notes, " ") + res.Skipped
			if !strings.Contains(joined, tc.wantSkipIn) {
				t.Fatalf("notes=%v skipped=%q, want %q", res.Notes, res.Skipped, tc.wantSkipIn)
			}
		})
	}
}

func TestPickStatusKey(t *testing.T) {
	responses := map[string]any{"2XX": 1, "default": 2, "4xx": 3}
	if got := pickStatusKey(responses, 201); got != "2XX" {
		t.Fatalf("got %q, want 2XX", got)
	}
	if got := pickStatusKey(map[string]any{"2xx": 1}, 201); got != "2xx" {
		t.Fatalf("case-insensitive class fallback failed: %q", got)
	}
	if got := pickStatusKey(map[string]any{"default": 1}, 500); got != "default" {
		t.Fatalf("got %q, want default", got)
	}
	if got := pickStatusKey(map[string]any{"404": 1}, 200); got != "" {
		t.Fatalf("got %q, want no match", got)
	}
}

func TestPickMediaType(t *testing.T) {
	content := map[string]any{"application/json": 1, "text/plain": 2}
	if got := pickMediaType(content, "Application/JSON; charset=utf-8"); got != "application/json" {
		t.Fatalf("exact match failed: %q", got)
	}
	if got := pickMediaType(map[string]any{"application/vnd.api+json": 1}, "text/plain"); got != "application/vnd.api+json" {
		t.Fatalf("json fallback failed: %q", got)
	}
	if got := pickMediaType(map[string]any{"text/plain": 1}, ""); got != "" {
		t.Fatalf("got %q, want no match", got)
	}
}

// --- schema conversion -----------------------------------------------------

func TestConvertNullableForms(t *testing.T) {
	// nullable + type -> type union
	got := convert(map[string]any{"type": "string", "nullable": true}).(map[string]any)
	types, ok := got["type"].([]any)
	if !ok || len(types) != 2 || types[1] != "null" {
		t.Fatalf("type union = %#v", got["type"])
	}

	// nullable + enum -> null added to the enum
	got = convert(map[string]any{"enum": []any{"a"}, "nullable": true}).(map[string]any)
	if vals, ok := got["enum"].([]any); !ok || len(vals) != 2 || vals[1] != nil {
		t.Fatalf("enum = %#v", got["enum"])
	}

	// nullable with neither type nor enum -> anyOf with null
	got = convert(map[string]any{"nullable": true, "anyOf": []any{map[string]any{"type": "string"}}}).(map[string]any)
	anyOf, ok := got["anyOf"].([]any)
	if !ok || len(anyOf) != 2 {
		t.Fatalf("anyOf wrap = %#v", got)
	}
}

func TestConvertDropsOpenAPIOnlyKeywords(t *testing.T) {
	got := convert(map[string]any{
		"type":          "object",
		"example":       map[string]any{"a": 1},
		"xml":           map[string]any{"name": "x"},
		"discriminator": map[string]any{"propertyName": "kind"},
		"properties":    map[string]any{"a": map[string]any{"type": "string"}},
	}).(map[string]any)
	for _, banned := range []string{"example", "xml", "discriminator", "nullable"} {
		if _, ok := got[banned]; ok {
			t.Errorf("%q leaked into the JSON Schema", banned)
		}
	}
	if _, ok := got["properties"]; !ok {
		t.Error("properties were dropped")
	}
}

func TestConvertBooleanExclusiveBounds(t *testing.T) {
	got := convert(map[string]any{"minimum": 1, "exclusiveMinimum": true}).(map[string]any)
	if got["exclusiveMinimum"] != 1 {
		t.Fatalf("exclusiveMinimum = %#v", got["exclusiveMinimum"])
	}
	if _, ok := got["minimum"]; ok {
		t.Error("minimum should be replaced by the numeric exclusiveMinimum")
	}

	got = convert(map[string]any{"maximum": 9, "exclusiveMaximum": true}).(map[string]any)
	if got["exclusiveMaximum"] != 9 {
		t.Fatalf("exclusiveMaximum = %#v", got["exclusiveMaximum"])
	}

	got = convert(map[string]any{"maximum": 9, "exclusiveMaximum": false}).(map[string]any)
	if _, ok := got["exclusiveMaximum"]; ok {
		t.Error("exclusiveMaximum: false must be dropped")
	}
}

func TestParseStatus(t *testing.T) {
	if got := parseStatus("default"); got != 0 {
		t.Fatalf("parseStatus(default) = %d", got)
	}
	if got := parseStatus("404"); got != 404 {
		t.Fatalf("parseStatus(404) = %d", got)
	}
}

// --- drift I/O -------------------------------------------------------------

func TestLoadBaselineMissing(t *testing.T) {
	if _, err := LoadBaseline(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSaveBaselineReportsWriteErrors(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := writeFile(blocker, "file, not a directory"); err != nil {
		t.Fatal(err)
	}
	if err := SaveBaseline(filepath.Join(blocker, "nested", "x.json"), []byte("{}")); err == nil {
		t.Fatal("expected an error when the parent path is a file")
	}
}

func TestCompareRejectsNonJSON(t *testing.T) {
	if _, err := Compare([]byte("nope"), []byte("{}")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestOpenAPIV31Spec(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v31.yaml")
	spec := `openapi: 3.1.0
info:
  title: V31
  version: "1"
paths:
  /x:
    get:
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: object
                required: [id]
                properties:
                  id: {type: integer}
                  note: {type: [string, "null"]}
`
	if err := writeFile(path, spec); err != nil {
		t.Fatal(err)
	}
	d, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := d.MatchOperation("GET", "/x")
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.ValidateResponse(m, 200, "application/json", []byte(`{"id":1,"note":null}`))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("3.1 nullable union rejected: %+v", res.Violations)
	}
}
