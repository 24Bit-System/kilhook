package spec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPickStatusKeyPrefersLowercaseClassOverDefault(t *testing.T) {
	responses := map[string]any{"2xx": map[string]any{}, "default": map[string]any{}}
	if got := pickStatusKey(responses, 200); got != "2xx" {
		t.Fatalf("pickStatusKey = %q, want 2xx", got)
	}
}

func TestViolationStatusUsesActualStatusForWildcards(t *testing.T) {
	spec := `openapi: 3.0.0
info: {title: T, version: "1"}
paths:
  /x:
    get:
      responses:
        "2xx":
          description: ok
          content:
            application/json:
              schema:
                type: object
                required: [id]
                properties:
                  id: {type: string}
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "spec.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := Load(specPath)
	if err != nil {
		t.Fatal(err)
	}
	m, err := doc.MatchOperation("get", "/x")
	if err != nil {
		t.Fatal(err)
	}
	res, err := doc.ValidateResponse(m, 200, "application/json", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Violations) == 0 {
		t.Fatal("expected a missing-required-field violation")
	}
	for _, v := range res.Violations {
		if v.Status != 200 {
			t.Fatalf("violation status = %d, want the wire status 200", v.Status)
		}
	}
}

func TestTopLevelRefKeepsNullable(t *testing.T) {
	spec := `openapi: 3.0.0
info: {title: T, version: "1"}
components:
  schemas:
    X:
      type: object
      required: [id]
      properties:
        id: {type: string}
paths:
  /x:
    get:
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/X"
                nullable: true
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "spec.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := Load(specPath)
	if err != nil {
		t.Fatal(err)
	}
	m, err := doc.MatchOperation("get", "/x")
	if err != nil {
		t.Fatal(err)
	}
	res, err := doc.ValidateResponse(m, 200, "application/json", []byte(`null`))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Violations) != 0 {
		t.Fatalf("a nullable response rejected null: %+v", res.Violations)
	}
}

func TestPickMediaTypeIsDeterministic(t *testing.T) {
	content := map[string]any{"APPLICATION/JSON": nil, "application/json": nil}
	first := pickMediaType(content, "")
	for i := 0; i < 20; i++ {
		if got := pickMediaType(content, ""); got != first {
			t.Fatalf("nondeterministic media type: %q vs %q", got, first)
		}
	}
}
