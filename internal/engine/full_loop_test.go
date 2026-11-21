package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFullLoopPostBodySpecDiff exercises the whole pipeline against a local
// server: POST with a JSON body, body/query/header/path fuzz targets, OpenAPI
// response validation, baseline write and a second-run diff, and an HTML
// export. No public network.
func TestFullLoopPostBodySpecDiff(t *testing.T) {
	var extra bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		name, _ := body["name"].(string)
		if name == "" {
			name = "base"
		}
		out := map[string]any{"id": 1, "name": name}
		if extra {
			out["extra"] = true
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()

	dir := t.TempDir()
	spec := `openapi: 3.0.0
info: {title: T, version: "1"}
paths:
  /pets:
    post:
      requestBody:
        content:
          application/json:
            schema: {type: object}
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: object
                required: [id, name]
                properties:
                  id: {type: integer}
                  name: {type: string}
`
	if err := os.WriteFile(filepath.Join(dir, "spec.yaml"), []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	request := "format: 1\nname: Full Loop\nmethod: POST\nurl: \"" + srv.URL + "/pets\"\n" +
		"headers:\n  Content-Type: application/json\n  X-Test: base\n" +
		"fuzz:\n  targets: [body.name, query.q, header.X-Test, path.0]\n  max_requests: 12\n  methods: [injection]\n" +
		"spec:\n  source: \"spec.yaml\"\n  operation: \"/pets post\"\n---\n{\"name\":\"base\"}\n"
	path := filepath.Join(dir, "full.kh")
	if err := os.WriteFile(path, []byte(request), 0o644); err != nil {
		t.Fatal(err)
	}

	// First pass stores the baseline without fuzzing.
	first, err := Run(context.Background(), path, Options{UpdateBaseline: true, NoFuzz: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.Response == nil || first.Response.Status != 200 {
		t.Fatalf("baseline response = %+v", first.Response)
	}
	if first.Spec == nil || len(first.Spec.Violations) != 0 {
		t.Fatalf("spec section = %+v", first.Spec)
	}
	if _, err := os.Stat(filepath.Join(dir, ".kilhook", "baselines", "full-loop.json")); err != nil {
		t.Fatalf("baseline not written: %v", err)
	}

	// Second pass changes the response shape and runs the full loop.
	extra = true
	second, err := Run(context.Background(), path, Options{RateLimit: 500}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.Fuzz == nil || second.Fuzz.Requests == 0 {
		t.Fatalf("fuzz did not run: %+v", second.Fuzz)
	}
	if second.Diff == nil {
		t.Fatal("expected a baseline diff")
	}
	added := false
	for _, c := range second.Diff.Changes {
		if c.Path == "response.extra" && c.Kind == "added" {
			added = true
		}
	}
	if !added {
		t.Fatalf("added field was not diffed: %+v", second.Diff.Changes)
	}
	if second.Spec == nil || len(second.Spec.Violations) != 0 {
		t.Fatalf("extra field should still satisfy the spec: %+v", second.Spec)
	}
	html, err := second.HTML()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "Full Loop") || !strings.Contains(string(html), "response.extra") {
		t.Fatal("HTML export is missing the request name or the diff")
	}
}
