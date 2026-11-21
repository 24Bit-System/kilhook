package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/24Bit-System/kilhook/internal/report"
)

const petstoreSpec = `openapi: 3.0.3
info:
  title: Test API
  version: 1.0.0
paths:
  /pets/{id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: pet
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/Pet"
components:
  schemas:
    Pet:
      type: object
      required: [id, name]
      properties:
        id:
          type: integer
        name:
          type: string
`

// newTestServer serves a clean pet, a 500 for injection-looking input, and an
// echo endpoint that reflects the query back.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		switch {
		case strings.Contains(q, "'"):
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `SQLSTATE[42000]: syntax error at or near "OR"`)
		case q != "":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"echo":"`+q+`","id":1,"name":"rex"}`)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":1,"name":"rex"}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func writeTemp(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func setupProject(t *testing.T, srvURL, fuzzBlock string) (dir, khPath string) {
	t.Helper()
	dir = t.TempDir()
	writeTemp(t, dir, "specs/petstore.yaml", petstoreSpec)
	writeTemp(t, dir, ".kilhook/env/dev.yaml", "base_url: \""+srvURL+"\"\nid: \"42\"\n")
	khPath = writeTemp(t, dir, "getpet.kh", `format: 1
name: Get Pet
method: GET
url: "{{base_url}}/pets/{{id}}"
headers:
  Accept: application/json
`+fuzzBlock+`spec:
  source: "specs/petstore.yaml"
---
`)
	return dir, khPath
}

func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, errOut, err := runCLIStreams(t, args...)
	return out + errOut, err
}

// runCLIStreams keeps stdout and stderr separate so machine-readable output can
// be parsed without note lines mixed in.
func runCLIStreams(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := newRootCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errOut.String(), err
}

func TestCleanRunExitsZero(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	srv := newTestServer(t)
	_, kh := setupProject(t, srv.URL, "")

	out, err := runCLI(t, "run", kh, "--env", "dev", "--no-diff")
	if err != nil {
		t.Fatalf("clean run failed: %v\n%s", err, out)
	}
	for _, want := range []string{"clean", "GET", "response: 200"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestFuzzFindsServerErrorAndExitsOne(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	srv := newTestServer(t)
	fuzzBlock := `fuzz:
  targets:
    - query.q
  methods:
    - injection
  max_requests: 20
  rate_limit: 1000
  per_host_concurrency: 2
`
	_, kh := setupProject(t, srv.URL, fuzzBlock)

	out, err := runCLI(t, "run", kh, "--env", "dev", "--no-diff")
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 1 {
		t.Fatalf("expected exit code 1, got %v\n%s", err, out)
	}
	if !strings.Contains(out, "[high]") {
		t.Errorf("no high-severity finding in output:\n%s", out)
	}
	if !strings.Contains(out, "problems found") {
		t.Errorf("verdict missing:\n%s", out)
	}
}

func TestContractViolationIsReported(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	// This server returns id as a string, which violates the spec's integer.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"one","name":"rex"}`)
	}))
	defer srv.Close()
	_, kh := setupProject(t, srv.URL, "")

	out, err := runCLI(t, "run", kh, "--env", "dev", "--no-diff")
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 1 {
		t.Fatalf("expected exit code 1, got %v\n%s", err, out)
	}
	if !strings.Contains(out, "response.id") {
		t.Errorf("violation path missing:\n%s", out)
	}
}

func TestJSONAndHTMLOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	srv := newTestServer(t)
	dir, kh := setupProject(t, srv.URL, "")

	htmlPath := filepath.Join(dir, "report.html")
	out, errOut, err := runCLIStreams(t, "run", kh, "--env", "dev", "--no-diff", "--json", "--html", htmlPath)
	if err != nil {
		t.Fatalf("run failed: %v\n%s%s", err, out, errOut)
	}
	if !strings.Contains(errOut, "report written to") {
		t.Errorf("expected the html note on stderr, got %q", errOut)
	}

	var rep report.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out)
	}
	if rep.Request.Name != "Get Pet" || rep.Response == nil || rep.Response.Status != 200 {
		t.Fatalf("report = %+v", rep)
	}
	if rep.Spec == nil || !strings.Contains(rep.Spec.Operation, "/pets/{id}") {
		t.Fatalf("spec section = %+v", rep.Spec)
	}

	html, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(html), "<!DOCTYPE html>") {
		t.Fatal("html export is not standalone")
	}
}

func TestBaselineRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	srv := newTestServer(t)
	dir, kh := setupProject(t, srv.URL, "")

	if out, err := runCLI(t, "run", kh, "--env", "dev", "--update-baseline"); err != nil {
		t.Fatalf("baseline write failed: %v\n%s", err, out)
	}
	baseline := filepath.Join(dir, ".kilhook", "baselines", "get-pet.json")
	if _, err := os.Stat(baseline); err != nil {
		t.Fatalf("baseline not written: %v", err)
	}

	// A second run compares against it and reports no differences.
	out, err := runCLI(t, "run", kh, "--env", "dev")
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "clean") {
		t.Errorf("expected clean verdict with no diff:\n%s", out)
	}
}

func TestUnknownVariableFailsClearly(t *testing.T) {
	srv := newTestServer(t)
	dir, _ := setupProject(t, srv.URL, "")
	kh := writeTemp(t, dir, "broken.kh", "format: 1\nname: Broken\nmethod: GET\nurl: \"{{base_url}}/pets/{{nope}}\"\n---\n")
	out, err := runCLI(t, "run", kh, "--env", "dev")
	if err == nil {
		t.Fatalf("expected an error\n%s", out)
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Fatalf("error should name the missing variable: %v", err)
	}
}
