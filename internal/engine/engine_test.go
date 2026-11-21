package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscover(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "b.kh"), "format: 1\nname: Bee\nmethod: POST\nurl: \"http://localhost/b\"\n---\n")
	writeFile(t, filepath.Join(dir, "a.kh"), "format: 1\nname: Ay\nmethod: GET\nurl: \"http://localhost/a\"\n---\n")
	writeFile(t, filepath.Join(dir, "broken.kh"), "not: a request\n")
	writeFile(t, filepath.Join(dir, "notes.txt"), "ignored")
	writeFile(t, filepath.Join(dir, "nested", "c.kh"), "format: 1\n")

	files, err := Discover(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("got %d files, want 3 (subdirectories are not walked)", len(files))
	}
	if filepath.Base(files[0].Path) != "a.kh" || files[0].Name != "Ay" || files[0].Method != "GET" {
		t.Fatalf("first file = %+v", files[0])
	}
	if files[2].Error == "" {
		t.Fatalf("broken.kh should carry a parse error, got %+v", files[2])
	}
}

func TestDiscoverMissingDir(t *testing.T) {
	if _, err := Discover(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestRunMissingFile(t *testing.T) {
	if _, err := Run(context.Background(), filepath.Join(t.TempDir(), "nope.kh"), Options{}, nil); err == nil {
		t.Fatal("expected an error")
	}
}

func TestRunReportsUnknownVariable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v.kh")
	writeFile(t, path, "format: 1\nname: V\nmethod: GET\nurl: \"http://localhost/{{missing}}\"\n---\n")
	_, err := Run(context.Background(), path, Options{NoDiff: true}, nil)
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("err = %v, want the missing variable named", err)
	}
}

func TestRunAgainstAServerAndWriteBaseline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "ok.kh")
	writeFile(t, path, "format: 1\nname: OK Get\nmethod: GET\nurl: \""+srv.URL+"/ok\"\n---\n")

	rep, err := Run(context.Background(), path, Options{UpdateBaseline: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Response == nil || rep.Response.Status != 200 {
		t.Fatalf("response = %+v", rep.Response)
	}
	if rep.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", rep.ExitCode)
	}
	baseline := filepath.Join(dir, ".kilhook", "baselines", "ok-get.json")
	if _, err := os.Stat(baseline); err != nil {
		t.Fatalf("baseline not written: %v", err)
	}

	// Second run compares against it and finds no change.
	rep2, err := Run(context.Background(), path, Options{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Diff == nil {
		t.Fatal("expected a diff section on the second run")
	}
	if len(rep2.Diff.Changes) != 0 {
		t.Fatalf("unexpected changes: %+v", rep2.Diff.Changes)
	}
}

func TestRunPropagatesProgress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "f.kh")
	writeFile(t, path, "format: 1\nname: Fuzz\nmethod: GET\nurl: \""+srv.URL+"/x\"\nfuzz:\n  targets: [path.0]\n  max_requests: 60\n---\n")

	var lines []string
	rep, err := Run(context.Background(), path, Options{NoSpec: true, NoDiff: true, RateLimit: 200}, func(format string, args ...any) {
		lines = append(lines, format)
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Fuzz == nil || rep.Fuzz.Requests == 0 {
		t.Fatalf("fuzz did not run: %+v", rep.Fuzz)
	}
	if len(lines) == 0 {
		t.Fatal("expected progress callbacks")
	}
}

func TestLoadDocumentRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "edit.kh")
	writeFile(t, path, `format: 1
name: Edit Me
method: POST
url: "{{base_url}}/users"
headers:
  Content-Type: application/json
  X-Trace: abc
query:
  page: "2"
auth:
  type: bearer
  token: "{{token}}"
fuzz:
  targets: [body.name, query.page]
  max_requests: 60
spec:
  source: "../openapi.yaml"
  operation: "/users post"
---
{"name": "ada"}
`)

	doc, err := LoadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Name != "Edit Me" || doc.Method != "POST" || doc.Body != `{"name": "ada"}`+"\n" {
		t.Fatalf("doc = %+v", doc)
	}
	if len(doc.Headers) != 2 || doc.Headers[0].Name != "Content-Type" {
		t.Fatalf("headers = %+v", doc.Headers)
	}
	if doc.Auth.Type != "bearer" || doc.Auth.Token != "{{token}}" {
		t.Fatalf("auth = %+v", doc.Auth)
	}
	if len(doc.Fuzz.Targets) != 2 || doc.Fuzz.MaxRequests != 60 {
		t.Fatalf("fuzz = %+v", doc.Fuzz)
	}

	// Save unchanged: the file must stay loadable and keep every value.
	saved, err := SaveDocument(*doc)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Name != doc.Name || saved.URL != doc.URL || len(saved.Fuzz.Targets) != 2 {
		t.Fatalf("saved = %+v", saved)
	}

	// Edit and save again.
	saved.Headers = append(saved.Headers, KV{Name: "Accept", Value: "application/json"})
	saved.Body = `{"name": "grace"}` + "\n"
	saved.Fuzz.Targets = []string{"body.name"}
	if _, err := SaveDocument(*saved); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Body != `{"name": "grace"}`+"\n" {
		t.Fatalf("body = %q", reloaded.Body)
	}
	if len(reloaded.Headers) != 3 {
		t.Fatalf("headers = %+v", reloaded.Headers)
	}
	if len(reloaded.Fuzz.Targets) != 1 || reloaded.Fuzz.Targets[0] != "body.name" {
		t.Fatalf("targets = %+v", reloaded.Fuzz.Targets)
	}
}

func TestSaveDocumentDropsDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lean.kh")
	writeFile(t, path, "format: 1\nname: Lean\nmethod: GET\nurl: \"http://localhost/x\"\nfuzz:\n  targets: [query.q]\n---\n")

	doc, err := LoadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	// The parser fills the defaults in; saving must not write them back.
	if doc.Fuzz.MaxRequests != 500 || doc.Fuzz.Wordlist != "default" {
		t.Fatalf("expected parsed defaults, got %+v", doc.Fuzz)
	}
	if _, err := SaveDocument(*doc); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "query.q") {
		t.Fatalf("targets were dropped:\n%s", data)
	}
	for _, banned := range []string{"max_requests", "rate_limit", "per_host", "wordlist", "follow_redirects"} {
		if strings.Contains(string(data), banned) {
			t.Errorf("saved file contains the default %q:\n%s", banned, data)
		}
	}
}

func TestSaveDocumentValidates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.kh")
	writeFile(t, path, "format: 1\nname: Bad\nmethod: GET\nurl: \"http://localhost/x\"\n---\n")
	doc, err := LoadDocument(path)
	if err != nil {
		t.Fatal(err)
	}

	blank := *doc
	blank.Name = "  "
	if _, err := SaveDocument(blank); err == nil || !strings.Contains(err.Error(), "name") {
		t.Fatalf("err = %v, want a name error", err)
	}

	badAuth := *doc
	badAuth.Auth = AuthDoc{Type: "oauth3"}
	if _, err := SaveDocument(badAuth); err == nil || !strings.Contains(err.Error(), "auth") {
		t.Fatalf("err = %v, want an auth error", err)
	}
}

func TestLoadDocumentReportsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "future.kh")
	writeFile(t, path, "format: 1\nname: Future\nmethod: GET\nurl: \"http://localhost/x\"\npriority: high\n---\n")
	doc, err := LoadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.UnknownFields) != 1 || !strings.Contains(doc.UnknownFields[0], "priority") {
		t.Fatalf("unknown fields = %+v", doc.UnknownFields)
	}
}

func TestLoadDocumentMissingFile(t *testing.T) {
	if _, err := LoadDocument(filepath.Join(t.TempDir(), "nope.kh")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSaveDocumentIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stable.kh")
	writeFile(t, path, `format: 1
name: Stable
method: GET
url: "{{base_url}}/x"
headers:
  Accept: application/json
fuzz:
  targets: [query.q]
---
{"a": 1}
`)
	doc, err := LoadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SaveDocument(*doc); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err = LoadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SaveDocument(*doc); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("second save changed the file:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
}

func TestFileBaselineMayNotLeaveTheWorkspace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "escape.kh")
	doc := "format: 1\nname: Escape\nmethod: GET\nurl: " + srv.URL + "/x\nspec:\n  baseline: ../../outside.json\n---\n"
	writeFile(t, path, doc)

	opts := Options{UpdateBaseline: true, NoFuzz: true, NoSpec: true}
	_, err := Run(context.Background(), path, opts, nil)
	if err == nil {
		t.Fatal("a spec.baseline outside the workspace must be rejected")
	}
	if !strings.Contains(err.Error(), "leaves the workspace") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(dir), "outside.json")); statErr == nil {
		t.Fatal("the run wrote a baseline outside the workspace")
	}
}

func TestRunCustomWordlistResolvesNextToTheFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "custom.txt"), "alpha\nbeta\ngamma\n")
	path := filepath.Join(dir, "w.kh")
	writeFile(t, path, "format: 1\nname: W\nmethod: GET\nurl: \""+srv.URL+"/x?q=1\"\nfuzz:\n  targets: [query.q]\n  wordlist: custom.txt\n  max_requests: 9\n---\n")

	// The test binary's working directory is the package source directory, so
	// "custom.txt" only resolves when it is taken relative to the .kh file.
	rep, err := Run(context.Background(), path, Options{NoSpec: true, NoDiff: true, RateLimit: 500}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Fuzz == nil || rep.Fuzz.Requests != 3 {
		t.Fatalf("custom wordlist did not drive the fuzz pass: %+v", rep.Fuzz)
	}
}

func TestPreviewDoesNotSplitRunes(t *testing.T) {
	body := []byte(strings.Repeat("a", 10) + "→" + strings.Repeat("b", 10))
	got := preview(body, 11)
	if !strings.HasSuffix(got, "\n…") {
		t.Fatalf("expected a truncated preview, got %q", got)
	}
	if !utf8.ValidString(strings.TrimSuffix(got, "\n…")) {
		t.Fatalf("preview ends mid-rune: %q", got)
	}
	if short := preview(body, 100); string(body) != short {
		t.Fatalf("a body under the limit must pass through unchanged, got %q", short)
	}
}
