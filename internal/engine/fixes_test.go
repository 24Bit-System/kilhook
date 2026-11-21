package engine

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/24Bit-System/kilhook/internal/diff"
	"github.com/24Bit-System/kilhook/internal/format"
)

func TestRedactQueryAndURL(t *testing.T) {
	q := redactQuery(map[string]string{
		"api_key": "secret",
		"token":   "tok",
		"q":       "pets",
	})
	if q["api_key"] != redacted || q["token"] != redacted {
		t.Fatalf("sensitive query values survived: %v", q)
	}
	if q["q"] != "pets" {
		t.Fatalf("ordinary query value changed: %v", q)
	}

	raw := "https://user:pass@example.test/x?api_key=abc&q=1"
	got := redactURL(raw)
	if strings.Contains(got, "pass") || strings.Contains(got, "abc") {
		t.Fatalf("credentials survived URL redaction: %s", got)
	}
	if !strings.Contains(got, "q=1") {
		t.Fatalf("ordinary query parameter was lost: %s", got)
	}
	if plain := "https://example.test/x?q=1"; redactURL(plain) != plain {
		t.Fatalf("URL without credentials should be unchanged")
	}
}

func TestRedactBodyJSONAndForm(t *testing.T) {
	jsonBody := []byte(`{"user":"bob","password":"hunter2","nested":{"access_token":"tok"}}`)
	got := string(redactBody(jsonBody))
	if strings.Contains(got, "hunter2") || strings.Contains(got, `"access_token":"tok"`) {
		t.Fatalf("JSON credentials survived: %s", got)
	}
	if !strings.Contains(got, "bob") {
		t.Fatalf("ordinary JSON value was lost: %s", got)
	}

	form := []byte("user=bob&password=hunter2&client_secret=shh")
	got = string(redactBody(form))
	if strings.Contains(got, "hunter2") || strings.Contains(got, "shh") {
		t.Fatalf("form credentials survived: %s", got)
	}
	if !strings.Contains(got, "user=bob") {
		t.Fatalf("ordinary form value was lost: %s", got)
	}

	opaque := []byte("a raw token that cannot be classified")
	if string(redactBody(opaque)) != string(opaque) {
		t.Fatal("opaque text must pass through unchanged")
	}
}

func TestRunRedactsSecretsInReport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"access_token":"response-secret"}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "secret.kh")
	url := strings.Replace(srv.URL, "http://", "http://user:pass@", 1) + `/x?api_key=url-secret&q=1`
	doc := "format: 1\nname: Secret\nmethod: POST\nurl: \"" + url + "\"\n" +
		"headers:\n  Authorization: Bearer top-secret\n" +
		"query:\n  token: query-secret\n" +
		"---\n" +
		`{"user":"bob","password":"hunter2"}`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := Run(context.Background(), path, Options{NoFuzz: true, NoSpec: true, NoDiff: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	blob := rep.Request.URL + "\n" + rep.Request.BodyPreview
	for _, secret := range []string{"url-secret", "top-secret", "query-secret", "hunter2", "response-secret"} {
		if strings.Contains(blob, secret) || strings.Contains(rep.Request.Headers["Authorization"], secret) {
			t.Fatalf("secret %q survived into the report: %+v", secret, rep.Request)
		}
	}
	for k, v := range rep.Request.Query {
		if (k == "token" || k == "api_key") && v != redacted {
			t.Fatalf("query %q not redacted: %q", k, v)
		}
	}
	if rep.Response == nil || strings.Contains(rep.Response.BodyPreview, "response-secret") {
		t.Fatalf("response token survived: %+v", rep.Response)
	}
	if strings.Contains(rep.Request.URL, "user:pass@") {
		t.Fatalf("URL userinfo password survived: %s", rep.Request.URL)
	}
	if !strings.Contains(rep.Request.BodyPreview, "bob") {
		t.Fatalf("ordinary body value was lost: %s", rep.Request.BodyPreview)
	}
}

func TestSpecFailureBecomesAWarning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "missing-spec.kh")
	doc := "format: 1\nname: No Spec\nmethod: GET\nurl: \"" + srv.URL + "/x\"\n" +
		"spec:\n  source: missing.yaml\n  operation: \"/x get\"\n---\n"
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := Run(context.Background(), path, Options{NoFuzz: true, NoDiff: true}, nil)
	if err != nil {
		t.Fatalf("a missing spec should not abort the run: %v", err)
	}
	if rep.Spec != nil {
		t.Fatalf("no spec section should be rendered: %+v", rep.Spec)
	}
	found := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "missing.yaml") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing spec should produce a warning, got %v", rep.Warnings)
	}
	if rep.ExitCode != 0 {
		t.Fatalf("a warning should not fail the run, exit = %d", rep.ExitCode)
	}
}

func TestLoadDocumentRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.kh")
	data := make([]byte, format.MaxFileBytes+1)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDocument(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want an exceeds-limit error", err)
	}
}

func TestRunRejectsInvalidOptions(t *testing.T) {
	cases := []Options{
		{RateLimit: math.NaN()},
		{RateLimit: math.Inf(1)},
		{RateLimit: -1},
		{MaxRequests: -1},
		{MaxRequests: format.MaxFuzzRequests + 1},
		{PerHost: -1},
		{PerHost: format.MaxPerHostLimit + 1},
		{TimeoutMS: -1},
		{TimeoutMS: format.MaxRequestTimeout + 1},
	}
	for _, opts := range cases {
		if _, err := Run(context.Background(), "does-not-matter.kh", opts, nil); err == nil {
			t.Fatalf("options %+v should be rejected", opts)
		}
	}
}

func TestRedactChangesHidesSensitiveValues(t *testing.T) {
	changes := []diff.Change{
		{Path: "response.access_token", Kind: "changed", Before: "old-token", After: "new-token"},
		{Path: "response.name", Kind: "changed", Before: "a", After: "b"},
	}
	got := redactChanges(changes)
	if got[0].Before != redacted || got[0].After != redacted {
		t.Fatalf("sensitive diff value survived: %+v", got[0])
	}
	if got[1].Before != "a" || got[1].After != "b" {
		t.Fatalf("ordinary diff value changed: %+v", got[1])
	}
}

func TestWriteMethodFuzzingWarns(t *testing.T) {
	if !isWriteMethod("post") || !isWriteMethod("DELETE") {
		t.Fatal("write methods should be recognised")
	}
	if isWriteMethod("GET") || isWriteMethod("HEAD") || isWriteMethod("OPTIONS") {
		t.Fatal("safe methods should not be flagged")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "write.kh")
	doc := "format: 1\nname: Write\nmethod: POST\nurl: \"" + srv.URL + "/x\"\nfuzz:\n  targets: [query.q]\n  max_requests: 1\n---\n{\"a\":1}"
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), path, Options{NoSpec: true, NoDiff: true, RateLimit: 100}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "create or modify server state") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a write-method warning, got %v", rep.Warnings)
	}
}
