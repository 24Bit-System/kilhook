package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/24Bit-System/kilhook/internal/diff"
	"github.com/24Bit-System/kilhook/internal/fuzz"
	"github.com/24Bit-System/kilhook/internal/spec"
)

func TestRedactRawQueryPreservesNonSensitivePairs(t *testing.T) {
	raw := "z=1&a=2&path=%2Ffoo&sp=a+b"
	got, changed := redactRawQuery(raw)
	if changed || got != raw {
		t.Fatalf("got %q changed=%v, want byte-identical", got, changed)
	}
	got, changed = redactRawQuery("token=secret;q=1&z=1")
	if !changed || strings.Contains(got, "secret") {
		t.Fatalf("semicolon-delimited credential survived: %q", got)
	}
}

func TestRedactURLDoesNotReencodeQueryForUserinfo(t *testing.T) {
	raw := "http://user:pass@example.com/p?z=1&a=2&path=%2Ffoo&sp=a+b"
	got := redactURL(raw)
	if strings.Contains(got, "pass@") || strings.Contains(got, "user@") {
		t.Fatalf("userinfo survived: %q", got)
	}
	// The query must be untouched: only userinfo was redacted.
	if !strings.HasSuffix(got, "?z=1&a=2&path=%2Ffoo&sp=a+b") {
		t.Fatalf("query was re-encoded/reordered: %q", got)
	}
	if got := redactURL("https://TOKEN123@example.test/x?pwd=secret&private_key=abc"); strings.Contains(got, "TOKEN123") || strings.Contains(got, "secret") || strings.Contains(got, "abc") {
		t.Fatalf("username or extended marker survived: %q", got)
	}
}

func TestRedactBodyHandlesMalformedAndMultipleDocuments(t *testing.T) {
	cases := []string{
		`{"token":"secret1"}` + "\n" + `{"token":"secret2"}`, // NDJSON
		`token=secret3&bad=%ZZ`,                               // malformed form
		"--BOUNDARY\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nsecret4\r\n--BOUNDARY--",
	}
	for i, body := range cases {
		got := string(redactBody([]byte(body)))
		for _, secret := range []string{"secret1", "secret2", "secret3", "secret4"} {
			if strings.Contains(got, secret) {
				t.Fatalf("case %d: secret %q survived: %q", i, secret, got)
			}
		}
	}
}

func TestRedactFuzzFindingsAndViolations(t *testing.T) {
	findings := []fuzz.Finding{{
		Payload:  "token=supersecret",
		Evidence: `error: Bearer abc.def123 in response`,
	}}
	got := redactFindings(findings)
	if strings.Contains(got[0].Payload, "supersecret") || strings.Contains(got[0].Evidence, "abc.def123") {
		t.Fatalf("finding credential survived: %+v", got)
	}
	violations := []spec.Violation{{Message: `expected string, got "token=leaked"`}}
	gotv := redactViolations(violations)
	if strings.Contains(gotv[0].Message, "leaked") {
		t.Fatalf("violation credential survived: %q", gotv[0].Message)
	}
}

func TestTextBaselineDiffIsRedacted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("session=NEWSECRET123\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	baseline := filepath.Join(dir, ".kilhook", "baselines", "text.json")
	if err := os.MkdirAll(filepath.Dir(baseline), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(baseline, []byte("session=OLDSECRET456\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "text.kh")
	raw := "format: 1\nname: Text\nmethod: GET\nurl: \"" + srv.URL + "\"\n---\n"
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := Run(context.Background(), path, Options{NoFuzz: true, NoSpec: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Diff == nil || rep.Diff.Format != "text" {
		t.Fatalf("expected a text diff, got %+v", rep.Diff)
	}
	for _, c := range rep.Diff.Changes {
		if strings.Contains(c.After, "NEWSECRET123") || strings.Contains(c.Before, "OLDSECRET456") {
			t.Fatalf("text diff credential survived: %+v", c)
		}
	}
}

func TestRedactChangesCoversOrdinaryFields(t *testing.T) {
	in := []diff.Change{{Path: "response.message", Kind: diff.Changed, After: `"token=abc123"`}}
	got := redactChanges(in)
	if strings.Contains(got[0].After, "abc123") {
		t.Fatalf("credential inside an ordinary field survived: %+v", got)
	}
}
