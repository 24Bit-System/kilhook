package format

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func mustParse(t *testing.T, path string) (*File, []string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	f, warnings, err := Parse(data)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return f, warnings
}

func TestParseLoginExample(t *testing.T) {
	f, warnings := mustParse(t, filepath.Join("testdata", "login.kh"))

	if f.Format != 1 || f.Name != "Login" || f.Method != "POST" {
		t.Fatalf("unexpected header fields: %+v", f)
	}
	if got, want := f.URL, "{{base_url}}/auth/login"; got != want {
		t.Errorf("url = %q, want %q", got, want)
	}
	if got, want := f.Headers["Content-Type"], "application/json"; got != want {
		t.Errorf("content-type = %q, want %q", got, want)
	}
	if f.Auth == nil || f.Auth.Type != AuthNone {
		t.Errorf("auth = %+v, want type none", f.Auth)
	}
	if got, want := f.Fuzz.Targets, []string{"body.email", "body.password", "header.X-Forwarded-For"}; !reflect.DeepEqual(got, want) {
		t.Errorf("targets = %v, want %v", got, want)
	}
	if f.Fuzz.MaxRequests != DefaultMaxRequests || f.Fuzz.RateLimit != DefaultRateLimit || f.Fuzz.PerHostConcurrency != DefaultPerHost {
		t.Errorf("defaults not applied: %+v", f.Fuzz)
	}
	if got, want := strings.TrimSpace(string(f.Body)), `{"email": "user@example.com", "password": "secret"}`; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

func TestParseRejectsMissingFormat(t *testing.T) {
	_, _, err := Parse([]byte("name: X\nmethod: GET\nurl: http://localhost:1/\n---\n"))
	if err == nil {
		t.Fatal("expected an error for a file without format")
	}
	if !strings.Contains(err.Error(), "format") {
		t.Errorf("error = %v, want it to mention format", err)
	}
}

func TestParseRejectsNoSeparator(t *testing.T) {
	_, _, err := Parse([]byte("format: 1\nname: X\n"))
	if err == nil || !strings.Contains(err.Error(), "separator") {
		t.Fatalf("err = %v, want separator error", err)
	}
}

func TestUnknownFieldsWarnNotFail(t *testing.T) {
	src := `format: 1
name: X
method: GET
url: http://localhost:1/x
future_field: 42
auth:
  type: none
  legacy_thing: true
---
`
	f, warnings, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("unknown fields must not be fatal: %v", err)
	}
	if f.Name != "X" {
		t.Fatalf("name = %q", f.Name)
	}
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{`"future_field"`, `"legacy_thing"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings missing %s: %v", want, warnings)
		}
	}
}

// TestMultipartBodyTargetsWarnAndSkip is the contract between the format and
// the fuzzer (project.md §5.5): declaring body.* targets on a multipart body is
// a warning plus a nil target set, never an error and never a silent no-op.
func TestMultipartBodyTargetsWarnAndSkip(t *testing.T) {
	src := `format: 1
name: Upload
method: POST
url: "http://localhost:1/upload"
headers:
  Content-Type: multipart/form-data; boundary=abc
fuzz:
  targets:
    - body.file
    - body.caption
    - header.X-Trace
---
--abc--
`
	f, warnings, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("multipart body targets must not be fatal: %v", err)
	}
	if f.Fuzz == nil {
		t.Fatal("fuzz block dropped")
	}
	if got := f.Fuzz.Targets; len(got) != 1 || got[0] != "header.X-Trace" {
		t.Fatalf("targets = %v, want only header.X-Trace", got)
	}
	var bodyWarnings, skipWarnings int
	for _, w := range warnings {
		if strings.Contains(w, "body.* targets skipped") {
			bodyWarnings++
		}
		if strings.Contains(w, "out of scope") {
			skipWarnings++
		}
	}
	if bodyWarnings != 1 || skipWarnings != 1 {
		t.Fatalf("warnings = %v, want exactly one body.* skip warning", warnings)
	}
}

func TestFormBodyTargetsSkipped(t *testing.T) {
	src := `format: 1
name: Form
method: POST
url: "http://localhost:1/form"
headers:
  Content-Type: application/x-www-form-urlencoded
fuzz:
  targets:
    - body.email
    - query.q
---
email=a
`
	f, warnings, _ := Parse([]byte(src))
	if got := f.Fuzz.Targets; len(got) != 1 || got[0] != "query.q" {
		t.Fatalf("targets = %v, want only query.q", got)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "out of scope") {
		t.Fatalf("warnings = %v", warnings)
	}
}

func TestPathIndexOutOfRangeSkipped(t *testing.T) {
	src := `format: 1
name: Item
method: GET
url: "http://localhost:1/users/42"
fuzz:
  targets:
    - path.0
    - path.1
    - path.7
---
`
	f, warnings, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, want := f.Fuzz.Targets, []string{"path.0", "path.1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "path.7") {
		t.Errorf("expected a warning naming path.7, got %v", warnings)
	}
}

func TestTemplatedURLDefersPathCheck(t *testing.T) {
	src := `format: 1
name: Item
method: GET
url: "{{base_url}}/users/42"
fuzz:
  targets:
    - path.0
    - path.1
---
`
	f, warnings, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Fuzz.Targets) != 2 {
		t.Fatalf("targets = %v, want both kept until the URL is resolved", f.Fuzz.Targets)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
}

func TestBodyTargetsOnTextBodySkipped(t *testing.T) {
	src := `format: 1
name: Raw
method: POST
url: "http://localhost:1/raw"
headers:
  Content-Type: text/plain
fuzz:
  targets:
    - body.x
---
hello
`
	f, warnings, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Fuzz.Targets) != 0 {
		t.Fatalf("targets = %v, want none", f.Fuzz.Targets)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "not JSON") {
		t.Errorf("warnings = %v", warnings)
	}
}

func TestAuthValidation(t *testing.T) {
	cases := []struct {
		name    string
		block   string
		wantErr string
	}{
		{"api key without in", "auth:\n  type: api_key\n  name: X-Key\n", "auth.in"},
		{"api key without name", "auth:\n  type: api_key\n  in: header\n", "auth.name"},
		{"unknown type", "auth:\n  type: magic\n", "auth.type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "format: 1\nname: X\nmethod: GET\nurl: http://localhost:1/\n" + tc.block + "---\n"
			_, _, err := Parse([]byte(src))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to mention %s", err, tc.wantErr)
			}
		})
	}
}

func TestUnknownFuzzMethodIsAnError(t *testing.T) {
	src := "format: 1\nname: X\nmethod: GET\nurl: http://localhost:1/\nfuzz:\n  methods:\n    - injections\n---\n"
	_, _, err := Parse([]byte(src))
	if err == nil || !strings.Contains(err.Error(), "unknown method") {
		t.Fatalf("err = %v", err)
	}
}

// TestRoundTrip is the §10.1 round-trip gate: parse → marshal → parse must be
// identical, and the body bytes must survive untouched.
func TestRoundTrip(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "*.kh"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no testdata: %v", err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			orig, warnings := mustParse(t, path)
			if len(warnings) != 0 {
				t.Fatalf("testdata must be warning-free: %v", warnings)
			}
			data, err := orig.Marshal()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			again, warnings, err := Parse(data)
			if err != nil {
				t.Fatalf("re-parse: %v\n%s", err, data)
			}
			if len(warnings) != 0 {
				t.Fatalf("re-parse warnings: %v\n%s", warnings, data)
			}
			if !bytes.Equal(orig.Body, again.Body) {
				t.Errorf("body changed:\n%q\n%q", orig.Body, again.Body)
			}
			// A second pass must be byte-identical (stable serialization).
			data2, err := again.Marshal()
			if err != nil {
				t.Fatalf("marshal 2: %v", err)
			}
			if !bytes.Equal(data, data2) {
				t.Errorf("serialization is not stable:\n%s\n---\n%s", data, data2)
			}
			orig.Body, again.Body = nil, nil
			if !reflect.DeepEqual(orig, again) {
				t.Errorf("round trip changed the file:\n%+v\n%+v\n%s", orig, again, data)
			}
		})
	}
}

func TestMarshalKeepsBodyVerbatim(t *testing.T) {
	body := "{\n  \"a\": 1,\n  \"b\": [1, 2]\n}\n"
	src := "format: 1\nname: X\nmethod: POST\nurl: http://localhost:1/\nheaders:\n  Content-Type: application/json\n---\n" + body
	f, _, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(out), "---\n"+body) {
		t.Fatalf("body not preserved:\n%s", out)
	}
}

func fuzzFile(extra string) []byte {
	return []byte("format: 1\nname: Limits\nmethod: GET\nurl: http://localhost:1/\nfuzz:\n  targets: [query.q]\n" + extra + "---\n")
}

func TestFuzzConfigBoundsAreValidated(t *testing.T) {
	cases := map[string]string{
		"nan rate":          "  rate_limit: .nan\n",
		"inf rate":          "  rate_limit: .inf\n",
		"negative rate":     "  rate_limit: -1\n",
		"tiny rate":         "  rate_limit: 0.001\n",
		"huge rate":         "  rate_limit: 20000\n",
		"huge max requests": "  max_requests: 1000001\n",
		"negative max":      "  max_requests: -1\n",
		"huge per host":     "  per_host_concurrency: 300\n",
		"negative per host": "  per_host_concurrency: -1\n",
		"huge timeout":      "timeout_ms: 3600001\n",
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Parse(fuzzFile(extra)); err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
		})
	}
}

func TestFuzzConfigAcceptsBoundaryValues(t *testing.T) {
	f, warnings, err := Parse(fuzzFile("  rate_limit: 0.01\n  max_requests: 1000000\n  per_host_concurrency: 256\n"))
	if err != nil {
		t.Fatal(err)
	}
	if f.Fuzz.RateLimit != 0.01 || f.Fuzz.MaxRequests != 1000000 || f.Fuzz.PerHostConcurrency != 256 {
		t.Fatalf("boundary values changed: %+v", f.Fuzz)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
}

func TestManagedHeaderTargetsWarnAndSkip(t *testing.T) {
	doc := []byte("format: 1\nname: H\nmethod: GET\nurl: http://localhost:1/\nfuzz:\n  targets: [header.Content-Length, header.Host, header.X-Test]\n---\n")
	f, warnings, err := Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"header.Host", "header.X-Test"}
	if !reflect.DeepEqual(f.Fuzz.Targets, want) {
		t.Fatalf("targets = %v, want %v", f.Fuzz.Targets, want)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "Content-Length") || !strings.Contains(joined, "managed") {
		t.Fatalf("missing managed-header warning: %v", warnings)
	}
}
