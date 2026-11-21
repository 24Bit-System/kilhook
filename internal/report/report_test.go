package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/24Bit-System/kilhook/internal/diff"
	"github.com/24Bit-System/kilhook/internal/fuzz"
	"github.com/24Bit-System/kilhook/internal/spec"
)

func sample() *Report {
	r := New()
	r.Generated = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	r.Request = Request{
		File:        "requests/getpet.kh",
		Name:        "Get Pet",
		Method:      "GET",
		URL:         "http://localhost:8080/pets/42",
		Headers:     map[string]string{"Accept": "application/json"},
		BodyPreview: "",
	}
	r.Response = &Response{Status: 200, DurationMS: 12, SizeBytes: 48, ContentType: "application/json"}
	r.Spec = &SpecSection{
		Source:    "specs/petstore.yaml",
		Operation: "GET /pets/{id}",
		StatusKey: "200",
		MediaType: "application/json",
		Violations: []spec.Violation{
			{Path: "response.id", Message: "got string, want integer", Operation: "GET /pets/{id}", Status: 200},
		},
	}
	r.Fuzz = &FuzzSection{
		Requests:   12,
		DurationMS: 250,
		RateLimit:  5,
		Targets:    []string{"path.1"},
		Methods:    []string{"injection"},
		Summary:    map[string]int{fuzz.SeverityHigh: 1},
		Findings: []fuzz.Finding{
			{
				Kind: fuzz.KindErrorText, Severity: fuzz.SeverityHigh, Target: "path.1",
				Payload:  "a' OR 1=1--",
				Evidence: `syntax error at or near "OR" <script>alert(1)</script>`,
			},
		},
	}
	r.Diff = &DiffSection{
		BaselineFile: ".kilhook/baselines/getpet.json",
		Format:       "json",
		Changes:      []diff.Change{{Path: "response.name", Kind: diff.Changed, Before: `"a"`, After: `"b"`}},
	}
	r.Warnings = []string{"fuzz.targets: body.email skipped"}
	r.SortWarnings()
	r.SetExitCode()
	return r
}

func TestTextReport(t *testing.T) {
	r := sample()
	out := r.Text()
	for _, want := range []string{"problems found", "GET http://localhost:8080/pets/42", "response.id", "[high]", "diff vs"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
}

func TestHTMLReportIsStandaloneAndEscaped(t *testing.T) {
	r := sample()
	out, err := r.HTML()
	if err != nil {
		t.Fatal(err)
	}
	html := string(out)
	if !strings.HasPrefix(html, "<!DOCTYPE html>") {
		t.Fatal("not a standalone html document")
	}
	for _, want := range []string{"Get Pet", "response.id", "problems found", "kilhook 0.1.0"} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
	}
	// Payload evidence must be escaped, never live markup.
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Error("evidence was not HTML-escaped")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("escaped evidence missing from output")
	}
	// No external assets: a standalone export must open offline.
	for _, bad := range []string{"<link", "<script src", `href="http`, `src="http`} {
		if strings.Contains(html, bad) {
			t.Errorf("html references external asset %q", bad)
		}
	}
}

func TestJSONReportRoundTrip(t *testing.T) {
	r := sample()
	data, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Request.Name != r.Request.Name || back.ExitCode != 1 || back.Version != Version {
		t.Fatalf("round trip lost data: %+v", back)
	}
	if len(back.Fuzz.Findings) != 1 || back.Fuzz.Findings[0].Payload != "a' OR 1=1--" {
		t.Fatalf("findings lost: %+v", back.Fuzz)
	}
}

func TestSplitAdvisoryMovesTimingOutOfFindings(t *testing.T) {
	r := New()
	r.Fuzz = &FuzzSection{Findings: []fuzz.Finding{
		{Kind: fuzz.KindStatus, Severity: fuzz.SeverityHigh},
		{Kind: fuzz.KindTiming, Severity: fuzz.SeverityInfo, Advisory: true},
	}}
	r.SplitAdvisory()
	if len(r.Fuzz.Findings) != 1 || len(r.Fuzz.Advisory) != 1 {
		t.Fatalf("findings=%d advisory=%d", len(r.Fuzz.Findings), len(r.Fuzz.Advisory))
	}
	if got := r.Fuzz.Summary[fuzz.SeverityInfo]; got != 0 {
		t.Fatalf("summary must be recomputed over the split findings: %v", r.Fuzz.Summary)
	}
	if got := r.Fuzz.Summary[fuzz.SeverityHigh]; got != 1 {
		t.Fatalf("summary lost the surviving finding: %v", r.Fuzz.Summary)
	}
	r.SetExitCode()
	if r.ExitCode != 1 {
		t.Fatal("a real finding must still fail the run")
	}
}

func TestSkippedFuzzRunWithNoFindingsIsIncomplete(t *testing.T) {
	r := New()
	r.Warnings = []string{"fuzz skipped: api.example.com is not localhost (pass --allow-nonlocal to override)"}
	r.SetExitCode()
	if r.ExitCode != 2 {
		t.Fatalf("exit code = %d, want 2 when a declared fuzz pass was refused", r.ExitCode)
	}
	if !strings.Contains(r.Text(), "incomplete") {
		t.Fatalf("text verdict should say incomplete:\n%s", r.Text())
	}
}

func TestAbortedRunWithNoFindingsIsIncomplete(t *testing.T) {
	r := New()
	r.Fuzz = &FuzzSection{Requests: 3, Aborted: "context canceled"}
	r.SetExitCode()
	if r.ExitCode != 2 {
		t.Fatalf("exit code = %d, want 2 for an aborted run with no findings", r.ExitCode)
	}
	if !strings.Contains(r.Text(), "incomplete") {
		t.Fatalf("text verdict should say incomplete:\n%s", r.Text())
	}
	html, err := r.HTML()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), ">incomplete<") {
		t.Fatal("html verdict badge should say incomplete")
	}

	// Findings still outrank the abort: a stopped run that already saw a 500
	// is "problems found", not merely incomplete.
	r.Fuzz.Findings = []fuzz.Finding{{Kind: fuzz.KindStatus, Severity: fuzz.SeverityHigh}}
	r.SetExitCode()
	if r.ExitCode != 1 {
		t.Fatalf("exit code = %d, want 1 when findings exist", r.ExitCode)
	}
}

func TestExitCodeClean(t *testing.T) {
	r := New()
	r.SetExitCode()
	if r.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", r.ExitCode)
	}
	r.Fuzz = &FuzzSection{Findings: []fuzz.Finding{{Kind: fuzz.KindTiming, Advisory: true}}}
	r.SplitAdvisory()
	r.SetExitCode()
	if r.ExitCode != 0 {
		t.Fatalf("advisory-only run must be clean, got %d", r.ExitCode)
	}
}

func TestHighSeverityCount(t *testing.T) {
	r := sample()
	if got := r.HighSeverityCount(); got != 1 {
		t.Fatalf("high = %d", got)
	}
	if got := r.ClassSummary(); !strings.Contains(got, "1 finding(s)") || !strings.Contains(got, "1 violation(s)") {
		t.Fatalf("summary = %q", got)
	}
}

func TestJSONAlwaysEmitsTheListKeys(t *testing.T) {
	r := New()
	r.Request = Request{Method: "GET", URL: "http://localhost/x", BodyBytes: 0}
	r.Response = &Response{Status: 200}
	r.Spec = &SpecSection{Source: "s.yaml", Operation: "GET /x"}
	r.Fuzz = &FuzzSection{Requests: 1}
	r.Diff = &DiffSection{Format: "json"}

	data, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"warnings"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("top-level %q is missing from the JSON", key)
		}
	}
	for section, key := range map[string]string{
		"spec": "violations",
		"fuzz": "findings",
		"diff": "changes",
	} {
		obj, ok := raw[section].(map[string]any)
		if !ok {
			t.Fatalf("section %q missing", section)
		}
		if _, ok := obj[key]; !ok {
			t.Errorf("%s.%s is missing from the JSON", section, key)
		}
	}
}
