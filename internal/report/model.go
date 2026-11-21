// Package report aggregates one run into a single serializable report and
// renders it as a standalone HTML file.
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/24Bit-System/kilhook/internal/diff"
	"github.com/24Bit-System/kilhook/internal/fuzz"
	"github.com/24Bit-System/kilhook/internal/spec"
)

// Version is stamped into every report so an exported file can be traced back
// to the build that produced it.
const Version = "0.1.0"

// WarnFuzzSkippedPrefix marks the warning emitted when a declared fuzz pass is
// refused by the loopback guard. A requested security check that did not run
// makes the run incomplete, not clean.
const WarnFuzzSkippedPrefix = "fuzz skipped:"

// Request describes what was sent.
type Request struct {
	File        string            `json:"file,omitempty"`
	Name        string            `json:"name"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers,omitempty"`
	Query       map[string]string `json:"query,omitempty"`
	BodyPreview string            `json:"body_preview,omitempty"`
	BodyBytes   int               `json:"body_bytes"`
}

// Response describes what came back.
type Response struct {
	Status      int    `json:"status"`
	DurationMS  int64  `json:"duration_ms"`
	SizeBytes   int    `json:"size_bytes"`
	ContentType string `json:"content_type,omitempty"`
	BodyPreview string `json:"body_preview,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

// FuzzSection summarises a fuzz pass.
type FuzzSection struct {
	Requests        int            `json:"requests"`
	Skipped         int            `json:"skipped"`
	TransportErrors int            `json:"transport_errors"`
	DurationMS      int64          `json:"duration_ms"`
	Aborted         string         `json:"aborted,omitempty"`
	Summary         map[string]int `json:"summary"`
	Findings        []fuzz.Finding `json:"findings"`
	Advisory        []fuzz.Finding `json:"advisory,omitempty"`
	Targets         []string       `json:"targets,omitempty"`
	Methods         []string       `json:"methods,omitempty"`
	RateLimit       float64        `json:"rate_limit,omitempty"`
}

// SpecSection summarises contract validation.
type SpecSection struct {
	Source     string           `json:"source"`
	Operation  string           `json:"operation"`
	SpecPath   string           `json:"spec_path,omitempty"`
	StatusKey  string           `json:"status_key,omitempty"`
	MediaType  string           `json:"media_type,omitempty"`
	Violations []spec.Violation `json:"violations"`
	Skipped    string           `json:"skipped,omitempty"`
	Notes      []string         `json:"notes"`
}

// DiffSection summarises comparison against a baseline.
type DiffSection struct {
	BaselineFile string        `json:"baseline_file,omitempty"`
	Format       string        `json:"format"`
	Changes      []diff.Change `json:"changes"`
	Drift        []spec.Drift  `json:"drift,omitempty"`
}

// Report is the single object the UI renders and the HTML export serialises.
type Report struct {
	Tool       string       `json:"tool"`
	Version    string       `json:"version"`
	Generated  time.Time    `json:"generated"`
	Request    Request      `json:"request"`
	Response   *Response    `json:"response,omitempty"`
	Fuzz       *FuzzSection `json:"fuzz,omitempty"`
	Spec       *SpecSection `json:"spec,omitempty"`
	Diff       *DiffSection `json:"diff,omitempty"`
	Warnings   []string     `json:"warnings"`
	DurationMS int64        `json:"duration_ms"`
	// ExitCode is the CLI verdict: 0 clean, 1 findings/violations.
	ExitCode int `json:"exit_code"`
}

// New returns an empty report stamped with the tool version.
func New() *Report {
	return &Report{Tool: "kilhook", Version: Version, Generated: time.Now().UTC()}
}

// JSON renders the report as indented JSON.
//
// Empty lists are normalised to [] rather than null or a missing key: consumers
// key off spec.violations, fuzz.findings and diff.changes unconditionally.
func (r *Report) JSON() ([]byte, error) {
	if r.Fuzz != nil {
		if r.Fuzz.Findings == nil {
			r.Fuzz.Findings = []fuzz.Finding{}
		}
		if r.Fuzz.Summary == nil {
			r.Fuzz.Summary = map[string]int{}
		}
	}
	if r.Spec != nil {
		if r.Spec.Violations == nil {
			r.Spec.Violations = []spec.Violation{}
		}
		if r.Spec.Notes == nil {
			r.Spec.Notes = []string{}
		}
	}
	if r.Diff != nil {
		if r.Diff.Changes == nil {
			r.Diff.Changes = []diff.Change{}
		}
	}
	if r.Warnings == nil {
		r.Warnings = []string{}
	}
	return json.MarshalIndent(r, "", "  ")
}

// FindingCount returns the number of actionable fuzz findings (advisory
// observations are not counted).
func (r *Report) FindingCount() int {
	if r.Fuzz == nil {
		return 0
	}
	return len(r.Fuzz.Findings)
}

// ViolationCount returns the number of contract violations.
func (r *Report) ViolationCount() int {
	if r.Spec == nil {
		return 0
	}
	return len(r.Spec.Violations)
}

// HighSeverityCount returns findings of high severity.
func (r *Report) HighSeverityCount() int {
	if r.Fuzz == nil {
		return 0
	}
	n := 0
	for _, f := range r.Fuzz.Findings {
		if f.Severity == fuzz.SeverityHigh {
			n++
		}
	}
	return n
}

// SetExitCode applies the documented verdict: any non-advisory finding (all
// severities, including low) or any contract violation fails the run with 1;
// advisory observations are split out beforehand and never fail it. An aborted
// or guard-skipped fuzz pass that found nothing is incomplete rather than clean, so it exits 2:
// "no findings" there means "nothing was observed", not "nothing is wrong".
func (r *Report) SetExitCode() {
	if r.FindingCount() > 0 || r.ViolationCount() > 0 {
		r.ExitCode = 1
		return
	}
	if r.Fuzz != nil && r.Fuzz.Aborted != "" {
		r.ExitCode = 2
		return
	}
	// The loopback guard skips fuzzing entirely, so there is no FuzzSection to
	// carry an Aborted flag. A declared fuzz pass that never ran is still an
	// incomplete run rather than a clean one.
	for _, w := range r.Warnings {
		if strings.HasPrefix(w, WarnFuzzSkippedPrefix) {
			r.ExitCode = 2
			return
		}
	}
	r.ExitCode = 0
}

// SplitAdvisory moves advisory-only observations out of the findings list so a
// timing hint can never look like a bug.
func (r *Report) SplitAdvisory() {
	if r.Fuzz == nil {
		return
	}
	var findings, advisory []fuzz.Finding
	for _, f := range r.Fuzz.Findings {
		if f.Advisory {
			advisory = append(advisory, f)
			continue
		}
		findings = append(findings, f)
	}
	r.Fuzz.Findings = findings
	r.Fuzz.Advisory = advisory
	// The engine computes Summary before the split; recompute it over the
	// findings that survive so the exported JSON can never claim counts that
	// the findings array no longer contains.
	r.Fuzz.Summary = fuzz.CountBySeverity(findings)
}

// SortWarnings keeps report output deterministic.
func (r *Report) SortWarnings() {
	sort.Strings(r.Warnings)
}

// ClassSummary is a tiny helper used by the text and HTML renderers.
func (r *Report) ClassSummary() string {
	return fmt.Sprintf("%d finding(s), %d violation(s)", r.FindingCount(), r.ViolationCount())
}
