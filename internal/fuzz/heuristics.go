package fuzz

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	httpreq "github.com/24Bit-System/kilhook/internal/http"
	"github.com/24Bit-System/kilhook/internal/strx"
)

// Finding kinds.
const (
	KindStatus     = "status_anomaly"
	KindErrorText  = "error_string"
	KindReflection = "reflection"
	KindTiming     = "timing_outlier"
)

// Severity levels, most severe first.
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
	SeverityLow    = "low"
	SeverityInfo   = "info"
)

// Finding is one classified observation about a fuzzed response.
type Finding struct {
	Kind           string `json:"kind"`
	Severity       string `json:"severity"`
	Target         string `json:"target"`
	Payload        string `json:"payload"`
	StatusCode     int    `json:"status_code"`
	BaselineStatus int    `json:"baseline_status"`
	Evidence       string `json:"evidence"`
	DurationMS     int64  `json:"duration_ms,omitempty"`
	Advisory       bool   `json:"advisory,omitempty"`
	Count          int    `json:"count,omitempty"`
}

// Detector holds the tuned heuristics. Timing is advisory and disabled by
// default: on the internal corpus it is the largest source of false positives.
type Detector struct {
	ErrorPatterns    []*regexp.Regexp
	ReflectionOn     bool
	ReflectionMinLen int
	TimingEnabled    bool
	TimingFactor     float64
	TimingFloor      time.Duration
}

// DefaultDetector returns the v1 detection set.
func DefaultDetector() Detector {
	return Detector{
		ErrorPatterns:    defaultErrorPatterns,
		ReflectionOn:     true,
		ReflectionMinLen: 8,
		TimingEnabled:    false,
		TimingFactor:     3,
		TimingFloor:      time.Second,
	}
}

var defaultErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)SQLSTATE\[`),
	regexp.MustCompile(`(?i)syntax error at or near`),
	regexp.MustCompile(`(?i)you have an error in your SQL syntax`),
	regexp.MustCompile(`(?i)\bORA-\d{5}\b`),
	regexp.MustCompile(`(?i)mysql_fetch_(array|assoc|row)`),
	regexp.MustCompile(`(?i)pg_query\(\)`),
	regexp.MustCompile(`(?i)unclosed quotation mark`),
	regexp.MustCompile(`(?i)Traceback \(most recent call last\)`),
	regexp.MustCompile(`(?i)^\s*at [\w$.]+\((.*\.java:\d+)\)`),
	regexp.MustCompile(`(?i)\bpanic:\s`),
	regexp.MustCompile(`(?i)goroutine \d+ \[`),
	regexp.MustCompile(`(?i)(jinja2|django)\.template(exception|syntaxerror)`),
	regexp.MustCompile(`(?i)TemplateSyntaxError`),
	regexp.MustCompile(`(?i)UndefinedVariableError`),
	regexp.MustCompile(`(?i)root:x:0:0:`),
	regexp.MustCompile(`(?i)\[boot\]root@localhost`),
	regexp.MustCompile(`(?i)Warning:\s+include\(`),
	regexp.MustCompile(`(?i)System\.(Exception|WebException)`),
}

// Analyze compares a fuzzed response to the baseline and returns findings.
func (d Detector) Analyze(base *httpreq.Response, target string, payload string, resp *httpreq.Response) []Finding {
	var findings []Finding

	baseStatus := 0
	if base != nil {
		baseStatus = base.StatusCode
	}

	// 1. Status anomalies: a request that was fine now fails server-side.
	if resp.StatusCode >= 500 && (baseStatus == 0 || baseStatus < 400) {
		findings = append(findings, Finding{
			Kind:           KindStatus,
			Severity:       SeverityHigh,
			Target:         target,
			Payload:        payload,
			StatusCode:     resp.StatusCode,
			BaselineStatus: baseStatus,
			Evidence:       fmt.Sprintf("baseline %d -> %d for payload %q", baseStatus, resp.StatusCode, truncate(payload, 80)),
		})
	}

	// 2. Error strings leaking server internals. The body is scanned as bytes:
	// responses are up to MaxResponseBytes and copying each one into a string
	// per fuzz request was the hot path's largest allocation.
	for _, re := range d.ErrorPatterns {
		loc := re.FindIndex(resp.Body)
		if loc == nil {
			continue
		}
		// A pattern already present in the baseline was not caused by this
		// payload. Reporting it would flag an existing leak once per target and
		// inflate the finding count without telling the user anything new.
		if base != nil && re.FindIndex(base.Body) != nil {
			continue
		}
		findings = append(findings, Finding{
			Kind:           KindErrorText,
			Severity:       SeverityHigh,
			Target:         target,
			Payload:        payload,
			StatusCode:     resp.StatusCode,
			BaselineStatus: baseStatus,
			Evidence:       evidenceWindow(resp.Body, loc[0], loc[1]),
		})
		break // one error-string finding per response is enough
	}

	// 3. Reflection: the payload comes back verbatim. Low severity on its own,
	// but it is the signal that makes injection findings trustworthy.
	//
	// Only success responses count. An error page that quotes the offending
	// input is the error explaining itself, and that response already produced a
	// status or error-string finding; reporting reflection there adds a second
	// row for one observation and inflates the finding count.
	if d.ReflectionOn && resp.StatusCode >= 200 && resp.StatusCode < 300 && len(payload) >= d.ReflectionMinLen && bytes.Contains(resp.Body, []byte(payload)) {
		findings = append(findings, Finding{
			Kind:           KindReflection,
			Severity:       SeverityLow,
			Target:         target,
			Payload:        payload,
			StatusCode:     resp.StatusCode,
			BaselineStatus: baseStatus,
			Evidence:       fmt.Sprintf("payload %q reflected in a %d response", truncate(payload, 60), resp.StatusCode),
		})
	}

	// 4. Timing: advisory, off by default.
	if d.TimingEnabled && base != nil && base.Duration > 0 {
		threshold := time.Duration(float64(base.Duration) * d.TimingFactor)
		if threshold < d.TimingFloor {
			threshold = d.TimingFloor
		}
		if resp.Duration > threshold {
			findings = append(findings, Finding{
				Kind:           KindTiming,
				Severity:       SeverityInfo,
				Target:         target,
				Payload:        payload,
				StatusCode:     resp.StatusCode,
				BaselineStatus: baseStatus,
				DurationMS:     resp.Duration.Milliseconds(),
				Advisory:       true,
				Evidence:       fmt.Sprintf("%dms vs baseline %dms", resp.Duration.Milliseconds(), base.Duration.Milliseconds()),
			})
		}
	}

	return findings
}

// Dedupe collapses repeated findings so one noisy target cannot drown the
// report: per (kind, target) the highest severity survives and repeats are
// counted.
func Dedupe(in []Finding) []Finding {
	type key struct{ kind, target string }
	order := make([]key, 0, len(in))
	best := make(map[key]Finding, len(in))
	for _, f := range in {
		k := key{f.Kind, f.Target}
		cur, ok := best[k]
		if !ok {
			f.Count = 1
			best[k] = f
			order = append(order, k)
			continue
		}
		cur.Count++
		if severityRank(f.Severity) < severityRank(cur.Severity) {
			f.Count = cur.Count
			best[k] = f
		} else {
			best[k] = cur
		}
	}
	out := make([]Finding, 0, len(best))
	for _, k := range order {
		out = append(out, best[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if severityRank(out[i].Severity) != severityRank(out[j].Severity) {
			return severityRank(out[i].Severity) < severityRank(out[j].Severity)
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Target < out[j].Target
	})
	return out
}

func severityRank(s string) int {
	switch s {
	case SeverityHigh:
		return 0
	case SeverityMedium:
		return 1
	case SeverityLow:
		return 2
	default:
		return 3
	}
}

// CountBySeverity summarises a finding list for reports.
func CountBySeverity(in []Finding) map[string]int {
	out := map[string]int{}
	for _, f := range in {
		out[f.Severity]++
	}
	return out
}

// evidenceWindow extracts up to 60 bytes of context on either side of a match.
// The window edges snap outward to UTF-8 rune boundaries, so a multi-byte
// character straddling an edge is included whole instead of cut in half.
func evidenceWindow(body []byte, start, end int) string {
	start -= 60
	if start < 0 {
		start = 0
	}
	for start > 0 && !utf8.RuneStart(body[start]) {
		start--
	}
	end += 60
	if end > len(body) {
		end = len(body)
	}
	for end < len(body) && !utf8.RuneStart(body[end]) {
		end++
	}
	return strings.TrimSpace(string(body[start:end]))
}

func truncate(s string, n int) string { return strx.Truncate(s, n) }
