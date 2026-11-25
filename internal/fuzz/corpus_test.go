package fuzz

// The false-positive corpus. A measured false-positive rate is worth more than
// an assertion, so this file stands up four local APIs with known answers and
// reports true/false positives and recall per target. Precision is only
// meaningful when a fixture actually produces findings; the clean fixture is a
// zero-false-positive gate, not a 100%-precision measurement.
//
//	clean       a well-behaved API that never echoes and never 500s   expect 0 findings
//	sql-unsafe  returns a SQL error page for quote payloads           expect status + error_string
//	echo        reflects the payload back in a 200                     expect reflection (low)
//	slow        takes ~1.4s only for payloads containing "sleep"       expect nothing unless timing is on
//
// The clean server is the precision measurement: every finding it produces is a
// false positive by construction, because the handler is written to be
// indifferent to its input. Nothing here touches the network: all four servers
// are httptest listeners on loopback.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	httpreq "github.com/24Bit-System/kilhook/internal/http"
)

// corpusPayloadLimit keeps the corpus fast enough to sit inside the normal test
// run. The payloads are interleaved across methods, so a cap still samples every
// method rather than only the first one.
const corpusPayloadLimit = 150

type corpusCase struct {
	name string
	// wantKinds lists the finding kinds this target must produce at least once.
	wantKinds []string
	// allowKinds lists kinds that are not counted as false positives here (the
	// echo server is supposed to report reflection).
	allowKinds []string
	// forbid lists severities that must never appear at all.
	forbidSeverities []string
	timing           bool
}

func corpusCases() []corpusCase {
	return []corpusCase{
		{
			name:             "clean",
			forbidSeverities: []string{SeverityHigh, SeverityMedium, SeverityLow},
		},
		{
			name:      "sql-unsafe",
			wantKinds: []string{KindStatus, KindErrorText},
		},
		{
			name:       "echo",
			wantKinds:  []string{KindReflection},
			allowKinds: []string{KindReflection},
		},
		{
			name:   "slow",
			timing: true,
		},
	}
}

func TestCorpusPrecisionAndRecall(t *testing.T) {
	payloads, err := Payloads("default", Methods)
	if err != nil {
		t.Fatalf("loading the bundled wordlist: %v", err)
	}
	if len(payloads) < corpusPayloadLimit {
		t.Fatalf("bundled wordlist has %d payloads, the corpus needs at least %d", len(payloads), corpusPayloadLimit)
	}

	type row struct {
		name     string
		requests int
		findings int
		truePos  int
		falsePos int
		skipped  int
	}
	var rows []row

	for _, tc := range corpusCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(corpusHandler(tc))
			defer srv.Close()

			base := &httpreq.Request{
				Method:          "GET",
				URL:             srv.URL + "/api?q=hello",
				Timeout:         5 * time.Second,
				FollowRedirects: true,
			}
			baseline, err := httpreq.Do(context.Background(), base)
			if err != nil {
				t.Fatalf("baseline request: %v", err)
			}

			target := Target{Raw: "query.q", Kind: KindQuery, Path: []string{"q"}}
			mutations := BuildMutations([]Target{target}, payloads)
			if len(mutations) > corpusPayloadLimit {
				mutations = mutations[:corpusPayloadLimit]
			}

			detector := DefaultDetector()
			detector.TimingEnabled = tc.timing
			detector.TimingFloor = 500 * time.Millisecond

			res, err := Run(context.Background(), base, baseline, mutations, Config{
				RateLimit:          400,
				PerHostConcurrency: 6,
				MaxRequests:        len(mutations),
				Workers:            6,
				Detector:           detector,
			})
			if err != nil {
				t.Fatalf("fuzz run: %v", err)
			}

			want := map[string]bool{}
			for _, k := range tc.wantKinds {
				want[k] = true
			}
			allow := map[string]bool{}
			for _, k := range tc.allowKinds {
				allow[k] = true
			}

			seenKinds := map[string]bool{}
			tp, fp := 0, 0
			for _, f := range res.Findings {
				seenKinds[f.Kind] = true
				for _, forbidden := range tc.forbidSeverities {
					if f.Severity == forbidden {
						t.Errorf("false positive (%s, %s) on %s target: %s",
							f.Kind, f.Severity, f.Target, f.Evidence)
					}
				}
				if want[f.Kind] || allow[f.Kind] && f.Severity == SeverityLow {
					tp++
				} else {
					fp++
				}
			}
			for _, k := range tc.wantKinds {
				if !seenKinds[k] {
					t.Errorf("missed %s on %s: findings were %v", k, tc.name, kindsOf(res.Findings))
				}
			}

			precLabel := "n/a (no findings)"
			if tp+fp > 0 {
				precLabel = fmt.Sprintf("%.0f%%", float64(tp)/float64(tp+fp)*100)
			}
			t.Logf("%-11s requests=%-3d findings=%-3d kinds=%-40s tp=%d fp=%d precision=%s",
				tc.name, res.Requests, len(res.Findings), strings.Join(kindsOf(res.Findings), ","), tp, fp, precLabel)
			rows = append(rows, row{tc.name, res.Requests, len(res.Findings), tp, fp, res.Skipped})
		})
	}

	var totalFP int
	for _, r := range rows {
		totalFP += r.falsePos
	}
	if totalFP != 0 {
		t.Errorf("corpus has %d false positive(s) in total; the budget is 0 for these fixtures", totalFP)
	}
}

// TestCorpusReportsTimingWhenEnabled proves the timing heuristic is wired up but
// stays out of the default set: the same slow server says nothing unless the
// detector is asked to time it.
func TestCorpusReportsTimingWhenEnabled(t *testing.T) {
	tc := corpusCase{name: "slow", timing: true}
	srv := httptest.NewServer(corpusHandler(tc))
	defer srv.Close()

	payloads := []Payload{{Text: "sleep", Method: "injection"}, {Text: "hello", Method: "injection"}}
	base := &httpreq.Request{Method: "GET", URL: srv.URL + "/api?q=hello", Timeout: 5 * time.Second}

	// The baseline clock is pinned instead of measured: this test proves the
	// wiring (Run -> Analyze -> timing finding), not latency measurement. A
	// measured baseline moves with machine load — under the race detector it can
	// exceed sleep/3, which pushes the factor-based threshold past the server's
	// fixed 1.4s sleep and the heuristic correctly stays quiet (flake). With a
	// 20ms baseline the threshold is the 300ms floor, which the 1.4s sleep always
	// clears; and if a non-sleeping request were ever slow enough to trip the
	// floor too, Dedupe collapses same-kind findings per target, so the count
	// stays at exactly one.
	baseline := &httpreq.Response{StatusCode: 200, Body: []byte(`{"slept":"no"}`), Duration: 20 * time.Millisecond}
	target := Target{Raw: "query.q", Kind: KindQuery, Path: []string{"q"}}

	run := func(timing bool) *Result {
		detector := DefaultDetector()
		detector.TimingEnabled = timing
		detector.TimingFloor = 300 * time.Millisecond
		res, err := Run(context.Background(), base, baseline, BuildMutations([]Target{target}, payloads), Config{
			RateLimit:          50,
			PerHostConcurrency: 1,
			MaxRequests:        len(payloads),
			Workers:            1,
			Detector:           detector,
		})
		if err != nil {
			t.Fatalf("fuzz run: %v", err)
		}
		return res
	}

	if got := run(false).Findings; len(got) != 0 {
		t.Fatalf("timing is off by default, but the default detector reported %v", kindsOf(got))
	}
	res := run(true)
	if len(res.Findings) != 1 || res.Findings[0].Kind != KindTiming {
		t.Fatalf("wanted one timing finding, got %v (requests=%d transportErrors=%d firstError=%q)",
			kindsOf(res.Findings), res.Requests, res.TransportErrors, res.FirstError)
	}
	if !res.Findings[0].Advisory {
		t.Fatal("timing findings must be advisory")
	}
}

// corpusHandler is the shared entry point for the four fixtures. It routes on the
// case name so each server stays a pure function of its configuration.
func corpusHandler(tc corpusCase) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		switch tc.name {
		case "clean":
			writeJSON(w, http.StatusOK, map[string]string{"id": "1", "q": "ok"})
		case "sql-unsafe":
			if unsafeSQL(q) {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "SQLSTATE[42000]: syntax error at or near %q", truncate(q, 24))
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"id": "1"})
		case "echo":
			writeJSON(w, http.StatusOK, map[string]string{"earlier": q})
		case "slow":
			if strings.Contains(strings.ToLower(q), "sleep") {
				time.Sleep(1400 * time.Millisecond)
			}
			writeJSON(w, http.StatusOK, map[string]string{"slept": "no"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

// unsafeSQL is the "vulnerable" half of the corpus: the handler only misbehaves
// when the input actually looks like a SQL fragment.
func unsafeSQL(v string) bool {
	lower := strings.ToLower(v)
	return strings.Contains(v, "'") || strings.Contains(lower, "union") || strings.Contains(lower, "1=1")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func kindsOf(findings []Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		key := f.Kind + "/" + f.Severity
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	return out
}
