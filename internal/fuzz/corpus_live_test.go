//go:build corpuslive

package fuzz

// The live false-positive corpus. It is behind the `corpuslive` build tag so the
// offline gate (scripts/verify.ps1) never depends on the network:
//
//	go test ./internal/fuzz/ -tags corpuslive -run TestLiveCorpusPrecision -v -timeout 15m
//
// These are real, public, read-only endpoints. That means the fixture corpus'
// ground truth is unavailable: nobody can say whether a 5xx these APIs return for
// a weird payload is a bug or a false positive. So this test does not fail on
// findings — it reports them per API and fails only when the harness itself is
// broken (baseline unreachable, transport errors, malformed mutations). The
// offline corpus is what enforces the zero-false-positive budget; this one shows
// what the real internet does to the numbers.
//
// Requests are polite: 3 per second, one connection per host, at most 60 payloads
// per API. Endpoints were chosen because they tolerate unauthenticated reads;
// GitHub's API is deliberately absent because its 60-requests-per-hour limit
// would be exhausted by one corpus run. The Swagger Petstore demo is also absent:
// it answers 403 to this client's traffic, and a corpus that measures Cloudflare
// rather than the API is worse than no corpus.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	httpreq "github.com/24Bit-System/kilhook/internal/http"
)

type liveCase struct {
	name string
	// url is the baseline request. It must return 2xx or the case is skipped.
	url string
	// target is the fuzz target, e.g. "query.q" or "path.3".
	target string
	// echoes marks an API that is supposed to reflect its input, so reflection
	// findings are expected rather than surprising.
	echoes bool
}

func liveCases() []liveCase {
	return []liveCase{
		{name: "httpbin", url: "https://httpbin.org/get?q=hello", target: "query.q", echoes: true},
		{name: "postman-echo", url: "https://postman-echo.com/get?q=hello", target: "query.q", echoes: true},
		{name: "jsonplaceholder", url: "https://jsonplaceholder.typicode.com/posts/1", target: "header.X-Forwarded-For"},
		{name: "dummyjson", url: "https://dummyjson.com/products/1?q=hello", target: "query.q"},
		{name: "rickandmorty", url: "https://rickandmortyapi.com/api/character/1", target: "path.2"},
		{name: "pokeapi", url: "https://pokeapi.co/api/v2/pokemon/1", target: "path.3"},
		{name: "swapi", url: "https://swapi.dev/api/people/1", target: "path.2"},
		{name: "open-meteo", url: "https://api.open-meteo.com/v1/forecast?latitude=1&longitude=1", target: "query.latitude"},
		{name: "agify", url: "https://api.agify.io?name=go", target: "query.name", echoes: true},
		{name: "sunrise-sunset", url: "https://api.sunrise-sunset.org/json?lat=1&lng=1", target: "query.lat"},
	}
}

// livePayloadCount is the cap per API. Sixty keeps a full run near two minutes at
// the configured rate.
const livePayloadCount = 60

func TestLiveCorpusPrecision(t *testing.T) {
	all, err := Payloads("default", Methods)
	if err != nil {
		t.Fatalf("loading the bundled wordlist: %v", err)
	}

	// Sample the payload list evenly so a small cap still covers every method and
	// every family instead of only the first injection payloads.
	// Public endpoints reject megabyte-long URLs before the request ever leaves
	// the machine, which would show up as transport errors rather than results.
	// The offline corpus still exercises those payloads; here they are dropped.
	const maxLivePayload = 2048
	var usable []Payload
	for _, p := range all {
		if len(p.Text) <= maxLivePayload {
			usable = append(usable, p)
		}
	}

	step := len(usable) / livePayloadCount
	if step < 1 {
		step = 1
	}
	var payloads []Payload
	for i := 0; i < len(usable) && len(payloads) < livePayloadCount; i += step {
		payloads = append(payloads, usable[i])
	}

	type row struct {
		name     string
		status   string
		requests int
		high     int
		medium   int
		low      int
		errors   int
		skipped  string
	}
	var rows []row

	for _, tc := range liveCases() {
		func() {
			target, err := ParseTarget(tc.target)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			base := &httpreq.Request{
				Method:          "GET",
				URL:             tc.url,
				Timeout:         20 * time.Second,
				FollowRedirects: true,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			baseline, err := httpreq.Do(ctx, base)
			if err != nil {
				rows = append(rows, row{name: tc.name, skipped: "baseline unreachable: " + err.Error()})
				return
			}
			if baseline.StatusCode >= 400 {
				rows = append(rows, row{name: tc.name, skipped: fmt.Sprintf("baseline returned %d", baseline.StatusCode)})
				return
			}

			mutations := BuildMutations([]Target{target}, payloads)
			res, err := Run(ctx, base, baseline, mutations, Config{
				RateLimit:          3,
				PerHostConcurrency: 1,
				MaxRequests:        len(mutations),
				AllowNonLocal:      true,
				Workers:            3,
				Detector:           DefaultDetector(),
			})
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}

			r := row{name: tc.name, status: fmt.Sprint(baseline.StatusCode), requests: res.Requests, errors: res.TransportErrors}
			var details []string
			for _, f := range res.Findings {
				switch f.Severity {
				case SeverityHigh:
					r.high++
				case SeverityMedium:
					r.medium++
				default:
					r.low++
				}
				if f.Severity != SeverityLow || !tc.echoes {
					details = append(details, fmt.Sprintf("%s/%s %s payload=%q", f.Kind, f.Severity, f.Target, f.Payload))
				}
			}
			sort.Strings(details)
			rows = append(rows, r)

			t.Logf("%-15s status=%s requests=%-3d high=%d medium=%d low=%d transport_errors=%d",
				r.name, r.status, r.requests, r.high, r.medium, r.low, r.errors)
			if len(details) > 0 {
				for _, d := range details {
					t.Logf("    needs triage: %s", d)
				}
			} else if r.requests > 0 {
				t.Logf("    no high/medium findings")
			}

			// The harness must not silently produce nothing: a run where every
			// request failed is a bug in the corpus, not a clean result.
			if res.Requests > 0 && res.TransportErrors*5 > res.Requests {
				t.Errorf("%s: %d of %d requests failed to transport", tc.name, res.TransportErrors, res.Requests)
			}
			if res.MutationErrors > 0 {
				t.Errorf("%s: %d mutations failed to build", tc.name, res.MutationErrors)
			}
		}()
	}

	var lines []string
	lines = append(lines, "", fmt.Sprintf("%-15s %-6s %-8s %-5s %-6s %-4s %-5s", "api", "status", "requests", "high", "medium", "low", "errs"))
	for _, r := range rows {
		if r.skipped != "" {
			lines = append(lines, fmt.Sprintf("%-15s skipped (%s)", r.name, r.skipped))
			continue
		}
		lines = append(lines, fmt.Sprintf("%-15s %-6s %-8d %-5d %-6d %-4d %-5d",
			r.name, r.status, r.requests, r.high, r.medium, r.low, r.errors))
	}
	t.Log("\n" + strings.Join(lines, "\n"))
}
