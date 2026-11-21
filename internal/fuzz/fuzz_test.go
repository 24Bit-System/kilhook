package fuzz

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	httpreq "github.com/24Bit-System/kilhook/internal/http"
)

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in   string
		kind string
		path []string
		err  bool
	}{
		{"query.q", KindQuery, []string{"q"}, false},
		{"header.X-Forwarded-For", KindHeader, []string{"X-Forwarded-For"}, false},
		{"path.0", KindPath, []string{"0"}, false},
		{"body.user.email", KindBody, []string{"user", "email"}, false},
		{"body.items.0.name", KindBody, []string{"items", "0", "name"}, false},
		{"path.-1", "", nil, true},
		{"cookies.sid", "", nil, true},
		{"nokind", "", nil, true},
		{"body.", "", nil, true},
	}
	for _, tc := range cases {
		got, err := ParseTarget(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("%q: expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if got.Kind != tc.kind || strings.Join(got.Path, "|") != strings.Join(tc.path, "|") {
			t.Errorf("%q -> %s %v", tc.in, got.Kind, got.Path)
		}
	}
}

func TestMutateBodyNestedAndArray(t *testing.T) {
	base := &httpreq.Request{Method: "POST", URL: "http://h/x", Body: []byte(`{"user":{"email":"a@b"},"items":[{"name":"n"}]}`)}
	// Mutations must not touch the base request.
	mut, err := Mutate(base, Target{Raw: "body.user.email", Kind: KindBody, Path: []string{"user", "email"}}, "injected'", false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(base.Body), "injected") {
		t.Fatal("base request was mutated")
	}
	var doc map[string]any
	if err := json.Unmarshal(mut.Body, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["user"].(map[string]any)["email"] != "injected'" {
		t.Fatalf("body = %s", mut.Body)
	}

	mut, err = Mutate(base, Target{Raw: "body.items.0.name", Kind: KindBody, Path: []string{"items", "0", "name"}}, "x", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mut.Body), `"name":"x"`) {
		t.Fatalf("body = %s", mut.Body)
	}
}

func TestMutateBodyTypedInjectsLiteral(t *testing.T) {
	base := &httpreq.Request{Method: "POST", URL: "http://h/x", Body: []byte(`{"n":1}`)}
	mut, err := Mutate(base, Target{Raw: "body.n", Kind: KindBody, Path: []string{"n"}}, `{"$ne":null}`, true)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(mut.Body, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["n"].(map[string]any); !ok {
		t.Fatalf("typed payload was not injected as an object: %s", mut.Body)
	}

	mut, err = Mutate(base, Target{Raw: "body.n", Kind: KindBody, Path: []string{"n"}}, `0`, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mut.Body), `"n":0`) {
		t.Fatalf("body = %s", mut.Body)
	}
}

func TestMutatePathSegment(t *testing.T) {
	base := &httpreq.Request{Method: "GET", URL: "http://h:8080/users/42/posts?x=1"}
	mut, err := Mutate(base, Target{Raw: "path.1", Kind: KindPath, Path: []string{"1"}}, "a b", false)
	if err != nil {
		t.Fatal(err)
	}
	if mut.URL != "http://h:8080/users/a%20b/posts?x=1" {
		t.Fatalf("url = %s", mut.URL)
	}
	if _, err := Mutate(base, Target{Raw: "path.9", Kind: KindPath, Path: []string{"9"}}, "x", false); err == nil {
		t.Fatal("expected out-of-range error")
	}
}

func TestMutateQueryAndHeader(t *testing.T) {
	base := &httpreq.Request{Method: "GET", URL: "http://h/x", Query: map[string]string{"q": "1"}, Headers: map[string]string{"Accept": "json"}}
	mut, err := Mutate(base, Target{Raw: "query.q", Kind: KindQuery, Path: []string{"q"}}, "z", false)
	if err != nil {
		t.Fatal(err)
	}
	if mut.Query["q"] != "z" || base.Query["q"] != "1" {
		t.Fatalf("query copy broken: %v / %v", mut.Query, base.Query)
	}
	mut, err = Mutate(base, Target{Raw: "header.Accept", Kind: KindHeader, Path: []string{"Accept"}}, "text/plain", false)
	if err != nil {
		t.Fatal(err)
	}
	if mut.Headers["Accept"] != "text/plain" || base.Headers["Accept"] != "json" {
		t.Fatalf("header copy broken: %v / %v", mut.Headers, base.Headers)
	}
}

func TestPayloadsBundledExpandsTokens(t *testing.T) {
	ps, err := Payloads("default", []string{"boundary"})
	if err != nil {
		t.Fatal(err)
	}
	var hasEmpty, hasLong bool
	for _, p := range ps {
		if p.Text == "" {
			hasEmpty = true
		}
		if len(p.Text) == 1024 {
			hasLong = true
		}
	}
	if !hasEmpty || !hasLong {
		t.Fatalf("token expansion failed: empty=%v long=%v", hasEmpty, hasLong)
	}
}

func TestPayloadsTypeConfusionIsTyped(t *testing.T) {
	ps, err := Payloads("default", []string{"type_confusion"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		if !p.Typed {
			t.Fatalf("payload %q should be typed", p.Text)
		}
	}
}

func TestPayloadsCustomFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/custom.txt"
	if err := writeFile(path, "# comment\nabc\n\ndef\n"); err != nil {
		t.Fatal(err)
	}
	ps, err := Payloads(path, []string{"injection"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 || ps[0].Text != "abc" || ps[1].Text != "def" {
		t.Fatalf("payloads = %+v", ps)
	}
}

func TestPayloadsRejectsUnknownMethod(t *testing.T) {
	if _, err := Payloads("default", []string{"sql"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestRunRefusesNonLocalHost(t *testing.T) {
	base := &httpreq.Request{Method: "GET", URL: "https://api.example.com/x"}
	_, err := Run(context.Background(), base, nil, nil, Config{})
	if err == nil || !strings.Contains(err.Error(), "allow-nonlocal") {
		t.Fatalf("err = %v", err)
	}
	if !errors.Is(err, ErrNonLocal) {
		t.Fatalf("the guard must return the typed error the engine warns on: %v", err)
	}
}

func TestRunMarksAbortedWhenCancelledAfterQueueing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	base := &httpreq.Request{Method: "GET", URL: srv.URL, Query: map[string]string{"q": "base"}, Timeout: 5 * time.Second}
	targets, _, _ := TargetsFromStrings([]string{"query.q"})
	payloads := make([]Payload, 0, 20)
	for i := 0; i < 20; i++ {
		payloads = append(payloads, Payload{Text: strings.Repeat("p", i+1), Method: "custom"})
	}
	muts := BuildMutations(targets, payloads)
	ctx, cancel := context.WithCancel(context.Background())
	// One worker per mutation: the producer queues everything immediately, so
	// cancellation is observed by workers during the drain, not by the producer.
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	res, err := Run(ctx, base, nil, muts, Config{
		RateLimit: 1000, PerHostConcurrency: len(muts), Workers: len(muts), MaxRequests: len(muts),
	})
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if res.Aborted == "" {
		t.Fatal("a cancelled run must be marked aborted even when all jobs were queued")
	}
}

func TestRunClampsToMaxRequests(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	base := &httpreq.Request{Method: "GET", URL: srv.URL, Query: map[string]string{"q": "base"}}
	targets, _, _ := TargetsFromStrings([]string{"query.q"})
	payloads := make([]Payload, 0, 50)
	for i := 0; i < 50; i++ {
		payloads = append(payloads, Payload{Text: strings.Repeat("a", i+1), Method: "custom"})
	}
	res, err := Run(context.Background(), base, nil, BuildMutations(targets, payloads), Config{
		MaxRequests: 5, RateLimit: 1000, PerHostConcurrency: 2, Workers: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Requests != 5 || res.Skipped != 45 {
		t.Fatalf("requests=%d skipped=%d, want 5/45", res.Requests, res.Skipped)
	}
	if got := atomic.LoadInt64(&hits); got != 5 {
		t.Fatalf("server saw %d requests, want 5", got)
	}
}

func TestRunRateLimitIsRespected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	base := &httpreq.Request{Method: "GET", URL: srv.URL, Query: map[string]string{"q": "base"}}
	targets, _, _ := TargetsFromStrings([]string{"query.q"})
	payloads := []Payload{{Text: "1"}, {Text: "2"}, {Text: "3"}, {Text: "4"}, {Text: "5"}}
	start := time.Now()
	res, err := Run(context.Background(), base, nil, BuildMutations(targets, payloads), Config{
		RateLimit: 10, PerHostConcurrency: 4, Workers: 4, MaxRequests: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	// 5 requests at 10/s cannot finish faster than ~400ms.
	if elapsed < 300*time.Millisecond {
		t.Fatalf("rate limit not applied: %d requests in %s", res.Requests, elapsed)
	}
}

func TestRunFindsServerErrorsAndReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		switch {
		case q == "base":
			_, _ = io.WriteString(w, `{"ok":true}`)
		case strings.Contains(q, "'"):
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `SQLSTATE[42000]: syntax error at or near "OR"`)
		default:
			_, _ = io.WriteString(w, `{"echo":"`+q+`"}`)
		}
	}))
	defer srv.Close()

	base := &httpreq.Request{Method: "GET", URL: srv.URL, Query: map[string]string{"q": "base"}}
	baseline, err := httpreq.Do(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	targets, _, _ := TargetsFromStrings([]string{"query.q"})
	payloads := []Payload{{Text: "xyzreflected", Method: "custom"}, {Text: "a' OR 1=1--", Method: "injection"}}
	res, err := Run(context.Background(), base, baseline, BuildMutations(targets, payloads), Config{
		RateLimit: 1000, PerHostConcurrency: 2, Workers: 2, MaxRequests: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	var kinds = map[string]bool{}
	for _, f := range res.Findings {
		kinds[f.Kind] = true
	}
	if !kinds[KindStatus] {
		t.Errorf("missing status anomaly finding: %+v", res.Findings)
	}
	if !kinds[KindErrorText] {
		t.Errorf("missing error-string finding: %+v", res.Findings)
	}
	if !kinds[KindReflection] {
		t.Errorf("missing reflection finding: %+v", res.Findings)
	}
}

func TestDedupeCollapsesPerTargetAndKind(t *testing.T) {
	in := []Finding{
		{Kind: KindReflection, Severity: SeverityLow, Target: "query.q"},
		{Kind: KindReflection, Severity: SeverityLow, Target: "query.q"},
		{Kind: KindStatus, Severity: SeverityHigh, Target: "query.q"},
	}
	out := Dedupe(in)
	if len(out) != 2 {
		t.Fatalf("got %d findings: %+v", len(out), out)
	}
	if out[0].Kind != KindStatus {
		t.Fatalf("high severity must sort first: %+v", out)
	}
	for _, f := range out {
		if f.Kind == KindReflection && f.Count != 2 {
			t.Fatalf("count = %d, want 2", f.Count)
		}
	}
}

func TestTimingFindingIsOffByDefault(t *testing.T) {
	base := &httpreq.Response{StatusCode: 200, Body: []byte("x"), Duration: 10 * time.Millisecond}
	slow := &httpreq.Response{StatusCode: 200, Body: []byte("x"), Duration: 5 * time.Second}

	if got := DefaultDetector().Analyze(base, "query.q", "payload-payload", slow); len(got) != 0 {
		t.Fatalf("timing must be quiet by default, got %+v", got)
	}

	d := DefaultDetector()
	d.TimingEnabled = true
	got := d.Analyze(base, "query.q", "payload-payload", slow)
	if len(got) != 1 || got[0].Kind != KindTiming || !got[0].Advisory || got[0].Severity != SeverityInfo {
		t.Fatalf("timing finding = %+v", got)
	}
}

func TestCountBySeverity(t *testing.T) {
	got := CountBySeverity([]Finding{{Severity: SeverityHigh}, {Severity: SeverityLow}, {Severity: SeverityHigh}})
	if got[SeverityHigh] != 2 || got[SeverityLow] != 1 {
		t.Fatalf("counts = %v", got)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func TestPayloadsInterleaveMethods(t *testing.T) {
	got, err := Payloads("default", []string{"boundary", "injection"})
	if err != nil {
		t.Fatal(err)
	}
	firstTen := map[string]bool{}
	for _, p := range got[:10] {
		firstTen[p.Method] = true
	}
	if !firstTen["boundary"] || !firstTen["injection"] {
		t.Fatalf("first ten payloads only cover %v; a capped run would never reach the other method", firstTen)
	}
}

func TestBuildMutationsReachesEveryTargetUnderACap(t *testing.T) {
	targets := []Target{
		{Raw: "header.Accept", Kind: KindHeader, Path: []string{"Accept"}},
		{Raw: "path.1", Kind: KindPath, Path: []string{"1"}},
		{Raw: "query.expand", Kind: KindQuery, Path: []string{"expand"}},
	}
	payloads, err := Payloads("default", []string{"boundary", "injection", "type_confusion"})
	if err != nil {
		t.Fatal(err)
	}
	muts := BuildMutations(targets, payloads)
	if len(muts) != len(targets)*len(payloads) {
		t.Fatalf("got %d mutations, want %d", len(muts), len(targets)*len(payloads))
	}
	// A cap of one payload's worth of work must touch every target.
	seen := map[string]bool{}
	for _, m := range muts[:len(targets)] {
		seen[m.Target.Raw] = true
	}
	for _, tg := range targets {
		if !seen[tg.Raw] {
			t.Fatalf("target %s never reached inside the first %d mutations", tg.Raw, len(targets))
		}
	}
}

func TestReflectionIsNotReportedOnErrorResponses(t *testing.T) {
	det := DefaultDetector()
	payload := "reflected-payload"

	ok := httpreq.Response{StatusCode: 200, Body: []byte("value: " + payload)}
	if got := det.Analyze(nil, "query.q", payload, &ok); len(got) != 1 || got[0].Kind != KindReflection {
		t.Fatalf("a 200 that echoes the payload should report reflection, got %+v", got)
	}

	bad := httpreq.Response{StatusCode: 500, Body: []byte("invalid input: " + payload)}
	for _, f := range det.Analyze(nil, "query.q", payload, &bad) {
		if f.Kind == KindReflection {
			t.Fatalf("a 500 that quotes the payload should not report reflection: %+v", f)
		}
	}
}

func TestOneOffFiveHundredIsNotReported(t *testing.T) {
	var payloadCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") == "hello" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		if atomic.AddInt32(&payloadCalls, 1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("transient overload"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	res := runOneMutation(t, srv.URL, `' OR 1=1--`)
	if len(res.Findings) != 0 {
		t.Fatalf("a single 500 that does not reproduce should not be reported: %+v", res.Findings)
	}
	if res.Retried != 1 {
		t.Fatalf("expected one confirmation attempt, got %d", res.Retried)
	}
}

func TestPersistentFiveHundredIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") == "hello" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("SQLSTATE[42000]: syntax error"))
	}))
	defer srv.Close()

	res := runOneMutation(t, srv.URL, `' OR 1=1--`)
	if !hasKind(res.Findings, KindStatus) {
		t.Fatalf("a reproducible 500 should be reported: %+v", res.Findings)
	}
	if !hasKind(res.Findings, KindErrorText) {
		t.Fatalf("the error text should survive confirmation: %+v", res.Findings)
	}
	if res.Retried != 1 {
		t.Fatalf("expected one confirmation attempt, got %d", res.Retried)
	}
}

// runOneMutation sends a single payload at query.q and returns the result.
func runOneMutation(t *testing.T, url, payload string) *Result {
	t.Helper()
	base := &httpreq.Request{Method: "GET", URL: url + "/api?q=hello", Timeout: 5 * time.Second}
	baseline, err := httpreq.Do(context.Background(), base)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	target := Target{Raw: "query.q", Kind: KindQuery, Path: []string{"q"}}
	muts := BuildMutations([]Target{target}, []Payload{{Text: payload, Method: "injection"}})
	res, err := Run(context.Background(), base, baseline, muts, Config{
		RateLimit:          100,
		PerHostConcurrency: 1,
		// One mutation plus one confirmation retry, so the retry draws from
		// the same hard request budget.
		MaxRequests: len(muts) + 1,
		Workers:     1,
		Detector:    DefaultDetector(),
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return res
}

func TestParseTargetRejectsManagedHeaders(t *testing.T) {
	for _, raw := range []string{"header.Content-Length", "header.Transfer-Encoding", "header.Connection"} {
		if _, err := ParseTarget(raw); err == nil {
			t.Fatalf("%q should be rejected as a managed header", raw)
		}
	}
	if _, err := ParseTarget("header.Host"); err != nil {
		t.Fatalf("header.Host should be supported: %v", err)
	}
}

func TestMutateHostTargetUsesRequestHost(t *testing.T) {
	base := &httpreq.Request{Method: "GET", URL: "http://h/x", Headers: map[string]string{}}
	mut, err := Mutate(base, Target{Raw: "header.Host", Kind: KindHeader, Path: []string{"Host"}}, "evil.example", false)
	if err != nil {
		t.Fatal(err)
	}
	if mut.Host != "evil.example" {
		t.Fatalf("Host = %q, want evil.example", mut.Host)
	}
	if _, ok := mut.Headers["Host"]; ok {
		t.Fatal("Host must not be written to the ignored Header map")
	}
	if base.Host != "" {
		t.Fatal("base request was mutated")
	}
}

func TestBuildMutationsCapped(t *testing.T) {
	targets := []Target{{Raw: "query.a"}, {Raw: "query.b"}}
	payloads := []Payload{{Text: "1"}, {Text: "2"}, {Text: "3"}}
	if got := BuildMutationsCapped(targets, payloads, 4); len(got) != 4 {
		t.Fatalf("len = %d, want 4", len(got))
	}
	if got := BuildMutationsCapped(targets, payloads, -1); len(got) != 6 {
		t.Fatalf("uncapped len = %d, want 6", len(got))
	}
	// Payload is still the outer loop, so a cap keeps every target in play.
	got := BuildMutationsCapped(targets, payloads, 2)
	if got[0].Target.Raw != "query.a" || got[1].Target.Raw != "query.b" {
		t.Fatalf("cap lost target coverage: %+v", got)
	}
}

func TestPayloadsRejectsTooManyCustomPayloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.txt")
	lines := strings.Repeat("a\n", MaxWordlistPayloads+1)
	if err := os.WriteFile(path, []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Payloads(path, nil); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("err = %v, want the payload-count limit", err)
	}
}

func TestRetryDrawsFromTheSameBudget(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		if r.URL.Query().Get("q") == "base" {
			_, _ = io.WriteString(w, `{"ok":true}`)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "SQLSTATE[42000]: syntax error")
	}))
	defer srv.Close()

	base := &httpreq.Request{Method: "GET", URL: srv.URL, Query: map[string]string{"q": "base"}}
	baseline, err := httpreq.Do(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := ParseTarget("query.q")
	muts := BuildMutations([]Target{target}, []Payload{{Text: "x", Method: "injection"}})
	res, err := Run(context.Background(), base, baseline, muts, Config{
		RateLimit: 1000, PerHostConcurrency: 2, Workers: 1, MaxRequests: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Requests != 1 || res.Retried != 0 {
		t.Fatalf("budget was exceeded: requests=%d retried=%d", res.Requests, res.Retried)
	}
	// Two hits: the baseline and the single budgeted fuzz request. The retry
	// must not add a third.
	if got := atomic.LoadInt64(&hits); got != 2 {
		t.Fatalf("server saw %d requests, want 2 (baseline + 1 fuzz)", got)
	}
	if !hasKind(res.Findings, KindStatus) {
		t.Fatalf("an unconfirmed 5xx should still be reported: %+v", res.Findings)
	}
}

func TestRunRejectsNonFiniteRateLimit(t *testing.T) {
	base := &httpreq.Request{Method: "GET", URL: "http://localhost:1/"}
	if _, err := Run(context.Background(), base, nil, nil, Config{RateLimit: math.NaN()}); err == nil {
		t.Fatal("NaN rate limit should be rejected")
	}
	if _, err := Run(context.Background(), base, nil, nil, Config{RateLimit: math.Inf(1)}); err == nil {
		t.Fatal("infinite rate limit should be rejected")
	}
}
