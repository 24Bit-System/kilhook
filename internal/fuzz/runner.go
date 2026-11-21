package fuzz

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"sync"
	"time"

	httpreq "github.com/24Bit-System/kilhook/internal/http"

	"github.com/24Bit-System/kilhook/internal/format"
)

// ErrNonLocal is returned when the loopback guard refuses a fuzz run. The
// engine turns it into a warning so the baseline, contract and diff phases can
// still produce a report; direct callers (and the CLI's own error path) keep
// seeing it as an error.
var ErrNonLocal = errors.New("host is not localhost")

// Mutation is one target/payload pair ready to send.
type Mutation struct {
	Target  Target
	Payload string
	Typed   bool
	Method  string
}

// Config are the run limits. Every knob has a documented default; the runner
// itself never hard-codes a rate (project.md §6.4, §8 Phase 2).
type Config struct {
	RateLimit          float64
	PerHostConcurrency int
	MaxRequests        int
	AllowNonLocal      bool
	Workers            int
	Detector           Detector
	ClientOptions      []httpreq.Option
	OnProgress         func(done, total int)
}

// Result is the outcome of a fuzz pass.
type Result struct {
	Findings           []Finding
	Requests           int
	TransportErrors    int
	MutationErrors     int
	Skipped            int
	Retried            int
	Duration           time.Duration
	Aborted            string
	FirstError         string
	FirstMutationError string
}

// Run executes every mutation against the target under the configured limits.
func Run(ctx context.Context, base *httpreq.Request, baseline *httpreq.Response, mutations []Mutation, cfg Config) (*Result, error) {
	if base == nil {
		return nil, fmt.Errorf("no request to fuzz")
	}
	if math.IsNaN(cfg.RateLimit) || math.IsInf(cfg.RateLimit, 0) {
		return nil, fmt.Errorf("rate limit must be a finite number")
	}
	if cfg.RateLimit < 0 {
		return nil, fmt.Errorf("rate limit must not be negative")
	}
	if cfg.RateLimit > format.MaxRateLimit {
		return nil, fmt.Errorf("rate limit must not exceed %g", format.MaxRateLimit)
	}
	if cfg.RateLimit > 0 && cfg.RateLimit < format.MinRateLimit {
		return nil, fmt.Errorf("rate limit must be at least %g", format.MinRateLimit)
	}
	if cfg.RateLimit == 0 {
		cfg.RateLimit = format.DefaultRateLimit
	}
	if cfg.PerHostConcurrency < 0 {
		return nil, fmt.Errorf("per-host concurrency must not be negative")
	}
	if cfg.PerHostConcurrency > format.MaxPerHostLimit {
		return nil, fmt.Errorf("per-host concurrency must not exceed %d", format.MaxPerHostLimit)
	}
	if cfg.PerHostConcurrency == 0 {
		cfg.PerHostConcurrency = format.DefaultPerHost
	}
	if cfg.MaxRequests < 0 {
		return nil, fmt.Errorf("max requests must not be negative")
	}
	if cfg.MaxRequests > format.MaxFuzzRequests {
		return nil, fmt.Errorf("max requests must not exceed %d", format.MaxFuzzRequests)
	}
	if cfg.MaxRequests == 0 {
		cfg.MaxRequests = format.DefaultMaxRequests
	}
	if cfg.Workers <= 0 {
		cfg.Workers = runtime.NumCPU()
		if cfg.Workers > 10 {
			cfg.Workers = 10
		}
		if cfg.Workers < 1 {
			cfg.Workers = 1
		}
	}
	if cfg.Detector.ErrorPatterns == nil {
		cfg.Detector = DefaultDetector()
	}

	// Safety guard: refuse to spray a non-local host unless explicitly allowed.
	if !cfg.AllowNonLocal && !httpreq.IsLoopback(base.URL) {
		return nil, fmt.Errorf("refusing to fuzz %s: %w (pass --allow-nonlocal to override)", httpreq.HostOf(base.URL), ErrNonLocal)
	}
	clientOpts := append([]httpreq.Option{}, cfg.ClientOptions...)
	// The semaphore below caps in-flight requests; this makes the cached
	// transport's connection pool honour the same per-host setting so
	// connections are reused instead of re-dialled under load.
	clientOpts = append(clientOpts, httpreq.WithPerHostConcurrency(cfg.PerHostConcurrency))
	if !cfg.AllowNonLocal {
		// The same rule has to hold after a redirect, or a local server could
		// bounce every fuzz request to the internet.
		clientOpts = append(clientOpts, httpreq.WithLocalOnly())
	}

	res := &Result{}
	start := time.Now()

	total := len(mutations)
	// The slice is trimmed to the budget to avoid pointless iteration. The
	// budget itself is enforced per network attempt, including confirmation
	// retries, so MaxRequests is a hard ceiling rather than a soft one.
	if total > cfg.MaxRequests {
		mutations = mutations[:cfg.MaxRequests]
	}
	if len(mutations) == 0 {
		return res, nil
	}

	lim := newLimiter(cfg.RateLimit)
	hostSem := newHostSemaphores(cfg.PerHostConcurrency)
	jobs := make(chan Mutation)
	var mu sync.Mutex
	var budgetMu sync.Mutex
	budgetLeft := cfg.MaxRequests
	takeBudget := func() bool {
		budgetMu.Lock()
		defer budgetMu.Unlock()
		if budgetLeft <= 0 {
			return false
		}
		budgetLeft--
		return true
	}
	var wg sync.WaitGroup
	var findings []Finding
	var firstErr string
	var firstMutErr string
	initialSends := 0

	worker := func() {
		defer wg.Done()
		for m := range jobs {
			if ctx.Err() != nil {
				return
			}
			req, err := Mutate(base, m.Target, m.Payload, m.Typed)
			if err != nil {
				mu.Lock()
				res.MutationErrors++
				if firstMutErr == "" {
					firstMutErr = fmt.Sprintf("%s: %v", m.Target.Raw, err)
				}
				mu.Unlock()
				continue
			}
			// Take the budget before waiting on the rate limiter so a retry that
			// cannot be sent does not consume a rate-limit slot.
			if !takeBudget() {
				continue
			}
			if err := lim.wait(ctx); err != nil {
				return
			}
			release, err := hostSem.acquire(ctx, httpreq.HostOf(req.URL))
			if err != nil {
				return
			}
			resp, err := httpreq.Do(ctx, req, clientOpts...)
			release()
			mu.Lock()
			res.Requests++
			initialSends++
			mu.Unlock()
			if err != nil {
				mu.Lock()
				res.TransportErrors++
				if firstErr == "" {
					firstErr = err.Error()
				}
				mu.Unlock()
				continue
			}
			fs := cfg.Detector.Analyze(baseline, m.Target.Raw, m.Payload, resp)

			// A 5xx is the highest-value finding and the easiest to fake: one
			// overloaded backend moment is enough. Re-send the same mutation once
			// and only keep the finding if the server does it again. The retry
			// draws from the same request budget.
			if hasKind(fs, KindStatus) && takeBudget() {
				retryStatus, retryOK, sent := retryOnce(ctx, req, lim, hostSem, clientOpts)
				mu.Lock()
				if sent {
					res.Requests++
					res.Retried++
				}
				if retryOK && retryStatus < 500 {
					fs = dropTransientFindings(fs)
				}
				mu.Unlock()
			}

			mu.Lock()
			findings = append(findings, fs...)
			mu.Unlock()
		}
	}

	wg.Add(cfg.Workers)
	for i := 0; i < cfg.Workers; i++ {
		go worker()
	}

	done := 0
	for _, m := range mutations {
		select {
		case <-ctx.Done():
			res.Aborted = ctx.Err().Error()
			goto finish
		case jobs <- m:
			done++
			if cfg.OnProgress != nil && (done == len(mutations) || done%10 == 0) {
				cfg.OnProgress(done, len(mutations))
			}
		}
	}

finish:
	close(jobs)
	wg.Wait()

	// Cancellation can also be seen by workers after the producer has queued
	// everything (for example while waiting on the rate limiter). Those runs
	// must be marked incomplete too, or the report calls cancellation-driven
	// skips "max_requests" and exits 0/1 instead of 2.
	if res.Aborted == "" && ctx.Err() != nil {
		res.Aborted = ctx.Err().Error()
	}

	res.Duration = time.Since(start)
	res.Findings = Dedupe(findings)
	// Mutation errors never reached the network, so they are not "skipped"
	// requests; everything else that was planned but not sent is.
	res.Skipped = total - initialSends - res.MutationErrors
	if res.Skipped < 0 {
		res.Skipped = 0
	}
	if cfg.OnProgress != nil {
		cfg.OnProgress(done, len(mutations))
	}
	res.FirstError = firstErr
	res.FirstMutationError = firstMutErr

	if res.Requests == 0 && res.TransportErrors > 0 {
		return res, fmt.Errorf("all %d requests failed: %s", res.TransportErrors, firstErr)
	}
	return res, nil
}

// retryOnce re-sends one mutated request under the same limits. It returns the
// status, whether a response arrived (a transport error proves nothing, so the
// caller keeps the original finding), and whether the request was actually
// sent (a cancelled context or a failed semaphore acquire sends nothing).
func retryOnce(ctx context.Context, req *httpreq.Request, lim *limiter, hostSem *hostSemaphores, opts []httpreq.Option) (int, bool, bool) {
	if ctx.Err() != nil {
		return 0, false, false
	}
	if err := lim.wait(ctx); err != nil {
		return 0, false, false
	}
	release, err := hostSem.acquire(ctx, httpreq.HostOf(req.URL))
	if err != nil {
		return 0, false, false
	}
	resp, err := httpreq.Do(ctx, req, opts...)
	release()
	if err != nil {
		return 0, false, true
	}
	return resp.StatusCode, true, true
}

// hasKind reports whether any finding has this kind.
func hasKind(fs []Finding, kind string) bool {
	for _, f := range fs {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

// dropTransientFindings removes the two kinds that a one-off server error can
// produce, keeping anything else the same response showed.
func dropTransientFindings(fs []Finding) []Finding {
	out := fs[:0]
	for _, f := range fs {
		if f.Kind == KindStatus || f.Kind == KindErrorText {
			continue
		}
		out = append(out, f)
	}
	return out
}

// limiter is a simple token bucket shared by all workers: one token every
// 1/rate seconds, no burst.
type limiter struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

func newLimiter(ratePerSecond float64) *limiter {
	if ratePerSecond <= 0 {
		ratePerSecond = format.DefaultRateLimit
	}
	interval := time.Duration(float64(time.Second) / ratePerSecond)
	// A finite but tiny rate can overflow the float→Duration conversion into a
	// negative value, which would disable throttling entirely. Callers validate
	// MinRateLimit; this is a defensive backstop for direct limiter use.
	if interval <= 0 {
		interval = time.Duration(float64(time.Second) / format.MaxRateLimit)
	}
	return &limiter{interval: interval}
}

func (l *limiter) wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	at := l.next
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	if d := time.Until(at); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// hostSemaphores caps in-flight requests per host.
type hostSemaphores struct {
	mu    sync.Mutex
	limit int
	sems  map[string]chan struct{}
}

func newHostSemaphores(limit int) *hostSemaphores {
	return &hostSemaphores{limit: limit, sems: map[string]chan struct{}{}}
}

func (h *hostSemaphores) acquire(ctx context.Context, host string) (func(), error) {
	h.mu.Lock()
	sem, ok := h.sems[host]
	if !ok {
		sem = make(chan struct{}, h.limit)
		h.sems[host] = sem
	}
	h.mu.Unlock()

	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}
