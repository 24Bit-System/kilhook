// Package engine runs one .kh request through the whole loop: send, validate
// against an OpenAPI contract, fuzz, diff against a baseline, and build one
// report. Both cmd/kh-cli and cmd/kh-app call it; it knows nothing about a UI.
package engine

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/24Bit-System/kilhook/internal/diff"
	"github.com/24Bit-System/kilhook/internal/format"
	"github.com/24Bit-System/kilhook/internal/fuzz"
	httpreq "github.com/24Bit-System/kilhook/internal/http"
	"github.com/24Bit-System/kilhook/internal/report"
	"github.com/24Bit-System/kilhook/internal/spec"
)

// Options are the per-run overrides a user can set from the CLI flags or the
// desktop UI. Zero values mean "use what the .kh file says".
type Options struct {
	EnvName        string  `json:"envName"`
	EnvFile        string  `json:"envFile"`
	AllowNonLocal  bool    `json:"allowNonLocal"`
	Baseline       string  `json:"baseline"`
	UpdateBaseline bool    `json:"updateBaseline"`
	NoFuzz         bool    `json:"noFuzz"`
	NoSpec         bool    `json:"noSpec"`
	NoDiff         bool    `json:"noDiff"`
	TimeoutMS      int     `json:"timeoutMs"`
	MaxRequests    int     `json:"maxRequests"`
	RateLimit      float64 `json:"rateLimit"`
	PerHost        int     `json:"perHost"`
	Timing         bool    `json:"timing"`
	Insecure       bool    `json:"insecure"`
}

// Logf receives human progress lines. It is called from background goroutines,
// so it must be safe for concurrent use.
type Logf func(format string, args ...any)

// Run executes the loop for one request file.
func Run(ctx context.Context, path string, opts Options, logf Logf) (*report.Report, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if err := validateOptions(opts); err != nil {
		return nil, err
	}
	start := time.Now()
	rep := report.New()

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if info.Size() > format.MaxFileBytes {
		return nil, fmt.Errorf("reading %s: exceeds the %d byte limit", path, format.MaxFileBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	file, warnings, err := format.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	rep.Warnings = append(rep.Warnings, warnings...)

	vars, err := loadVars(path, opts)
	if err != nil {
		return nil, err
	}

	req, err := httpreq.FromFile(file, vars)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if opts.TimeoutMS > 0 {
		req.Timeout = time.Duration(opts.TimeoutMS) * time.Millisecond
	}

	rep.Request = report.Request{
		File:        path,
		Name:        file.Name,
		Method:      req.Method,
		URL:         redactURL(req.URL),
		Headers:     redactHeaders(req.Headers),
		Query:       redactQuery(req.Query),
		BodyPreview: preview(redactBody(req.Body), 2000),
		BodyBytes:   len(req.Body),
	}

	clientOpts := []httpreq.Option{}
	if opts.Insecure {
		clientOpts = append(clientOpts, httpreq.WithInsecureTLS())
	}

	if file.Fuzz != nil && len(file.Fuzz.Targets) > 0 && !opts.NoFuzz && isWriteMethod(req.Method) {
		msg := fmt.Sprintf("fuzzing %s can create or modify server state; run it against a test environment", req.Method)
		rep.Warnings = append(rep.Warnings, msg)
		logf("warning: %s\n", msg)
	}

	baselineResp, err := httpreq.Do(ctx, req, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	rep.Response = &report.Response{
		Status:      baselineResp.StatusCode,
		DurationMS:  baselineResp.Duration.Milliseconds(),
		SizeBytes:   len(baselineResp.Body),
		ContentType: baselineResp.Header.Get("Content-Type"),
		BodyPreview: preview(redactBody(baselineResp.Body), 4000),
		Truncated:   baselineResp.Truncated,
	}

	dir := filepath.Dir(path)

	// --- contract validation -------------------------------------------------
	// A missing or unreadable spec is a warning, not a reason to abandon the
	// rest of the loop: the response, fuzz pass and baseline diff are still
	// useful, and a typo in spec.source should not cost the user a fuzz run.
	if file.Spec != nil && !opts.NoSpec {
		specPath := resolvePath(dir, file.Spec.Source)
		doc, err := spec.Load(specPath)
		if err != nil {
			rep.Warnings = append(rep.Warnings, err.Error())
		} else {
			rep.Warnings = append(rep.Warnings, doc.Warnings...)
			m, err := matchSpecOperation(doc, file, req)
			if err != nil {
				rep.Warnings = append(rep.Warnings, err.Error())
			} else {
				specResult, err := doc.ValidateResponse(m, baselineResp.StatusCode, baselineResp.Header.Get("Content-Type"), baselineResp.Body)
				if err != nil {
					rep.Warnings = append(rep.Warnings, err.Error())
				} else {
					rep.Spec = &report.SpecSection{
						Source:     specPath,
						Operation:  specResult.Operation,
						SpecPath:   specResult.SpecPath,
						StatusKey:  specResult.StatusKey,
						MediaType:  specResult.MediaType,
						Violations: redactViolations(specResult.Violations),
						Skipped:    specResult.Skipped,
						Notes:      specResult.Notes,
					}
				}
			}
		}
	}

	// --- fuzzing -------------------------------------------------------------
	if file.Fuzz != nil && len(file.Fuzz.Targets) > 0 && !opts.NoFuzz {
		targets, targetWarnings, err := fuzz.TargetsFromStrings(file.Fuzz.Targets)
		if err != nil {
			return nil, err
		}
		rep.Warnings = append(rep.Warnings, targetWarnings...)
		fuzz.SortTargets(targets)

		wordlist := file.Fuzz.Wordlist
		if !fuzz.Bundled(wordlist) {
			// A custom wordlist is a path in the request file's world: resolve
			// it next to the .kh file, not against the process working
			// directory (a packaged app starts in System32).
			resolved := resolvePath(dir, wordlist)
			if !withinDir(dir, resolved) {
				return nil, fmt.Errorf("%s: fuzz.wordlist %q leaves the workspace", path, file.Fuzz.Wordlist)
			}
			wordlist = resolved
		}
		payloads, err := fuzz.Payloads(wordlist, file.Fuzz.Methods)
		if err != nil {
			return nil, err
		}
		maxRequests := firstNonZeroInt(opts.MaxRequests, file.Fuzz.MaxRequests)
		if maxRequests <= 0 {
			maxRequests = format.DefaultMaxRequests
		}
		cfg := fuzz.Config{
			RateLimit:          firstNonZero(opts.RateLimit, file.Fuzz.RateLimit),
			PerHostConcurrency: firstNonZeroInt(opts.PerHost, file.Fuzz.PerHostConcurrency),
			MaxRequests:        maxRequests,
			AllowNonLocal:      opts.AllowNonLocal,
			Detector:           fuzz.DefaultDetector(),
			ClientOptions:      clientOpts,
			OnProgress: func(done, total int) {
				if done == total || done%25 == 0 {
					logf("fuzz: %d/%d\n", done, total)
				}
			},
		}
		cfg.Detector.TimingEnabled = opts.Timing

		mutations := fuzz.BuildMutationsCapped(targets, payloads, maxRequests)
		fuzzResult, ferr := fuzz.Run(ctx, req, baselineResp, mutations, cfg)
		if errors.Is(ferr, fuzz.ErrNonLocal) {
			// The guard refuses the fuzz pass before any fuzz request is sent,
			// but the baseline response, contract check and diff before it are
			// still valid. Skip fuzzing with a warning instead of discarding
			// the whole report.
			msg := fmt.Sprintf("%s%s is not localhost (pass --allow-nonlocal to override)", report.WarnFuzzSkippedPrefix, httpreq.HostOf(req.URL))
			rep.Warnings = append(rep.Warnings, msg)
			logf("warning: %s\n", msg)
		} else {
			if fuzzResult == nil {
				if ferr != nil {
					return nil, ferr
				}
				return nil, errors.New("fuzz returned no result")
			}
			if ferr != nil {
				rep.Warnings = append(rep.Warnings, ferr.Error())
			}
			rep.Fuzz = &report.FuzzSection{
				Requests:        fuzzResult.Requests,
				Skipped:         fuzzResult.Skipped,
				TransportErrors: fuzzResult.TransportErrors,
				DurationMS:      fuzzResult.Duration.Milliseconds(),
				Aborted:         fuzzResult.Aborted,
				Summary:         fuzz.CountBySeverity(fuzzResult.Findings),
				Findings:        redactFindings(fuzzResult.Findings),
				Targets:         file.Fuzz.Targets,
				Methods:         file.Fuzz.Methods,
				RateLimit:       cfg.RateLimit,
			}
			if fuzzResult.MutationErrors > 0 {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("fuzz: %d mutation error(s) (first: %s)", fuzzResult.MutationErrors, fuzzResult.FirstMutationError))
			}
		}
	}

	// --- diff against baseline ----------------------------------------------
	if !opts.NoDiff {
		baselinePath, err := baselinePathFor(path, dir, file, opts)
		if err != nil {
			return nil, err
		}
		if baselinePath != "" {
			if opts.UpdateBaseline {
				if err := spec.SaveBaseline(baselinePath, baselineResp.Body); err != nil {
					return nil, err
				}
				rep.Warnings = append(rep.Warnings, "baseline updated: "+baselinePath)
			} else {
				prev, err := spec.LoadBaseline(baselinePath)
				if err != nil {
					if !errors.Is(err, os.ErrNotExist) {
						return nil, fmt.Errorf("baseline %s: %w", baselinePath, err)
					}
					rep.Warnings = append(rep.Warnings, fmt.Sprintf("no baseline at %s (run with --update-baseline to create one)", baselinePath))
				} else {
					section := &report.DiffSection{BaselineFile: baselinePath, Format: "json"}
					if diff.IsJSON(prev) && diff.IsJSON(baselineResp.Body) {
						changes, err := diff.JSON(prev, baselineResp.Body)
						if err != nil {
							return nil, err
						}
						changes = redactChanges(changes)
						section.Changes = changes
						section.Drift = spec.CompareChanges(changes)
					} else {
						section.Format = "text"
						section.Changes = redactChanges(diff.Text(string(prev), string(baselineResp.Body)))
					}
					rep.Diff = section
				}
			}
		}
	}

	rep.DurationMS = time.Since(start).Milliseconds()
	rep.SplitAdvisory()
	rep.SortWarnings()
	rep.SetExitCode()
	return rep, nil
}

// Workfile describes one .kh file found in a workspace folder.
type Workfile struct {
	Path   string `json:"path"`
	Name   string `json:"name"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Error  string `json:"error,omitempty"`
}

// Discover lists the .kh files directly inside dir (no recursion — a workspace
// is a folder, and a recursive walk would pick up other people's fixtures).
func Discover(dir string) ([]Workfile, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("no workspace folder given")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	var out []Workfile = make([]Workfile, 0)
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".kh") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		wf := Workfile{Path: path, Name: e.Name()}
		// Do not read through a symlink or junction that leaves the workspace.
		// Discover only lists; Open/Run would reject the path anyway, but the
		// listing should not pull an outside file into memory first.
		if !withinDir(dir, path) {
			wf.Error = "file resolves outside the workspace"
			out = append(out, wf)
			continue
		}
		// Bound the read itself: a size check via e.Info() is a TOCTOU window
		// if the file grows between the stat and the read.
		f, err := os.Open(path)
		if err != nil {
			wf.Error = err.Error()
			out = append(out, wf)
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, format.MaxFileBytes+1))
		f.Close()
		if err != nil {
			wf.Error = err.Error()
			out = append(out, wf)
			continue
		}
		if len(data) > format.MaxFileBytes {
			wf.Error = fmt.Sprintf("file is over the %d-byte limit", format.MaxFileBytes)
			out = append(out, wf)
			continue
		}
		file, _, err := format.Parse(data)
		if err != nil {
			wf.Error = err.Error()
			out = append(out, wf)
			continue
		}
		wf.Name = file.Name
		wf.Method = file.Method
		wf.URL = file.URL
		out = append(out, wf)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func matchSpecOperation(doc *spec.Document, file *format.File, req *httpreq.Request) (*spec.Match, error) {
	if file.Spec != nil && strings.TrimSpace(file.Spec.Operation) != "" {
		tmpl, method, err := parseOperationHint(file.Spec.Operation)
		if err != nil {
			return nil, err
		}
		item := doc.Doc.Paths.Find(tmpl)
		if item == nil {
			return nil, fmt.Errorf("spec.operation %q: path %q is not declared in the spec", file.Spec.Operation, tmpl)
		}
		if item.GetOperation(strings.ToUpper(method)) == nil {
			return nil, fmt.Errorf("spec.operation %q: method %q is not declared for %q", file.Spec.Operation, strings.ToUpper(method), tmpl)
		}
		return &spec.Match{SpecPath: tmpl, Method: method, Op: item.GetOperation(strings.ToUpper(method))}, nil
	}

	reqURL, err := httpreq.ParseURLPath(req.URL)
	if err != nil {
		return nil, err
	}
	return doc.MatchOperation(req.Method, reqURL)
}

func parseOperationHint(hint string) (path, method string, err error) {
	fields := strings.Fields(hint)
	if len(fields) != 2 {
		return "", "", fmt.Errorf(`spec.operation must look like "/pets/{id} get", got %q`, hint)
	}
	return fields[0], strings.ToLower(fields[1]), nil
}

func baselinePathFor(requestPath, dir string, file *format.File, opts Options) (string, error) {
	if opts.Baseline != "" {
		return opts.Baseline, nil
	}
	if file.Spec != nil && strings.TrimSpace(file.Spec.Baseline) != "" {
		// A path written in the .kh file is data, not a command: it may not point
		// outside the workspace. Otherwise a shared request file plus
		// --update-baseline is a way to overwrite any file the user can write.
		// An explicit --baseline on the command line is allowed to go anywhere,
		// because that is the user typing the path.
		resolved := resolvePath(dir, file.Spec.Baseline)
		if !withinDir(dir, resolved) {
			return "", fmt.Errorf("%s: spec.baseline %q leaves the workspace; pass --baseline to use a path outside it", requestPath, file.Spec.Baseline)
		}
		return resolved, nil
	}
	slug := slugify(file.Name)
	if slug == "" {
		base := strings.TrimSuffix(filepath.Base(requestPath), filepath.Ext(requestPath))
		slug = slugify(base)
	}
	if slug == "" {
		if opts.UpdateBaseline {
			return "", fmt.Errorf("cannot derive a baseline file name from %q", requestPath)
		}
		return "", nil
	}
	defaultPath := filepath.Join(dir, ".kilhook", "baselines", slug+".json")
	if opts.UpdateBaseline {
		return defaultPath, nil
	}
	// A read-only run uses the default path only when it already exists, so a
	// workspace that never stored a baseline stays quiet instead of warning.
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath, nil
	}
	return "", nil
}

func loadVars(requestPath string, opts Options) (map[string]string, error) {
	vars := map[string]string{}
	path := opts.EnvFile
	if path == "" && opts.EnvName != "" {
		path = filepath.Join(filepath.Dir(requestPath), ".kilhook", "env", opts.EnvName+".yaml")
	}
	if path == "" {
		return vars, nil
	}
	loaded, err := httpreq.LoadEnvironment(path)
	if err != nil {
		return nil, err
	}
	for k, v := range loaded {
		vars[k] = v
	}
	return vars, nil
}

// WithinDir reports whether path stays inside dir after resolving symlinks and
// junctions. The Wails bridge uses it for paths the frontend supplies; it is
// the same confinement rule the engine applies to paths read from .kh files,
// so a link placed inside a workspace cannot escape either boundary.
func WithinDir(dir, path string) bool { return withinDir(dir, path) }

// withinDir reports whether path stays inside dir after cleaning. Symlinks and
// junctions are resolved to their real location (deepest existing ancestor plus
// any trailing non-existent segments) so a link inside the workspace cannot
// escape the boundary.
func withinDir(dir, path string) bool {
	dir = evalExisting(dir)
	path = evalExisting(path)
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// evalExisting resolves symlinks for the longest existing prefix of p and
// reattaches the (non-existent) remainder verbatim, so a path with a
// not-yet-created tail still compares sanely.
func evalExisting(p string) string {
	p = filepath.Clean(p)
	if real, err := filepath.EvalSymlinks(p); err == nil {
		return real
	}
	parent := p
	var rest []string
	for {
		if _, err := os.Lstat(parent); err == nil {
			break
		}
		if parent == filepath.Dir(parent) {
			return p
		}
		rest = append([]string{filepath.Base(parent)}, rest...)
		parent = filepath.Dir(parent)
	}
	real, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return p
	}
	parts := append([]string{real}, rest...)
	return filepath.Join(parts...)
}

func resolvePath(dir, p string) string {
	if p == "" {
		return p
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

func preview(body []byte, limit int) string {
	s := strings.TrimRight(string(body), "\r\n")
	if len(s) <= limit {
		return s
	}
	// Never cut a UTF-8 rune in half: bodies are full of them.
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit] + "\n…"
}

func slugify(s string) string {
	var b strings.Builder
	prevDash := false
	hasNonASCII := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if r > 127 {
				hasNonASCII = true
			}
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if !hasNonASCII {
		return out
	}
	if out == "" {
		// A name made only of non-ASCII characters still needs the hash so it
		// cannot collide with another such name (or force the filename fallback).
		h := fnv.New32a()
		h.Write([]byte(s))
		return "n-" + fmt.Sprintf("%x", h.Sum32())
	}
	h := fnv.New32a()
	h.Write([]byte(s))
	return out + "-" + fmt.Sprintf("%x", h.Sum32())
}

func redactHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if isSensitiveHeader(k) {
			out[k] = "[redacted]"
		} else {
			out[k] = v
		}
	}
	return out
}

func isSensitiveHeader(name string) bool {
	return isSensitiveName(name)
}

// isWriteMethod reports whether fuzzing this method can change server state.
func isWriteMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

// validateOptions rejects override values that would otherwise reach the
// runner as NaN/Inf or as an unbounded allocation. Zero means "use the file".
func validateOptions(opts Options) error {
	if math.IsNaN(opts.RateLimit) || math.IsInf(opts.RateLimit, 0) {
		return errors.New("rate limit must be a finite number")
	}
	if opts.RateLimit < 0 {
		return errors.New("rate limit must not be negative")
	}
	if opts.RateLimit > 0 && opts.RateLimit < format.MinRateLimit {
		return fmt.Errorf("rate limit must be at least %g", format.MinRateLimit)
	}
	if opts.RateLimit > format.MaxRateLimit {
		return fmt.Errorf("rate limit must not exceed %g", format.MaxRateLimit)
	}
	if opts.MaxRequests < 0 {
		return errors.New("max requests must not be negative")
	}
	if opts.MaxRequests > format.MaxFuzzRequests {
		return fmt.Errorf("max requests must not exceed %d", format.MaxFuzzRequests)
	}
	if opts.PerHost < 0 {
		return errors.New("per-host concurrency must not be negative")
	}
	if opts.PerHost > format.MaxPerHostLimit {
		return fmt.Errorf("per-host concurrency must not exceed %d", format.MaxPerHostLimit)
	}
	if opts.TimeoutMS < 0 {
		return errors.New("timeout must not be negative")
	}
	if opts.TimeoutMS > format.MaxRequestTimeout {
		return fmt.Errorf("timeout must not exceed %d ms", format.MaxRequestTimeout)
	}
	return nil
}

func firstNonZero(a, b float64) float64 {
	if a > 0 {
		return a
	}
	return b
}

func firstNonZeroInt(a, b int) int {
	if a > 0 {
		return a
	}
	return b
}
