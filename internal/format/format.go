// Package format parses and serializes .kh request files.
//
// A .kh file is YAML frontmatter, a line containing only "---", then the raw
// request body. Nothing in this package performs I/O beyond reading the byte
// slice it is given, so it is usable from the CLI, the desktop app and tests.
package format

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Version is the only .kh format version this build understands. It is frozen
// at Phase 1 completion; breaking changes require Version 2 plus a migration.
const Version = 1

// MaxFileBytes bounds the size of a .kh file Parse will accept, so an
// accidental or hostile multi-gigabyte file cannot exhaust memory. Specs and
// responses have their own caps (spec.MaxSpecBytes, http.MaxResponseBytes).
const MaxFileBytes = 4 << 20

// Defaults for request behaviour.
const (
	DefaultTimeoutMS   = 30000
	DefaultFollowRedir = true
	DefaultMaxRequests = 500
	DefaultRateLimit   = 5.0
	DefaultPerHost     = 2
)

// Bounds for fuzz configuration. These are deliberately generous for real
// work but small enough that a hand-edited or shared .kh file cannot ask the
// runner to allocate an unbounded request budget or throttle interval.
const (
	MaxFuzzRequests   = 1_000_000
	MaxRateLimit      = 10_000.0
	MinRateLimit      = 0.01
	MaxPerHostLimit   = 256
	MaxRequestTimeout = 3_600_000 // one hour, in ms
)

// managedHeaders are connection-level headers net/http writes itself. A fuzz
// target naming one of them would silently do nothing (the client ignores the
// map entry), so Parse warns and drops it. Host is not in this list: fuzz has
// explicit support for it through httpreq.Request.Host.
var managedHeaders = map[string]bool{
	"content-length":    true,
	"transfer-encoding": true,
	"connection":        true,
	"trailer":           true,
	"upgrade":           true,
	"te":                true,
	"proxy-connection":  true,
	"keep-alive":        true,
}

// ManagedHeader reports whether name is a connection-level header that the
// HTTP client controls itself.
func ManagedHeader(name string) bool {
	return managedHeaders[strings.ToLower(strings.TrimSpace(name))]
}

// Auth types.
const (
	AuthNone   = "none"
	AuthBasic  = "basic"
	AuthBearer = "bearer"
	AuthAPIKey = "api_key"
)

// Body types.
const (
	BodyNone      = ""
	BodyJSON      = "json"
	BodyForm      = "form"
	BodyMultipart = "multipart"
	BodyText      = "text"
)

// Auth is the auth block of a .kh file.
type Auth struct {
	Type     string `yaml:"type"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	Token    string `yaml:"token,omitempty"`
	In       string `yaml:"in,omitempty"`
	Name     string `yaml:"name,omitempty"`
	Value    string `yaml:"value,omitempty"`
}

// Fuzz is the fuzz block of a .kh file. Zero values are replaced by the
// defaults above at parse time, so callers never see a partially filled block.
type Fuzz struct {
	Targets            []string `yaml:"targets,omitempty"`
	Wordlist           string   `yaml:"wordlist,omitempty"`
	Methods            []string `yaml:"methods,omitempty"`
	MaxRequests        int      `yaml:"max_requests,omitempty"`
	RateLimit          float64  `yaml:"rate_limit,omitempty"`
	PerHostConcurrency int      `yaml:"per_host_concurrency,omitempty"`
}

// Spec is the spec block of a .kh file.
type Spec struct {
	Source    string `yaml:"source,omitempty"`
	Operation string `yaml:"operation,omitempty"`
	Baseline  string `yaml:"baseline,omitempty"`
}

// File is a parsed .kh request.
type File struct {
	Format          int               `yaml:"format"`
	Name            string            `yaml:"name"`
	Method          string            `yaml:"method"`
	URL             string            `yaml:"url"`
	Headers         map[string]string `yaml:"headers,omitempty"`
	Query           map[string]string `yaml:"query,omitempty"`
	Auth            *Auth             `yaml:"auth,omitempty"`
	Fuzz            *Fuzz             `yaml:"fuzz,omitempty"`
	Spec            *Spec             `yaml:"spec,omitempty"`
	TimeoutMS       int               `yaml:"timeout_ms,omitempty"`
	FollowRedirects *bool             `yaml:"follow_redirects,omitempty"`

	// Body is the raw bytes after the "---" separator. It is not a YAML field.
	Body []byte `yaml:"-"`
}

// Timeout returns the effective timeout in milliseconds.
func (f *File) Timeout() int {
	if f.TimeoutMS <= 0 {
		return DefaultTimeoutMS
	}
	return f.TimeoutMS
}

// Redirects reports whether redirects should be followed.
func (f *File) Redirects() bool {
	if f.FollowRedirects == nil {
		return DefaultFollowRedir
	}
	return *f.FollowRedirects
}

// ContentType returns the request Content-Type header, if any. YAML allows
// case-variant duplicates ("Content-Type" and "content-type" side by side);
// the lexicographically smallest matching key wins so the result is
// deterministic across runs, and Parse warns when duplicates exist.
func (f *File) ContentType() string {
	best, val := "", ""
	for k, v := range f.Headers {
		if strings.EqualFold(k, "Content-Type") && (best == "" || k < best) {
			best, val = k, v
		}
	}
	return val
}

// BodyType classifies the body by the declared Content-Type. A body with no
// Content-Type is treated as JSON when it parses as JSON, otherwise text.
func (f *File) BodyType() string {
	if len(strings.TrimSpace(string(f.Body))) == 0 {
		return BodyNone
	}
	ct := strings.ToLower(f.ContentType())
	switch {
	case strings.HasPrefix(ct, "application/x-www-form-urlencoded"):
		return BodyForm
	case strings.HasPrefix(ct, "multipart/form-data"):
		return BodyMultipart
	case strings.Contains(ct, "json"):
		return BodyJSON
	case ct == "":
		// No declared type: honour the documented sniff so a JSON body still
		// gets body.* fuzz targets instead of silently narrowing the pass.
		if json.Valid(f.Body) {
			return BodyJSON
		}
		return BodyText
	default:
		return BodyText
	}
}

// ValidationError reports a .kh file that cannot be used at all.
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Reason)
}

var knownTopLevel = map[string]bool{
	"format": true, "name": true, "method": true, "url": true,
	"headers": true, "query": true, "auth": true, "fuzz": true,
	"spec": true, "timeout_ms": true, "follow_redirects": true,
}

var knownAuth = map[string]bool{
	"type": true, "username": true, "password": true, "token": true,
	"in": true, "name": true, "value": true,
}

var knownFuzz = map[string]bool{
	"targets": true, "wordlist": true, "methods": true, "max_requests": true,
	"rate_limit": true, "per_host_concurrency": true,
}

var knownSpec = map[string]bool{
	"source": true, "operation": true, "baseline": true,
}

var validMethods = map[string]bool{
	http.MethodGet: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodPatch: true, http.MethodDelete: true, http.MethodHead: true,
	http.MethodOptions: true,
}
