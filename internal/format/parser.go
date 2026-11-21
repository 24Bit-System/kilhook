package format

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Parse parses a .kh file. Warnings are recoverable problems that change what
// runs (an ignored target, an unknown field); an error means the file cannot be
// executed at all.
func Parse(data []byte) (*File, []string, error) {
	if len(data) > MaxFileBytes {
		return nil, nil, &ValidationError{"format", fmt.Sprintf("file is %d bytes, over the %d-byte limit", len(data), MaxFileBytes)}
	}
	front, body, err := split(data)
	if err != nil {
		return nil, nil, err
	}

	var f File
	if err := yaml.Unmarshal(front, &f); err != nil {
		return nil, nil, fmt.Errorf("frontmatter: %w", err)
	}
	f.Body = body

	var raw map[string]any
	if err := yaml.Unmarshal(front, &raw); err != nil {
		return nil, nil, fmt.Errorf("frontmatter: %w", err)
	}

	if err := f.validate(); err != nil {
		return nil, nil, err
	}

	var warnings []string
	warnings = append(warnings, unknownKeys("frontmatter", raw, knownTopLevel)...)
	if sub, ok := raw["auth"].(map[string]any); ok {
		warnings = append(warnings, unknownKeys("auth", sub, knownAuth)...)
	}
	if sub, ok := raw["fuzz"].(map[string]any); ok {
		warnings = append(warnings, unknownKeys("fuzz", sub, knownFuzz)...)
	}
	if sub, ok := raw["spec"].(map[string]any); ok {
		warnings = append(warnings, unknownKeys("spec", sub, knownSpec)...)
	}
	warnings = append(warnings, f.applyFuzzDefaults()...)
	warnings = append(warnings, f.filterTargets()...)
	warnings = append(warnings, duplicateHeaderWarnings(f.Headers)...)

	return &f, dedupe(warnings), nil
}

// duplicateHeaderWarnings flags header names repeated with different casing
// ("Content-Type" beside "content-type"). YAML accepts both keys, but HTTP
// header names are case-insensitive, so the wire request is ambiguous: the
// client sends both lines and the server picks. ContentType() and the client's
// header setting resolve deterministically; the user still deserves the note.
func duplicateHeaderWarnings(headers map[string]string) []string {
	if len(headers) < 2 {
		return nil
	}
	byLower := make(map[string][]string, len(headers))
	for k := range headers {
		l := strings.ToLower(k)
		byLower[l] = append(byLower[l], k)
	}
	var warnings []string
	for l, variants := range byLower {
		if len(variants) < 2 {
			continue
		}
		sort.Strings(variants)
		warnings = append(warnings, fmt.Sprintf(
			"headers: %q appears as both %s; HTTP header names are case-insensitive, so the request may send it twice",
			l, strings.Join(variants, " and ")))
	}
	sort.Strings(warnings)
	return warnings
}

func (f *File) validate() error {
	if f.Format == 0 {
		return &ValidationError{"format", "missing; every .kh file must declare format: 1"}
	}
	if f.Format != Version {
		return &ValidationError{"format", fmt.Sprintf("unsupported version %d (this build supports %d)", f.Format, Version)}
	}
	if strings.TrimSpace(f.Name) == "" {
		return &ValidationError{"name", "required"}
	}
	if strings.TrimSpace(f.URL) == "" {
		return &ValidationError{"url", "required"}
	}
	f.Method = strings.ToUpper(strings.TrimSpace(f.Method))
	if f.Method == "" {
		return &ValidationError{"method", "required"}
	}
	if !validMethods[f.Method] {
		return &ValidationError{"method", fmt.Sprintf("unsupported method %q", f.Method)}
	}
	if f.TimeoutMS < 0 {
		return &ValidationError{"timeout_ms", "must not be negative"}
	}
	if f.TimeoutMS > MaxRequestTimeout {
		return &ValidationError{"timeout_ms", fmt.Sprintf("must not exceed %d", MaxRequestTimeout)}
	}
	if f.Auth != nil {
		f.Auth.Type = strings.ToLower(strings.TrimSpace(f.Auth.Type))
		if f.Auth.Type == "" {
			f.Auth.Type = AuthNone
		}
		switch f.Auth.Type {
		case AuthNone, AuthBasic, AuthBearer:
		case AuthAPIKey:
			f.Auth.In = strings.ToLower(strings.TrimSpace(f.Auth.In))
			if f.Auth.In != "header" && f.Auth.In != "query" {
				return &ValidationError{"auth.in", `must be "header" or "query"`}
			}
			if strings.TrimSpace(f.Auth.Name) == "" {
				return &ValidationError{"auth.name", "required for api_key auth"}
			}
		default:
			return &ValidationError{"auth.type", fmt.Sprintf("unsupported type %q", f.Auth.Type)}
		}
	}
	if f.Fuzz != nil {
		if math.IsNaN(f.Fuzz.RateLimit) || math.IsInf(f.Fuzz.RateLimit, 0) {
			return &ValidationError{"fuzz.rate_limit", "must be a finite number"}
		}
		if f.Fuzz.RateLimit < 0 {
			return &ValidationError{"fuzz.rate_limit", "must not be negative"}
		}
		if f.Fuzz.RateLimit > 0 && f.Fuzz.RateLimit < MinRateLimit {
			return &ValidationError{"fuzz.rate_limit", fmt.Sprintf("must be at least %g", MinRateLimit)}
		}
		if f.Fuzz.RateLimit > MaxRateLimit {
			return &ValidationError{"fuzz.rate_limit", fmt.Sprintf("must not exceed %g", MaxRateLimit)}
		}
		if f.Fuzz.MaxRequests < 0 {
			return &ValidationError{"fuzz.max_requests", "must not be negative"}
		}
		if f.Fuzz.MaxRequests > MaxFuzzRequests {
			return &ValidationError{"fuzz.max_requests", fmt.Sprintf("must not exceed %d", MaxFuzzRequests)}
		}
		if f.Fuzz.PerHostConcurrency < 0 {
			return &ValidationError{"fuzz.per_host_concurrency", "must not be negative"}
		}
		if f.Fuzz.PerHostConcurrency > MaxPerHostLimit {
			return &ValidationError{"fuzz.per_host_concurrency", fmt.Sprintf("must not exceed %d", MaxPerHostLimit)}
		}
		for _, m := range f.Fuzz.Methods {
			switch m {
			case "injection", "boundary", "type_confusion":
			default:
				return &ValidationError{"fuzz.methods", fmt.Sprintf("unknown method %q", m)}
			}
		}
	}
	return nil
}

// applyFuzzDefaults fills every unset knob with the documented default so the
// runner never has to invent a fallback.
func (f *File) applyFuzzDefaults() []string {
	if f.Fuzz == nil {
		return nil
	}
	var warnings []string
	if f.Fuzz.MaxRequests <= 0 {
		f.Fuzz.MaxRequests = DefaultMaxRequests
	}
	if f.Fuzz.RateLimit <= 0 {
		f.Fuzz.RateLimit = DefaultRateLimit
	}
	if f.Fuzz.PerHostConcurrency <= 0 {
		f.Fuzz.PerHostConcurrency = DefaultPerHost
	}
	if len(f.Fuzz.Methods) == 0 {
		f.Fuzz.Methods = []string{"injection"}
	}
	if f.Fuzz.Wordlist == "" {
		f.Fuzz.Wordlist = "default"
	}
	if len(f.Fuzz.Targets) == 0 {
		warnings = append(warnings, "fuzz: block present with no targets; the fuzz pass will be skipped")
	}
	return warnings
}

// filterTargets validates declared targets and drops the ones v1 cannot honour.
// A dropped target always produces a warning; nothing is ever silently ignored.
func (f *File) filterTargets() []string {
	if f.Fuzz == nil || len(f.Fuzz.Targets) == 0 {
		return nil
	}
	bodyType := f.BodyType()
	bodyTargetsSkipped := false
	pathSegments := literalPathSegments(f.URL)

	var kept []string
	var warnings []string
	for _, t := range f.Fuzz.Targets {
		t = strings.TrimSpace(t)
		if t == "" {
			warnings = append(warnings, "fuzz.targets: empty target ignored")
			continue
		}
		kind, rest, ok := strings.Cut(t, ".")
		if !ok || rest == "" {
			warnings = append(warnings, fmt.Sprintf("fuzz.targets: malformed target %q ignored (expected body.x, query.x, header.X or path.N)", t))
			continue
		}
		switch kind {
		case "body":
			if bodyType == BodyForm || bodyType == BodyMultipart {
				bodyTargetsSkipped = true
				continue
			}
			if bodyType != BodyJSON {
				warnings = append(warnings, fmt.Sprintf("fuzz.targets: %q skipped, body is %s not JSON", t, bodyTypeName(bodyType)))
				continue
			}
			if !json.Valid(f.Body) {
				warnings = append(warnings, fmt.Sprintf("fuzz.targets: %q skipped, body is not valid JSON", t))
				continue
			}
		case "path":
			idx, err := strconv.Atoi(rest)
			if err != nil || idx < 0 {
				warnings = append(warnings, fmt.Sprintf("fuzz.targets: %q ignored, path index must be a non-negative integer", t))
				continue
			}
			if pathSegments >= 0 && idx >= pathSegments {
				warnings = append(warnings, fmt.Sprintf("fuzz.targets: %q skipped, URL has %d path segments", t, pathSegments))
				continue
			}
		case "query", "header":
			if kind == "header" && ManagedHeader(rest) {
				warnings = append(warnings, fmt.Sprintf("fuzz.targets: %q skipped, %s is managed by the HTTP client and cannot be fuzzed", t, rest))
				continue
			}
		default:
			warnings = append(warnings, fmt.Sprintf("fuzz.targets: %q ignored, unknown target kind %q", t, kind))
			continue
		}
		kept = append(kept, t)
	}
	f.Fuzz.Targets = kept

	if bodyTargetsSkipped {
		warnings = append(warnings, fmt.Sprintf("fuzz.targets: body.* targets skipped, %s body fuzzing is out of scope for format %d (JSON only)", bodyTypeName(bodyType), Version))
	}
	return warnings
}

// literalPathSegments returns the number of URL path segments, or -1 when the
// URL is not concrete enough to count (it still contains an interpolation).
func literalPathSegments(raw string) int {
	if strings.Contains(raw, "{{") {
		return -1
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return -1
	}
	p := strings.Trim(u.Path, "/")
	if p == "" {
		return 0
	}
	return len(strings.Split(p, "/"))
}

func bodyTypeName(t string) string {
	switch t {
	case BodyNone:
		return "empty"
	case BodyJSON:
		return "JSON"
	case BodyForm:
		return "form-urlencoded"
	case BodyMultipart:
		return "multipart"
	default:
		return "text"
	}
}

func unknownKeys(scope string, raw map[string]any, known map[string]bool) []string {
	var warnings []string
	for k := range raw {
		if !known[k] {
			warnings = append(warnings, fmt.Sprintf("%s: unknown field %q ignored", scope, k))
		}
	}
	return warnings
}

func split(data []byte) (front, body []byte, err error) {
	s := string(data)
	start := 0
	// A YAML block scalar (key: | or key: >) may contain a literal "---" on
	// its own line. Track the active block's indentation so that line is not
	// mistaken for the frontmatter/body separator.
	blockIndent := -1
	for {
		nl := strings.IndexByte(s[start:], '\n')
		var line string
		next := len(s)
		if nl < 0 {
			line = s[start:]
		} else {
			line = s[start : start+nl]
			next = start + nl + 1
		}
		indent := leadingIndent(line)
		if blockIndent >= 0 {
			if strings.TrimSpace(line) != "" && indent <= blockIndent {
				blockIndent = -1
			}
		}
		if blockIndent < 0 {
			if n := blockScalarIndent(line); n >= 0 {
				blockIndent = n
			}
		}
		if blockIndent < 0 && strings.TrimRight(line, " \t\r") == "---" {
			return []byte(s[:start]), []byte(s[next:]), nil
		}
		if nl < 0 {
			break
		}
		start = next
	}
	return nil, nil, &ValidationError{"format", `no "---" separator between frontmatter and body`}
}

func leadingIndent(line string) int {
	n := 0
	for n < len(line) && (line[n] == ' ' || line[n] == '\t') {
		n++
	}
	return n
}

// blockScalarIndent returns the indentation of a "key: |" / "key: >" line, or
// -1 when the line does not open a block scalar.
func blockScalarIndent(line string) int {
	rest := strings.TrimLeft(line, " \t")
	idx := strings.Index(rest, ":")
	if idx < 0 {
		return -1
	}
	value := strings.TrimLeft(rest[idx+1:], " \t")
	if value == "" || (value[0] != '|' && value[0] != '>') {
		return -1
	}
	return leadingIndent(line)
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
