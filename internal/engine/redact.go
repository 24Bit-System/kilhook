package engine

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/24Bit-System/kilhook/internal/diff"
	"github.com/24Bit-System/kilhook/internal/fuzz"
	"github.com/24Bit-System/kilhook/internal/spec"
)

// sensitiveMarkers are the name fragments that make a header, query parameter
// or JSON field value unsafe to put in a report. They match the list the header
// redactor has always used, plus the spellings common in query strings and
// config files (api_key, private_key, pwd).
var sensitiveMarkers = []string{
	"authorization", "cookie", "api-key", "api_key", "apikey",
	"access-key", "access_key", "accesskey", "private-key", "private_key", "privatekey",
	"token", "secret", "password", "passwd", "pwd", "credential", "auth",
	"session", "signature", "bearer", "pass", "pw",
}

// isSensitiveName reports whether a header/query/body field name carries a
// credential. The comparison is deliberately a contains check: names like
// X-Auth-Token and client_secret must both match.
func isSensitiveName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, marker := range sensitiveMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

const redacted = "[redacted]"

// redactQuery returns a copy of a request's query map with sensitive values
// replaced. The original map is never modified (it still has to drive the run).
func redactQuery(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if isSensitiveName(k) {
			out[k] = redacted
			continue
		}
		out[k] = v
	}
	return out
}

// redactURL hides credentials in the URL's userinfo and in sensitive query
// parameters. Non-sensitive parts are kept byte-identical: a single "changed"
// flag used to make userinfo redaction re-encode the entire query and reorder
// its parameters, which made ordinary URLs unreadable in reports.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	changed := false
	if u.User != nil {
		// A username alone can be a credential (https://TOKEN@example.test).
		_, hasPassword := u.User.Password()
		if hasPassword {
			u.User = url.UserPassword(redacted, redacted)
		} else {
			u.User = url.User(redacted)
		}
		changed = true
	}
	if u.RawQuery != "" {
		if q, ok := redactRawQuery(u.RawQuery); ok {
			u.RawQuery = q
			changed = true
		}
	}
	if !changed {
		return raw
	}
	return u.String()
}

// redactRawQuery redacts sensitive parameters in a raw query string while
// preserving every non-sensitive pair byte for byte. url.Query() cannot be used
// here: it silently drops pairs with semicolons, which would leave a credential
// such as "?token=secret;q=1" intact in the report.
func redactRawQuery(raw string) (string, bool) {
	parts := strings.Split(raw, "&")
	changed := false
	for i, part := range parts {
		key, _, hasValue := strings.Cut(part, "=")
		decoded, err := url.QueryUnescape(key)
		if err != nil {
			decoded = key
		}
		if !isSensitiveName(decoded) {
			continue
		}
		if hasValue {
			parts[i] = key + "=" + url.QueryEscape(redacted)
		} else {
			parts[i] = key + "=" + url.QueryEscape(redacted)
		}
		changed = true
	}
	return strings.Join(parts, "&"), changed
}

// redactBody redacts credentials in a JSON (including NDJSON), form-urlencoded
// or multipart body preview. Every branch is designed to redact what it can
// even when the rest of the body is malformed: a single bad escape or a second
// JSON document must never disable redaction for the whole preview.
func redactBody(body []byte) []byte {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return body
	}
	switch {
	case trimmed[0] == '{' || trimmed[0] == '[':
		return redactJSONDocuments(trimmed, body)
	case bytes.HasPrefix(bytes.ToLower(trimmed), []byte("--")):
		return redactMultipart(trimmed, body)
	case bytes.Contains(trimmed, []byte("=")):
		return redactForm(trimmed, body)
	default:
		return []byte(redactFindingText(string(body)))
	}
}

// redactJSONDocuments redacts every JSON value in a (possibly NDJSON) body.
func redactJSONDocuments(trimmed, original []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var docs []any
	for {
		var doc any
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			// Unparseable tail: fall back to generic text redaction over the
			// whole body rather than returning secrets untouched.
			return []byte(redactFindingText(string(original)))
		}
		docs = append(docs, doc)
	}
	if len(docs) == 0 {
		return []byte(redactFindingText(string(original)))
	}
	out := redactJSONSlice(docs)
	if out != nil {
		return out
	}
	return original
}

func redactJSONSlice(docs []any) []byte {
	var buf bytes.Buffer
	changed := false
	for i, doc := range docs {
		redactedDoc, ch := redactJSONValue(doc)
		changed = changed || ch
		if i > 0 {
			buf.WriteByte('\n')
		}
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(redactedDoc); err != nil {
			return nil
		}
	}
	if !changed {
		return nil
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// redactForm redacts sensitive form fields without relying on url.ParseQuery,
// which returns partial values together with an error on a single bad escape.
func redactForm(trimmed, original []byte) []byte {
	text, changed := redactRawQuery(strings.TrimSpace(string(trimmed)))
	if !changed {
		return original
	}
	return []byte(strings.Replace(string(original), strings.TrimSpace(string(trimmed)), text, 1))
}

// redactMultipart redacts the value part of a multipart field whose
// Content-Disposition carries a sensitive name. It is a line-based state
// machine rather than a full MIME parser: previews only need to stop secrets
// from being exported, not to preserve the exact framing.
func redactMultipart(trimmed, original []byte) []byte {
	text := string(trimmed)
	lines := strings.Split(text, "\n")
	redact := false
	inBody := false
	changed := false
	for i, line := range lines {
		trimmedLine := strings.TrimRight(line, "\r")
		if strings.HasPrefix(trimmedLine, "--") {
			redact = false
			inBody = false
			continue
		}
		if m := multipartName.FindStringSubmatch(trimmedLine); m != nil && isSensitiveName(m[1]) {
			redact = true
			inBody = false
			continue
		}
		if !inBody {
			if trimmedLine == "" {
				inBody = true
			}
			continue
		}
		if redact && trimmedLine != "" {
			prefix := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			lines[i] = prefix + redacted
			changed = true
		}
	}
	if !changed {
		return original
	}
	return []byte(strings.Join(lines, "\n"))
}

var multipartName = regexp.MustCompile(`(?i)name="([^"]*)"`)

// credentialAssignment matches "key: value", "key=value" and their JSON
// spellings inside arbitrary text, so that report excerpts can be redacted
// even when the surrounding body was not parseable.
var credentialAssignment = regexp.MustCompile(`(?i)(\b(?:authorization|cookie|api[-_]?key|apikey|access[-_]?key|access[-_]?token|refresh[-_]?token|token|secret|password|passwd|pwd|private[-_]?key|credential|session|signature)["']?\s*[:=]\s*)("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s&;,}\]]+)`)

var bearerToken = regexp.MustCompile(`(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+`)

// redactFindingText applies best-effort redaction to a free-text report field.
func redactFindingText(s string) string {
	s = credentialAssignment.ReplaceAllString(s, "${1}"+redacted)
	return bearerToken.ReplaceAllString(s, "${1}"+redacted)
}

func redactFindings(in []fuzz.Finding) []fuzz.Finding {
	if len(in) == 0 {
		return in
	}
	out := make([]fuzz.Finding, len(in))
	for i, f := range in {
		out[i] = f
		out[i].Payload = redactFindingText(f.Payload)
		out[i].Evidence = redactFindingText(f.Evidence)
	}
	return out
}

func redactViolations(in []spec.Violation) []spec.Violation {
	if len(in) == 0 {
		return in
	}
	out := make([]spec.Violation, len(in))
	for i, v := range in {
		out[i] = v
		out[i].Message = redactFindingText(v.Message)
	}
	return out
}

func redactJSONValue(v any) (any, bool) {
	switch node := v.(type) {
	case map[string]any:
		changed := false
		for k, val := range node {
			if isSensitiveName(k) {
				node[k] = redacted
				changed = true
				continue
			}
			next, childChanged := redactJSONValue(val)
			if childChanged {
				node[k] = next
				changed = true
			}
		}
		return node, changed
	case []any:
		changed := false
		for i, val := range node {
			next, childChanged := redactJSONValue(val)
			if childChanged {
				node[i] = next
				changed = true
			}
		}
		return node, changed
	default:
		return v, false
	}
}

// redactChanges hides values whose JSON path names a credential, then applies
// the text redactor to both sides so a secret quoted inside an ordinary field
// is caught too. This covers JSON diffs and plain-text line diffs alike.
func redactChanges(in []diff.Change) []diff.Change {
	if len(in) == 0 {
		return in
	}
	out := make([]diff.Change, len(in))
	for i, c := range in {
		out[i] = c
		out[i].Before = redactFindingText(c.Before)
		out[i].After = redactFindingText(c.After)
		if isSensitiveName(c.Path) {
			if c.Before != "" {
				out[i].Before = redacted
			}
			if c.After != "" {
				out[i].After = redacted
			}
		}
	}
	return out
}
