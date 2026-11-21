// Package fuzz turns declared .kh targets plus a payload list into concrete
// request mutations, runs them under rate and safety limits, and classifies what
// came back.
package fuzz

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/24Bit-System/kilhook/internal/format"
	httpreq "github.com/24Bit-System/kilhook/internal/http"
)

// Target kinds.
const (
	KindBody   = "body"
	KindQuery  = "query"
	KindHeader = "header"
	KindPath   = "path"
)

// Target is one declared injection point.
type Target struct {
	Raw    string
	Kind   string
	Path   []string // body: object keys / array indices; path: one numeric segment; query/header: the name
	Method string   // fuzz method this target was resolved under, for diagnostics
}

// ParseTarget parses "query.q", "header.X-Forwarded-For", "path.0", "body.user.name".
func ParseTarget(raw string) (Target, error) {
	kind, rest, ok := strings.Cut(strings.TrimSpace(raw), ".")
	if !ok || rest == "" {
		return Target{}, fmt.Errorf("malformed target %q", raw)
	}
	t := Target{Raw: raw, Kind: kind}
	switch kind {
	case KindBody:
		for _, seg := range strings.Split(rest, ".") {
			if seg == "" {
				return Target{}, fmt.Errorf("target %q has an empty path segment", raw)
			}
			t.Path = append(t.Path, seg)
		}
	case KindPath:
		idx, err := strconv.Atoi(rest)
		if err != nil || idx < 0 {
			return Target{}, fmt.Errorf("target %q: path index must be a non-negative integer", raw)
		}
		t.Path = []string{strconv.Itoa(idx)}
	case KindQuery, KindHeader:
		if kind == KindHeader && format.ManagedHeader(rest) {
			return Target{}, fmt.Errorf("target %q: %s is managed by the HTTP client and cannot be fuzzed", raw, rest)
		}
		t.Path = []string{rest}
	default:
		return Target{}, fmt.Errorf("target %q: unknown kind %q", raw, kind)
	}
	return t, nil
}

// Mutate returns a copy of req with payload injected at target. It never
// modifies the input and never touches the .kh file on disk.
func Mutate(req *httpreq.Request, t Target, payload string, typed bool) (*httpreq.Request, error) {
	out := &httpreq.Request{
		Method:          req.Method,
		URL:             req.URL,
		Timeout:         req.Timeout,
		FollowRedirects: req.FollowRedirects,
		InsecureTLS:     req.InsecureTLS,
		Body:            req.Body,
		Headers:         copyMap(req.Headers),
		Query:           copyMap(req.Query),
	}
	if req.Auth != nil {
		a := *req.Auth
		out.Auth = &a
	}
	out.Host = req.Host

	switch t.Kind {
	case KindHeader:
		// net/http ignores Header["Host"]; Request.Host is the only override
		// that reaches the wire, so header.Host is routed there explicitly.
		if strings.EqualFold(t.Path[0], "Host") {
			out.Host = payload
		} else {
			// HTTP header names are case-insensitive. If the request already
			// declares this header under a different casing, mutate that key:
			// adding a second map entry would be canonicalised by Do's
			// Header.Set loop and the *original* value would win, so the
			// payload would silently never reach the wire.
			key := t.Path[0]
			for k := range out.Headers {
				if strings.EqualFold(k, key) {
					key = k
					break
				}
			}
			out.Headers[key] = payload
		}
	case KindQuery:
		out.Query[t.Path[0]] = payload
	case KindPath:
		idx, _ := strconv.Atoi(t.Path[0])
		mutated, err := mutatePath(out.URL, idx, payload)
		if err != nil {
			return nil, err
		}
		out.URL = mutated
	case KindBody:
		mutated, err := mutateBody(out.Body, t.Path, payload, typed)
		if err != nil {
			return nil, err
		}
		out.Body = mutated
	default:
		return nil, fmt.Errorf("unknown target kind %q", t.Kind)
	}
	return out, nil
}

func mutatePath(rawURL string, idx int, payload string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	// Split the *escaped* path: u.Path is the decoded form, so splitting it
	// would turn a pre-existing "%2F" inside one segment into a segment
	// separator and re-escape the untouched segments differently than the
	// caller wrote them. Working on EscapedPath leaves every segment this
	// mutation does not touch byte-identical on the wire.
	escaped := u.EscapedPath()
	// Preserve the exact number of leading and trailing slashes: strings.Trim
	// removes all of them, which would change a URL like /a//b/ into /a/b/.
	leading := len(escaped) - len(strings.TrimLeft(escaped, "/"))
	trailing := len(escaped) - len(strings.TrimRight(escaped, "/"))
	trimmed := strings.Trim(escaped, "/")
	var segments []string
	if trimmed != "" {
		segments = strings.Split(trimmed, "/")
	}
	if idx >= len(segments) {
		return "", fmt.Errorf("path index %d out of range (%d segments)", idx, len(segments))
	}
	segments[idx] = url.PathEscape(payload)

	prefix := strings.Repeat("/", leading)
	suffix := strings.Repeat("/", trailing)
	escPath := prefix + strings.Join(segments, "/") + suffix
	plain := make([]string, len(segments))
	for i, s := range segments {
		p, err := url.PathUnescape(s)
		if err != nil {
			return "", fmt.Errorf("path segment %q: %w", s, err)
		}
		plain[i] = p
	}
	u.Path = prefix + strings.Join(plain, "/") + suffix
	// url.String() uses RawPath only when it is a valid encoding of Path;
	// both were derived from the same segments, so they always agree here.
	if escPath != u.Path {
		u.RawPath = escPath
	} else {
		u.RawPath = ""
	}
	return u.String(), nil
}

// mutateBody sets payload at a dot path inside the JSON body. typed=true injects
// the payload as a JSON literal (wrong type on purpose), typed=false as a string.
func mutateBody(body []byte, path []string, payload string, typed bool) ([]byte, error) {
	var doc any
	dec := json.NewDecoder(bytes.NewReader(body))
	// Without UseNumber every untouched numeric field becomes float64 and is
	// re-encoded with precision loss: a snowflake ID would silently change in
	// every fuzz request. The JSON differ already does this for the same reason.
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("body is not JSON: %w", err)
	}

	var value any = payload
	if typed {
		var lit any
		literal := json.NewDecoder(strings.NewReader(payload))
		literal.UseNumber()
		if err := literal.Decode(&lit); err != nil || !onlyWhitespaceRemains(literal) {
			// Not a single JSON literal: fall back to a string so a bad wordlist
			// line does not abort the run or silently inject a different value.
			value = payload
		} else {
			value = lit
		}
	}

	updated, err := setPath(doc, path, value)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(updated); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// onlyWhitespaceRemains reports whether a decoder is at EOF after reading one
// value. json.Decoder.Decode ignores trailing data by default, which would let
// a wordlist line like "1 2" silently inject just "1".
func onlyWhitespaceRemains(dec *json.Decoder) bool {
	var extra any
	return dec.Decode(&extra) == io.EOF
}

func setPath(doc any, path []string, value any) (any, error) {
	if len(path) == 0 {
		return value, nil
	}
	head := path[0]
	switch node := doc.(type) {
	case map[string]any:
		child, ok := node[head]
		if !ok {
			// Allow extending objects: a declared target is intent to write.
			child = nil
		}
		next, err := setPath(child, path[1:], value)
		if err != nil {
			return nil, err
		}
		node[head] = next
		return node, nil
	case []any:
		idx, err := strconv.Atoi(head)
		if err != nil || idx < 0 || idx >= len(node) {
			return nil, fmt.Errorf("body path segment %q is not a valid array index (len %d)", head, len(node))
		}
		next, err := setPath(node[idx], path[1:], value)
		if err != nil {
			return nil, err
		}
		node[idx] = next
		return node, nil
	case nil:
		// Build a container of the right shape for the remaining path.
		if _, err := strconv.Atoi(head); err == nil {
			return nil, fmt.Errorf("body path segment %q needs an array, found nothing", head)
		}
		m := map[string]any{}
		next, err := setPath(nil, path[1:], value)
		if err != nil {
			return nil, err
		}
		m[head] = next
		return m, nil
	default:
		return nil, fmt.Errorf("body path segment %q: cannot descend into %T", head, doc)
	}
}

func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// TargetsFromStrings resolves declared target strings, preserving order.
func TargetsFromStrings(raw []string) ([]Target, []string, error) {
	var targets []Target
	var warnings []string
	for _, r := range raw {
		t, err := ParseTarget(r)
		if err != nil {
			warnings = append(warnings, err.Error())
			continue
		}
		targets = append(targets, t)
	}
	return targets, warnings, nil
}

// SortTargets gives reports a stable order.
func SortTargets(in []Target) {
	sort.Slice(in, func(i, j int) bool { return in[i].Raw < in[j].Raw })
}
