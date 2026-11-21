// Package http turns a parsed .kh file into an HTTP request and executes it.
// It deliberately uses only net/http from the standard library.
package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/24Bit-System/kilhook/internal/format"
)

// MaxResponseBytes bounds how much of a response body is read. A malicious or
// broken server must not be able to exhaust memory (project.md §11.3).
const MaxResponseBytes = 10 << 20 // 10 MiB

// Request is a fully resolved request, ready to send.
type Request struct {
	Method          string
	URL             string
	Headers         map[string]string
	Query           map[string]string
	Host            string // override for the Host header; empty means the URL host
	Body            []byte
	Auth            *format.Auth
	Timeout         time.Duration
	FollowRedirects bool
	InsecureTLS     bool
}

// Response is the outcome of one request.
type Response struct {
	StatusCode int
	Status     string
	Header     http.Header
	Body       []byte
	Duration   time.Duration
	URL        string
	Truncated  bool
}

// JSON reports whether the response advertises a JSON body.
func (r *Response) JSON() bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "json")
}

// FromFile resolves a parsed .kh file against environment variables.
func FromFile(f *format.File, vars map[string]string) (*Request, error) {
	expand := func(what, s string) (string, error) {
		out, err := Interpolate(s, vars)
		if err != nil {
			return "", fmt.Errorf("%s: %w", what, err)
		}
		return out, nil
	}

	rawURL, err := expand("url", f.URL)
	if err != nil {
		return nil, err
	}
	headers := make(map[string]string, len(f.Headers))
	for k, v := range f.Headers {
		hv, err := expand("header "+k, v)
		if err != nil {
			return nil, err
		}
		headers[k] = hv
	}
	query := make(map[string]string, len(f.Query))
	for k, v := range f.Query {
		qv, err := expand("query "+k, v)
		if err != nil {
			return nil, err
		}
		query[k] = qv
	}

	auth := f.Auth
	if auth != nil {
		cp := *auth
		auth = &cp
		for field, val := range map[string]*string{
			"auth.username": &auth.Username,
			"auth.password": &auth.Password,
			"auth.token":    &auth.Token,
			"auth.value":    &auth.Value,
		} {
			expanded, err := expand(field, *val)
			if err != nil {
				return nil, err
			}
			*val = expanded
		}
	}

	req := &Request{
		Method:          f.Method,
		URL:             rawURL,
		Headers:         headers,
		Query:           query,
		Auth:            auth,
		Timeout:         time.Duration(f.Timeout()) * time.Millisecond,
		FollowRedirects: f.Redirects(),
	}
	if body := f.Body; len(body) > 0 {
		expanded, err := expand("body", string(body))
		if err != nil {
			return nil, err
		}
		req.Body = []byte(expanded)
	}
	return req, nil
}

// Do executes the request. The body read is bounded by MaxResponseBytes.
func Do(ctx context.Context, req *Request, opts ...Option) (*Response, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}

	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("url %q: %w", req.URL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("url %q: missing scheme or host", req.URL)
	}
	if len(req.Query) > 0 {
		q := u.Query()
		for k, v := range req.Query {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = format.DefaultTimeoutMS * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	body := req.Body
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	hreq, err := http.NewRequestWithContext(ctx, req.Method, u.String(), bodyReader)
	if err != nil {
		return nil, err
	}
	// Header.Set canonicalises the name, so case-variant duplicates in the
	// file ("Content-Type" beside "content-type") collapse into one header and
	// the last Set wins. Walk the keys in descending order so the
	// lexicographically smallest key wins — the same rule File.ContentType()
	// uses — keeping the wire request consistent with the body classification.
	keys := SortedKeys(req.Headers)
	for i := len(keys) - 1; i >= 0; i-- {
		hreq.Header.Set(keys[i], req.Headers[keys[i]])
	}
	if req.Auth != nil {
		switch req.Auth.Type {
		case format.AuthBasic:
			hreq.SetBasicAuth(req.Auth.Username, req.Auth.Password)
		case format.AuthBearer:
			hreq.Header.Set("Authorization", "Bearer "+req.Auth.Token)
		case format.AuthAPIKey:
			switch req.Auth.In {
			case "header":
				hreq.Header.Set(req.Auth.Name, req.Auth.Value)
			case "query":
				q := hreq.URL.Query()
				q.Set(req.Auth.Name, req.Auth.Value)
				hreq.URL.RawQuery = q.Encode()
			}
		}
	}
	// Header["Host"] is ignored by net/http; Request.Host is the only way to
	// override the host line on the wire (fuzz target header.Host uses it).
	if req.Host != "" {
		hreq.Host = req.Host
	}

	tr := sharedTransport(req.InsecureTLS || o.insecureTLS, req.MaxPerHost(o.perHost), o.localOnly)
	client := &http.Client{Transport: tr, Timeout: timeout}
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if !req.FollowRedirects {
			return http.ErrUseLastResponse
		}
		if o.localOnly && !IsLoopback(next.URL.String()) {
			// Stop at the redirect instead of following it off-machine. The
			// caller sees the 3xx response, which is honest: the request was not
			// made.
			return http.ErrUseLastResponse
		}
		return nil
	}

	start := time.Now()
	resp, err := client.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	limit := o.maxBody
	if limit <= 0 {
		limit = MaxResponseBytes
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	truncated := int64(len(data)) > limit
	if truncated {
		data = data[:limit]
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Header:     resp.Header,
		Body:       data,
		Duration:   time.Since(start),
		URL:        resp.Request.URL.String(),
		Truncated:  truncated,
	}, nil
}

// MaxPerHost is the per-host connection cap used by the transport.
func (r *Request) MaxPerHost(def int) int {
	if def > 0 {
		return def
	}
	return format.DefaultPerHost
}

// transportKey identifies one cached transport configuration.
type transportKey struct {
	insecure  bool
	perHost   int
	localOnly bool
}

var (
	transportMu sync.Mutex
	transports  = make(map[transportKey]*http.Transport)
)

// sharedTransport returns one cached *http.Transport per option set. A fuzz
// run performs hundreds of Do calls; building a transport per call means a
// TCP/TLS handshake per request, no connection reuse, and inflated Duration
// values that the timing heuristic reads. The http.Client stays per-call: its
// timeout and CheckRedirect closure depend on the individual request.
func sharedTransport(insecure bool, perHost int, localOnly bool) *http.Transport {
	if perHost <= 0 {
		perHost = format.DefaultPerHost
	}
	key := transportKey{insecure: insecure, perHost: perHost, localOnly: localOnly}

	transportMu.Lock()
	defer transportMu.Unlock()
	if tr, ok := transports[key]; ok {
		return tr
	}
	tr := &http.Transport{
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   perHost,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if !localOnly {
		// A local-only run must not be routed through an HTTP proxy: the proxy
		// would make the "loopback" request on another machine. With no proxy
		// configured, the URL host is the host actually dialed.
		tr.Proxy = http.ProxyFromEnvironment
	}
	tr.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit opt-in
	}
	transports[key] = tr
	return tr
}

// Option tunes a single Do call.
type Option func(*options)

type options struct {
	maxBody     int64
	perHost     int
	insecureTLS bool
	localOnly   bool
}

func defaultOptions() options {
	return options{maxBody: MaxResponseBytes, perHost: format.DefaultPerHost}
}

// WithMaxBodyBytes overrides the response body read limit.
func WithMaxBodyBytes(n int64) Option { return func(o *options) { o.maxBody = n } }

// WithLocalOnly refuses to follow a redirect that leaves this machine. The fuzz
// runner sets it whenever --allow-nonlocal is absent: a local server that
// redirects to the internet must not turn a loopback-only run into one that
// sprays a remote host.
func WithLocalOnly() Option { return func(o *options) { o.localOnly = true } }

// WithPerHostConcurrency overrides the per-host connection cap.
func WithPerHostConcurrency(n int) Option { return func(o *options) { o.perHost = n } }

// WithInsecureTLS disables certificate verification for the request.
func WithInsecureTLS() Option { return func(o *options) { o.insecureTLS = true } }

// HostOf returns the host of a URL, or "" when it cannot be parsed.
func HostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// IsLoopback reports whether the URL targets this machine.
func IsLoopback(raw string) bool {
	h := HostOf(raw)
	if h == "" {
		return false
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// SortedKeys is a small helper for deterministic reports.
func SortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
