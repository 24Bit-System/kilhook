package http

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/24Bit-System/kilhook/internal/format"
)

func TestInterpolateReplacesAll(t *testing.T) {
	got, err := Interpolate("{{base}}/x/{{ id }}?a={{base}}", map[string]string{"base": "http://h", "id": "42"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "http://h/x/42?a=http://h"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestInterpolateReportsAllMissing(t *testing.T) {
	_, err := Interpolate("{{a}}/{{b}}/{{a}}", map[string]string{})
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "a, b") {
		t.Fatalf("error = %q, want a, b listed once each", msg)
	}
}

func TestLoadEnvironment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dev.yaml")
	body := "base_url: \"http://localhost:8080\"\nid: 42\nflag: true\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	vars, err := LoadEnvironment(path)
	if err != nil {
		t.Fatal(err)
	}
	if vars["base_url"] != "http://localhost:8080" || vars["id"] != "42" || vars["flag"] != "true" {
		t.Fatalf("vars = %#v", vars)
	}
}

func TestLoadEnvironmentRejectsNested(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("nested:\n  a: b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnvironment(path); err == nil {
		t.Fatal("expected error for a nested map")
	}
}

func TestDoSendsMethodHeadersQueryBodyAndAuth(t *testing.T) {
	var got struct {
		method, path, query, header, auth, body, ct string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.method = r.Method
		got.path = r.URL.Path
		got.query = r.URL.RawQuery
		got.header = r.Header.Get("X-Trace")
		got.auth = r.Header.Get("Authorization")
		got.ct = r.Header.Get("Content-Type")
		got.body = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	req := &Request{
		Method:  "POST",
		URL:     srv.URL + "/v1/items",
		Headers: map[string]string{"Content-Type": "application/json", "X-Trace": "t-1"},
		Query:   map[string]string{"expand": "true", "q": "a b"},
		Body:    []byte(`{"name":"x"}`),
		Auth:    &format.Auth{Type: format.AuthBearer, Token: "tok"},
	}
	resp, err := Do(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if string(resp.Body) != `{"ok":true}` {
		t.Fatalf("body = %q", resp.Body)
	}
	if got.method != "POST" || got.path != "/v1/items" {
		t.Fatalf("server saw %s %s", got.method, got.path)
	}
	if got.header != "t-1" || got.auth != "Bearer tok" {
		t.Fatalf("headers: trace=%q auth=%q", got.header, got.auth)
	}
	if got.body != `{"name":"x"}` || got.ct != "application/json" {
		t.Fatalf("body=%q ct=%q", got.body, got.ct)
	}
	if got.query != "expand=true&q=a+b" {
		t.Fatalf("query = %q", got.query)
	}
}

func TestAPIKeyInQuery(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Query().Get("key")
	}))
	defer srv.Close()

	req := &Request{
		Method: "GET",
		URL:    srv.URL,
		Auth:   &format.Auth{Type: format.AuthAPIKey, In: "query", Name: "key", Value: "k1"},
	}
	if _, err := Do(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if seen != "k1" {
		t.Fatalf("api key not sent, got %q", seen)
	}
}

func TestBasicAuth(t *testing.T) {
	var user, pass string
	var ok bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok = r.BasicAuth()
	}))
	defer srv.Close()

	req := &Request{
		Method: "GET",
		URL:    srv.URL,
		Auth:   &format.Auth{Type: format.AuthBasic, Username: "u", Password: "p"},
	}
	if _, err := Do(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if !ok || user != "u" || pass != "p" {
		t.Fatalf("basic auth = %q/%q ok=%v", user, pass, ok)
	}
}

func TestNoRedirectsWhenDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/from" {
			http.Redirect(w, r, "/to", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "final")
	}))
	defer srv.Close()

	resp, err := Do(context.Background(), &Request{Method: "GET", URL: srv.URL + "/from", FollowRedirects: false})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}

	resp, err = Do(context.Background(), &Request{Method: "GET", URL: srv.URL + "/from", FollowRedirects: true})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(resp.Body) != "final" {
		t.Fatalf("followed redirect gave %d %q", resp.StatusCode, resp.Body)
	}
}

func TestResponseBodyIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 4096))
	}))
	defer srv.Close()

	resp, err := Do(context.Background(), &Request{Method: "GET", URL: srv.URL}, WithMaxBodyBytes(1024))
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Truncated {
		t.Fatal("expected truncation flag")
	}
	if len(resp.Body) != 1024 {
		t.Fatalf("len = %d, want 1024", len(resp.Body))
	}
}

func TestTimeoutIsHonoured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer srv.Close()

	start := time.Now()
	_, err := Do(context.Background(), &Request{Method: "GET", URL: srv.URL, Timeout: 50 * time.Millisecond})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("timeout took %s", elapsed)
	}
}

func TestFromFileResolvesEverything(t *testing.T) {
	src := `format: 1
name: X
method: POST
url: "{{base_url}}/pets/{{id}}"
headers:
  Content-Type: application/json
query:
  q: "{{term}}"
auth:
  type: bearer
  token: "{{token}}"
---
{"name":"{{pet}}"}
`
	f, _, err := format.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"base_url": "http://h:1", "id": "7", "term": "cat", "token": "t", "pet": "rex"}
	req, err := FromFile(f, vars)
	if err != nil {
		t.Fatal(err)
	}
	if req.URL != "http://h:1/pets/7" || req.Query["q"] != "cat" {
		t.Fatalf("req = %+v", req)
	}
	if req.Auth.Token != "t" {
		t.Fatalf("token = %q", req.Auth.Token)
	}
	if string(req.Body) != "{\"name\":\"rex\"}\n" {
		t.Fatalf("body = %q", req.Body)
	}
}

func TestFromFileNamesMissingVariable(t *testing.T) {
	src := "format: 1\nname: X\nmethod: GET\nurl: \"{{base_url}}/x\"\n---\n"
	f, _, err := format.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	_, err = FromFile(f, map[string]string{})
	if err == nil || !strings.Contains(err.Error(), "base_url") {
		t.Fatalf("err = %v, want it to name base_url", err)
	}
}

func TestIsLoopback(t *testing.T) {
	cases := map[string]bool{
		"http://localhost:8080/x": true,
		"http://127.0.0.1/x":      true,
		"http://[::1]:9000/x":     true,
		"https://api.example.com": false,
		"not a url":               false,
	}
	for in, want := range cases {
		if got := IsLoopback(in); got != want {
			t.Errorf("IsLoopback(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestLocalOnlyStopsAtRemoteRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/elsewhere", http.StatusFound)
	}))
	defer srv.Close()

	req := &Request{Method: "GET", URL: srv.URL + "/", Timeout: 5 * time.Second, FollowRedirects: true}
	resp, err := Do(context.Background(), req, WithLocalOnly())
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected to stop at the 302, got %d", resp.StatusCode)
	}
}

func TestLocalOnlyFollowsLoopbackRedirect(t *testing.T) {
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("arrived"))
	}))
	defer dest.Close()

	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL, http.StatusFound)
	}))
	defer src.Close()

	req := &Request{Method: "GET", URL: src.URL + "/", Timeout: 5 * time.Second, FollowRedirects: true}
	resp, err := Do(context.Background(), req, WithLocalOnly())
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != http.StatusOK || string(resp.Body) != "arrived" {
		t.Fatalf("loopback redirect should be followed: status=%d body=%q", resp.StatusCode, resp.Body)
	}
}

func TestHostOverrideReachesTheWire(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Host
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	if _, err := Do(context.Background(), &Request{Method: "GET", URL: srv.URL, Host: "virtual.example"}); err != nil {
		t.Fatal(err)
	}
	if got != "virtual.example" {
		t.Fatalf("server saw Host %q, want virtual.example", got)
	}
}

func TestLocalOnlyTransportDisablesProxy(t *testing.T) {
	if tr := sharedTransport(false, 2, true); tr.Proxy != nil {
		t.Fatal("local-only transport must not use an environment proxy")
	}
	if tr := sharedTransport(false, 2, false); tr.Proxy == nil {
		t.Fatal("normal transport should still honour the environment proxy")
	}
}
