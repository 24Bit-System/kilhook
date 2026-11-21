package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/24Bit-System/kilhook/internal/format"
	httpreq "github.com/24Bit-System/kilhook/internal/http"
	"github.com/24Bit-System/kilhook/internal/spec"
)

const unitSpec = `openapi: 3.0.3
info: {title: Units, version: "1"}
paths:
  /pets/{id}:
    get:
      responses:
        "200": {description: ok}
    delete:
      responses:
        "204": {description: gone}
  /pets:
    get:
      responses:
        "200": {description: ok}
`

func writeUnitSpec(t *testing.T, dir string) *spec.Document {
	t.Helper()
	path := filepath.Join(dir, "spec.yaml")
	if err := os.WriteFile(path, []byte(unitSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := spec.Load(path)
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	return doc
}

func TestParseOperationHint(t *testing.T) {
	cases := []struct {
		hint    string
		path    string
		method  string
		wantErr string
	}{
		{hint: "/pets/{id} get", path: "/pets/{id}", method: "get"},
		{hint: "/pets DELETE", path: "/pets", method: "delete"},
		{hint: "/pets", wantErr: "must look like"},
		{hint: "", wantErr: "must look like"},
		{hint: "a b c", wantErr: "must look like"},
	}
	for _, tc := range cases {
		path, method, err := parseOperationHint(tc.hint)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("%q: want error containing %q, got %v", tc.hint, tc.wantErr, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: unexpected error %v", tc.hint, err)
		}
		if path != tc.path || method != tc.method {
			t.Fatalf("%q: got (%q, %q), want (%q, %q)", tc.hint, path, method, tc.path, tc.method)
		}
	}
}

func TestMatchSpecOperationUsesTheHint(t *testing.T) {
	dir := t.TempDir()
	doc := writeUnitSpec(t, dir)
	file := &format.File{Spec: &format.Spec{Operation: "/pets/{id} get"}}
	req := &httpreq.Request{Method: "GET", URL: "https://example.test/pets/7"}

	match, err := matchSpecOperation(doc, file, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match.SpecPath != "/pets/{id}" || match.Method != "get" || match.Op == nil {
		t.Fatalf("unexpected match: %+v", match)
	}
}

func TestMatchSpecOperationRejectsBadHints(t *testing.T) {
	dir := t.TempDir()
	doc := writeUnitSpec(t, dir)
	req := &httpreq.Request{Method: "GET", URL: "https://example.test/pets/7"}

	cases := []struct {
		operation string
		want      string
	}{
		{operation: "/pets", want: "must look like"},
		{operation: "/missing/{id} get", want: "is not declared"},
		{operation: "/pets/{id} post", want: "is not declared"},
	}
	for _, tc := range cases {
		file := &format.File{Spec: &format.Spec{Operation: tc.operation}}
		if _, err := matchSpecOperation(doc, file, req); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%q: want error containing %q, got %v", tc.operation, tc.want, err)
		}
	}
}

func TestMatchSpecOperationWithoutHintMatchesTheURL(t *testing.T) {
	dir := t.TempDir()
	doc := writeUnitSpec(t, dir)
	req := &httpreq.Request{Method: "GET", URL: "https://example.test/pets/7"}

	match, err := matchSpecOperation(doc, &format.File{}, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match.SpecPath != "/pets/{id}" {
		t.Fatalf("want /pets/{id}, got %q", match.SpecPath)
	}
}

func TestBaselinePathFor(t *testing.T) {
	dir := t.TempDir()

	// 1. --baseline wins and may point anywhere.
	got, err := baselinePathFor("req.kh", dir, &format.File{}, Options{Baseline: "/elsewhere/b.json"})
	if err != nil || got != "/elsewhere/b.json" {
		t.Fatalf("explicit baseline: got (%q, %v)", got, err)
	}

	// 2. A file baseline inside the workspace is used.
	file := &format.File{Name: "Pets", Spec: &format.Spec{Baseline: ".kilhook/last.json"}}
	got, err = baselinePathFor("req.kh", dir, file, Options{})
	if err != nil {
		t.Fatalf("file baseline: %v", err)
	}
	if want := filepath.Join(dir, ".kilhook", "last.json"); got != want {
		t.Fatalf("file baseline: got %q, want %q", got, want)
	}

	// 3. A file baseline outside the workspace is refused.
	file = &format.File{Name: "Pets", Spec: &format.Spec{Baseline: "../escape.json"}}
	if _, err = baselinePathFor("req.kh", dir, file, Options{}); err == nil || !strings.Contains(err.Error(), "leaves the workspace") {
		t.Fatalf("escaping baseline: want refusal, got %v", err)
	}

	// 4. Without a baseline, --update-baseline creates the default path.
	got, err = baselinePathFor(filepath.Join(dir, "req.kh"), dir, &format.File{Name: "Pets"}, Options{UpdateBaseline: true})
	if err != nil {
		t.Fatalf("default baseline: %v", err)
	}
	if want := filepath.Join(dir, ".kilhook", "baselines", "pets.json"); got != want {
		t.Fatalf("default baseline: got %q, want %q", got, want)
	}

	// 5. A read-only run stays quiet until that default file exists.
	got, err = baselinePathFor(filepath.Join(dir, "req.kh"), dir, &format.File{Name: "Pets"}, Options{})
	if err != nil || got != "" {
		t.Fatalf("missing default: got (%q, %v)", got, err)
	}
	if err = os.MkdirAll(filepath.Join(dir, ".kilhook", "baselines"), 0o755); err != nil {
		t.Fatal(err)
	}
	def := filepath.Join(dir, ".kilhook", "baselines", "pets.json")
	if err = os.WriteFile(def, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = baselinePathFor(filepath.Join(dir, "req.kh"), dir, &format.File{Name: "Pets"}, Options{})
	if err != nil || got != def {
		t.Fatalf("existing default: got (%q, %v), want %q", got, err, def)
	}

	// 6. A name with nothing sluggable falls back to the file name, then errors.
	got, err = baselinePathFor(filepath.Join(dir, "my-req.kh"), dir, &format.File{Name: "***"}, Options{UpdateBaseline: true})
	if err != nil || !strings.HasSuffix(got, "my-req.json") {
		t.Fatalf("file-name fallback: got (%q, %v)", got, err)
	}
	if _, err = baselinePathFor(filepath.Join(dir, "***.kh"), dir, &format.File{Name: "***"}, Options{UpdateBaseline: true}); err == nil {
		t.Fatal("want an error when no name can be derived")
	}
}

func TestLoadVars(t *testing.T) {
	dir := t.TempDir()
	envDir := filepath.Join(dir, ".kilhook", "env")
	if err := os.MkdirAll(envDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(envDir, "dev.yaml"), []byte("base_url: http://localhost:9\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// No env selected: empty map, no error.
	vars, err := loadVars(filepath.Join(dir, "req.kh"), Options{})
	if err != nil || len(vars) != 0 {
		t.Fatalf("no env: got (%v, %v)", vars, err)
	}

	// Env name resolves next to the request file.
	vars, err = loadVars(filepath.Join(dir, "req.kh"), Options{EnvName: "dev"})
	if err != nil || vars["base_url"] != "http://localhost:9" {
		t.Fatalf("env name: got (%v, %v)", vars, err)
	}

	// A missing env file is an error, not a silent empty map.
	if _, err = loadVars(filepath.Join(dir, "req.kh"), Options{EnvName: "nope"}); err == nil {
		t.Fatal("missing env file should error")
	}

	// An explicit env file wins over the name.
	explicit := filepath.Join(dir, "custom.yaml")
	if err = os.WriteFile(explicit, []byte("base_url: http://localhost:10\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	vars, err = loadVars(filepath.Join(dir, "req.kh"), Options{EnvName: "dev", EnvFile: explicit})
	if err != nil || vars["base_url"] != "http://localhost:10" {
		t.Fatalf("env file: got (%v, %v)", vars, err)
	}
}

func TestWithinDirAndResolvePath(t *testing.T) {
	dir := filepath.Join("C:", "work", "ws")
	cases := []struct {
		path string
		want bool
	}{
		{path: filepath.Join(dir, "a.json"), want: true},
		{path: filepath.Join(dir, "sub", "a.json"), want: true},
		{path: filepath.Join(dir, "..", "a.json"), want: false},
		{path: filepath.Join("C:", "elsewhere", "a.json"), want: false},
	}
	for _, tc := range cases {
		if got := withinDir(dir, tc.path); got != tc.want {
			t.Fatalf("withinDir(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}

	if got := resolvePath(dir, "x/y.json"); got != filepath.Join(dir, "x", "y.json") {
		t.Fatalf("relative resolve: got %q", got)
	}
	if !WithinDir(dir, filepath.Join(dir, "a", "b.json")) {
		t.Fatal("the exported bridge helper must agree with withinDir")
	}
	if WithinDir(dir, filepath.Join(filepath.Dir(dir), "outside.json")) {
		t.Fatal("the exported bridge helper must reject paths outside the workspace")
	}
	if got := resolvePath(dir, ""); got != "" {
		t.Fatalf("empty resolve: got %q", got)
	}
	abs := filepath.Join(t.TempDir(), "a.json")
	if got := resolvePath(dir, abs); got != abs {
		t.Fatalf("absolute resolve: got %q", got)
	}
}

func TestPreviewTruncates(t *testing.T) {
	if got := preview([]byte("abc\n"), 10); got != "abc" {
		t.Fatalf("short body: got %q", got)
	}
	got := preview([]byte("0123456789abcdef"), 5)
	if !strings.HasPrefix(got, "01234") || !strings.HasSuffix(got, "…") {
		t.Fatalf("long body: got %q", got)
	}
}

func TestFirstNonZero(t *testing.T) {
	if got := firstNonZero(0, 2.5); got != 2.5 {
		t.Fatalf("float fallback: got %v", got)
	}
	if got := firstNonZero(1.5, 2.5); got != 1.5 {
		t.Fatalf("float primary: got %v", got)
	}
	if got := firstNonZeroInt(0, 7); got != 7 {
		t.Fatalf("int fallback: got %v", got)
	}
	if got := firstNonZeroInt(3, 7); got != 3 {
		t.Fatalf("int primary: got %v", got)
	}
}

func TestSlugifyAndDiscover(t *testing.T) {
	if got := slugify("Login v2!"); got != "login-v2" {
		t.Fatalf("slugify: got %q", got)
	}
	if got := slugify("***"); got != "" {
		t.Fatalf("slugify with no usable runes: got %q", got)
	}

	dir := t.TempDir()
	if _, err := Discover(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("Discover on a missing folder should error")
	}
	if _, err := Discover("  "); err == nil || !strings.Contains(err.Error(), "no workspace folder") {
		t.Fatalf("Discover(\"  \") should explain the missing folder, got %v", err)
	}
}
