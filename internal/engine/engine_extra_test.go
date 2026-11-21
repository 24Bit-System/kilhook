package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/24Bit-System/kilhook/internal/format"
)

func TestRedactHeaders(t *testing.T) {
	in := map[string]string{
		"Authorization": "Bearer secret-token",
		"X-Api-Key":     "abc123",
		"Cookie":        "session=xyz",
		"Accept":        "application/json",
		"X-Trace-Id":    "trace-1",
	}
	out := redactHeaders(in)
	if out["Accept"] != "application/json" {
		t.Fatalf("Accept should survive: %v", out)
	}
	if out["X-Trace-Id"] != "trace-1" {
		t.Fatalf("X-Trace-Id should survive: %v", out)
	}
	for _, k := range []string{"Authorization", "X-Api-Key", "Cookie"} {
		if out[k] != "[redacted]" {
			t.Fatalf("%s should be redacted, got %q", k, out[k])
		}
	}
	if isSensitiveHeader("X-Custom-Token") != true {
		t.Fatal("token marker missed")
	}
	if isSensitiveHeader("Accept") {
		t.Fatal("Accept wrongly flagged")
	}
	if len(out) != len(in) {
		t.Fatalf("redactHeaders changed the key count: %d vs %d", len(out), len(in))
	}
}

func TestSlugifyNonASCIIAppendsHash(t *testing.T) {
	ascii := slugify("Login v2!")
	nonASCII := slugify("Café API")
	if !strings.Contains(nonASCII, "-") {
		t.Fatalf("non-ascii slug should keep a separator: %q", nonASCII)
	}
	if ascii == nonASCII {
		t.Fatal("ascii and non-ascii slugs must differ")
	}
	// ASCII slugs are unchanged (no hash appended).
	if slugify("Hello World") != "hello-world" {
		t.Fatalf("ascii slug changed: %q", slugify("Hello World"))
	}
	// Deterministic: same input -> same output.
	if slugify("Café API") != nonASCII {
		t.Fatal("slugify is not deterministic")
	}
}

func TestRunRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.kh")
	data := make([]byte, format.MaxFileBytes+1)
	for i := range data {
		data[i] = 'a'
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), path, Options{}, nil); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want an exceeds-limit error", err)
	}
}

func TestDiscoverSkipsOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.kh")
	data := make([]byte, format.MaxFileBytes+1)
	for i := range data {
		data[i] = 'a'
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	files, err := Discover(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	if files[0].Error == "" || !strings.Contains(files[0].Error, "over the") {
		t.Fatalf("oversized file should carry an error, got %+v", files[0])
	}
}
