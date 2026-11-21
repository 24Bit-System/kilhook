package http

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEnvironmentIsBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.yaml")
	// One byte over the cap is enough to prove the limit is enforced.
	data := "k: " + strings.Repeat("a", MaxEnvBytes) + "\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnvironment(path); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("err = %v, want the byte-limit error", err)
	}
}

func TestLoadEnvironmentStillReadsNormalFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dev.yaml")
	if err := os.WriteFile(path, []byte("base_url: http://localhost:8080\nuser: dev\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	vars, err := LoadEnvironment(path)
	if err != nil {
		t.Fatal(err)
	}
	if vars["base_url"] != "http://localhost:8080" || vars["user"] != "dev" {
		t.Fatalf("vars = %+v", vars)
	}
}
