package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverRefusesSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	valid := "format: 1\nname: Outside\nmethod: GET\nurl: http://localhost:1/\n---\n"
	outsidePath := filepath.Join(outside, "outside.kh")
	if err := os.WriteFile(outsidePath, []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.kh")
	if err := os.Symlink(outsidePath, link); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}

	files, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want the single link entry", len(files))
	}
	if files[0].Error == "" || !strings.Contains(files[0].Error, "outside the workspace") {
		t.Fatalf("escaping symlink should be flagged, got %+v", files[0])
	}
	if files[0].Name != "link.kh" {
		t.Fatalf("name = %q", files[0].Name)
	}
}
