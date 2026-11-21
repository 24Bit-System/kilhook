package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/24Bit-System/kilhook/internal/engine"
)

func TestUsableWorkspaceRejectsSystemDirectories(t *testing.T) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		t.Skip("no SystemRoot on this platform")
	}
	for _, dir := range []string{
		root,
		filepath.Join(root, "System32"),
		filepath.Join(root, "System32", "drivers"),
	} {
		if usableWorkspace(dir) {
			t.Fatalf("%q should not be offered as a workspace", dir)
		}
	}
}

func TestUsableWorkspaceAcceptsProjectDirectories(t *testing.T) {
	dir := t.TempDir()
	if !usableWorkspace(dir) {
		t.Fatalf("%q should be a usable workspace", dir)
	}
}

func TestCreateRequiresRegisteredRoot(t *testing.T) {
	w := NewWorkspace()
	dir := t.TempDir()
	if _, err := w.Create(dir); err == nil {
		t.Fatal("Create must refuse an unregistered folder")
	}
	if _, err := w.Discover(dir); err != nil {
		t.Fatal(err)
	}
	path, err := w.Create(dir)
	if err != nil {
		t.Fatalf("Create after Discover: %v", err)
	}
	if !strings.HasSuffix(path, ".kh") {
		t.Fatalf("path = %q", path)
	}
}

func TestSaveRequiresKhExtensionAndRegisteredRoot(t *testing.T) {
	w := NewWorkspace()
	dir := t.TempDir()
	if _, err := w.Discover(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Save(engine.Document{Path: filepath.Join(dir, "x.txt")}); err == nil {
		t.Fatal("Save must reject a non-.kh path")
	}
	if _, err := w.Save(engine.Document{Path: filepath.Join(t.TempDir(), "x.kh")}); err == nil {
		t.Fatal("Save must reject a path outside the registered root")
	}
}

func TestSaveHTMLRequiresChosenPath(t *testing.T) {
	w := NewWorkspace()
	dir := t.TempDir()
	if _, err := w.SaveHTML("<html/>", filepath.Join(dir, "r.html")); err == nil {
		t.Fatal("SaveHTML must refuse a path the user never chose")
	}
}
func TestDialogResultTreatsCancelAsNoChange(t *testing.T) {
	got, err := dialogResult("", errors.New("cancelled by user"))
	if err != nil || got != "" {
		t.Fatalf("cancel should be a no-op, got %q, %v", got, err)
	}

	got, err = dialogResult(`C:\workspaces\example`, nil)
	if err != nil || got != `C:\workspaces\example` {
		t.Fatalf("selection should pass through, got %q, %v", got, err)
	}

	if _, err = dialogResult("", errors.New("com failure")); err == nil {
		t.Fatal("a real dialog error must not be swallowed")
	}
}

func TestCreateMakesUniqueParseableFiles(t *testing.T) {
	w := NewWorkspace()
	dir := t.TempDir()
	if _, err := w.Discover(dir); err != nil {
		t.Fatal(err)
	}
	first, err := w.Create(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := w.Create(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("Create reused a name: %s", first)
	}
	if filepath.Base(first) != "new-request.kh" || filepath.Base(second) != "new-request-2.kh" {
		t.Fatalf("unexpected names: %s, %s", first, second)
	}
	doc, err := engine.LoadDocument(first)
	if err != nil {
		t.Fatalf("the created file does not parse: %v", err)
	}
	if doc.Name != "New Request" || doc.Method != "GET" {
		t.Fatalf("unexpected document: %+v", doc)
	}
	if _, err := w.Create(""); err == nil {
		t.Fatal("Create without a folder must fail")
	}
}

func TestModifiedTracksWrites(t *testing.T) {
	w := NewWorkspace()
	dir := t.TempDir()
	if _, err := w.Discover(dir); err != nil {
		t.Fatal(err)
	}
	path, err := w.Create(dir)
	if err != nil {
		t.Fatal(err)
	}
	before, err := w.Modified(path)
	if err != nil {
		t.Fatal(err)
	}
	// Sleep so even a filesystem with coarse mtime resolution sees a change.
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(path, []byte("format: 1\nname: X\nmethod: GET\nurl: \"http://x/\"\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := w.Modified(path)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("Modified did not notice the write")
	}
	if _, err := w.Modified(filepath.Join(dir, "missing.kh")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
	if _, err := w.Modified(""); err == nil {
		t.Fatal("expected an error for an empty path")
	}
}

func TestWorkspaceRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	doc := []byte("format: 1\nname: X\nmethod: GET\nurl: http://localhost:1/\n---\n")
	outsidePath := filepath.Join(outside, "secret.kh")
	if err := os.WriteFile(outsidePath, doc, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.kh")
	if err := os.Symlink(outsidePath, link); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	w := NewWorkspace()
	if _, err := w.Discover(root); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Open(link); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("Open through a symlink must be refused: %v", err)
	}
	if _, err := w.Run(link, engine.Options{}); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("Run through a symlink must be refused: %v", err)
	}
}

func TestFileOperationsRequireRegisteredRoot(t *testing.T) {
	w := NewWorkspace()
	root := t.TempDir()
	outside := t.TempDir()
	if _, err := w.Discover(root); err != nil {
		t.Fatal(err)
	}
	doc := []byte("format: 1\nname: X\nmethod: GET\nurl: http://localhost:1/\n---\n")
	outsidePath := filepath.Join(outside, "x.kh")
	if err := os.WriteFile(outsidePath, doc, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := w.Open(outsidePath); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("Open outside the root: %v", err)
	}
	if _, err := w.Modified(outsidePath); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("Modified outside the root: %v", err)
	}
	if _, err := w.Run(outsidePath, engine.Options{}); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("Run outside the root: %v", err)
	}

	inPath := filepath.Join(root, "x.kh")
	if err := os.WriteFile(inPath, doc, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Open(inPath); err != nil {
		t.Fatalf("Open inside the root: %v", err)
	}
	if _, err := w.Modified(inPath); err != nil {
		t.Fatalf("Modified inside the root: %v", err)
	}
}
