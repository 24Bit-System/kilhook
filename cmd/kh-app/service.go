package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/24Bit-System/kilhook/internal/engine"
	"github.com/24Bit-System/kilhook/internal/report"
)

// Progress is emitted on "run:progress" while a run is in flight.
type Progress struct {
	Phase string `json:"phase"`
}

// Result is what the window receives after a run. The frontend renders JSON
// through the same report model the CLI and the HTML export use.
type Result struct {
	JSON string `json:"json"`
	HTML string `json:"html"`
}

// Workspace is the bound service: everything the UI can ask the engine to do.
type Workspace struct {
	mu           sync.Mutex
	cancel       context.CancelFunc
	roots        map[string]bool
	lastSavePath string
}

// NewWorkspace returns the service instance bound to the app.
func NewWorkspace() *Workspace { return &Workspace{} }

// registerRoot records a folder the user has explicitly opened, so Create/Save
// (which take frontend-supplied paths) can be confined to it.
func (w *Workspace) registerRoot(dir string) {
	if strings.TrimSpace(dir) == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.roots == nil {
		w.roots = make(map[string]bool)
	}
	// Store the real (cleaned) path, not a lowercased one: engine.WithinDir
	// resolves symlinks below and needs a path the filesystem recognises.
	w.roots[filepath.Clean(dir)] = true
}

// hasRoot reports whether dir is one of the folders the user explicitly
// opened. Windows paths are case-insensitive, so compare without case.
func hasRoot(roots map[string]bool, dir string) bool {
	clean := filepath.Clean(dir)
	for root := range roots {
		if strings.EqualFold(root, clean) {
			return true
		}
	}
	return false
}

func normalizePath(p string) string {
	return strings.ToLower(filepath.Clean(p))
}

// Version returns the product version for the title bar.
func (w *Workspace) Version() string { return report.Version }

// Home picks the folder the window opens on: the working directory, or the
// first of the conventional request folders that actually contains a .kh file.
// Opening on an empty folder is technically correct and practically useless.
func (w *Workspace) Home() string {
	dir, err := os.Getwd()
	if err != nil || !usableWorkspace(dir) {
		if home, homeErr := os.UserHomeDir(); homeErr == nil {
			dir = home
		}
	}
	for _, candidate := range []string{
		dir,
		filepath.Join(dir, "requests"),
		filepath.Join(dir, "testdata", "requests"),
	} {
		if files, err := engine.Discover(candidate); err == nil && len(files) > 0 {
			w.registerRoot(candidate)
			return candidate
		}
	}
	w.registerRoot(dir)
	return dir
}

// usableWorkspace rejects the directories a packaged app starts in: an MSIX
// launch runs with the working directory set to System32, and offering that as
// a workspace is wrong even before the user types anything.
func usableWorkspace(dir string) bool {
	if dir == "" {
		return false
	}
	lower := strings.ToLower(filepath.Clean(dir))
	for _, bad := range []string{
		os.Getenv("SystemRoot"),
		os.Getenv("ProgramFiles"),
		os.Getenv("ProgramFiles(x86)"),
		os.Getenv("ProgramData"),
	} {
		if bad == "" {
			continue
		}
		bad = strings.ToLower(filepath.Clean(bad))
		if lower == bad || strings.HasPrefix(lower, bad+string(os.PathSeparator)) {
			return false
		}
	}
	return true
}

// Environments lists the environment names available next to a workspace: the
// .kilhook/env/*.yaml files a user can select without typing a name from memory.
func (w *Workspace) Environments(dir string) ([]string, error) {
	if dir == "" {
		dir = w.Home()
	}
	entries, err := os.ReadDir(filepath.Join(dir, ".kilhook", "env"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	names := make([]string, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		for _, ext := range []string{".yaml", ".yml"} {
			if strings.EqualFold(filepath.Ext(e.Name()), ext) {
				name := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
				if !seen[name] {
					seen[name] = true
					names = append(names, name)
				}
				break
			}
		}
	}
	sort.Strings(names)
	return names, nil
}

// ChooseFolder opens the native folder picker and returns the selected path.
// It returns "" when the user cancels, which the frontend treats as "no change".
func (w *Workspace) ChooseFolder() (string, error) {
	app := application.Get()
	if app == nil {
		return "", errors.New("no application instance")
	}
	res, err := dialogResult(app.Dialog.OpenFile().
		SetTitle("Choose a workspace folder").
		CanChooseFiles(false).
		CanChooseDirectories(true).
		PromptForSingleSelection())
	if err == nil && res != "" {
		w.registerRoot(res)
	}
	return res, err
}

// dialogResult maps the native picker's outcome. Cancelling is a normal result,
// not a failure: the dialog returns "cancelled by user" and the window should stay
// exactly as it was, without an error bar.
func dialogResult(chosen string, err error) (string, error) {
	if err == nil {
		return chosen, nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "cancel") {
		return "", nil
	}
	return "", err
}

// ChooseSavePath opens the native save dialog for the HTML report and returns
// the chosen path. Cancelling returns "", which the frontend treats as "do
// nothing" — the same contract ChooseFolder has.
func (w *Workspace) ChooseSavePath(defaultName string) (string, error) {
	app := application.Get()
	if app == nil {
		return "", errors.New("no application instance")
	}
	if strings.TrimSpace(defaultName) == "" {
		defaultName = "kilhook-report.html"
	}
	res, err := dialogResult(app.Dialog.SaveFile().
		SetMessage("Save the HTML report").
		SetFilename(defaultName).
		AddFilter("HTML report", ".html").
		PromptForSingleSelection())
	if err == nil && res != "" {
		w.mu.Lock()
		w.lastSavePath = normalizePath(res)
		w.mu.Unlock()
	}
	return res, err
}

// newRequestTemplate is the starter file Create writes. It must always parse:
// the point of the button is that a first request exists without hand-editing
// YAML.
const newRequestTemplate = `format: 1
name: New Request
method: GET
url: "http://localhost:8080/"
headers:
  Accept: application/json
---
`

// Create writes a starter .kh file into dir and returns its path. It never
// overwrites: later calls produce new-request-2.kh, new-request-3.kh and so on.
func (w *Workspace) Create(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", errors.New("no workspace folder")
	}
	w.mu.Lock()
	roots := make(map[string]bool, len(w.roots))
	for k, v := range w.roots {
		roots[k] = v
	}
	w.mu.Unlock()
	// hasRoot alone compares case-insensitively (Windows convention). On a
	// case-sensitive filesystem that would authorise writing to a different,
	// unregistered directory with the same name in different case.
	if !hasRoot(roots, dir) || !withinRegisteredRoot(roots, dir) {
		return "", errors.New("workspace folder is not registered")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	for i := 1; i < 1000; i++ {
		name := "new-request.kh"
		if i > 1 {
			name = fmt.Sprintf("new-request-%d.kh", i)
		}
		candidate := filepath.Join(dir, name)
		// O_EXCL makes claim-and-create atomic, so two windows pointed at the
		// same folder can never both write new-request.kh.
		f, err := os.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if _, err := f.WriteString(newRequestTemplate); err != nil {
			f.Close()
			os.Remove(candidate)
			return "", err
		}
		if err := f.Close(); err != nil {
			os.Remove(candidate)
			return "", err
		}
		return candidate, nil
	}
	return "", fmt.Errorf("no free new-request*.kh name in %s", dir)
}

// Discover lists the .kh files in a folder.
func (w *Workspace) Discover(dir string) ([]engine.Workfile, error) {
	if dir == "" {
		dir = w.Home()
	}
	w.registerRoot(dir)
	return engine.Discover(dir)
}

func (w *Workspace) isRegistered(path string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return withinRegisteredRoot(w.roots, path)
}

// Run executes the full loop for one file and returns the rendered report.
func (w *Workspace) Run(file string, opts engine.Options) (Result, error) {
	if !w.isRegistered(file) {
		return Result{}, errors.New("request file is outside the workspace")
	}
	w.mu.Lock()
	if w.cancel != nil {
		w.mu.Unlock()
		return Result{}, errors.New("a run is already in progress")
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.mu.Unlock()

	defer func() {
		w.mu.Lock()
		w.cancel = nil
		w.mu.Unlock()
		cancel()
	}()

	emit := application.Get()
	logf := func(format string, args ...any) {
		if emit == nil {
			return
		}
		progress := Progress{Phase: fmt.Sprintf(format, args...)}
		emit.Event.Emit("run:progress", progress)
	}

	rep, err := engine.Run(ctx, file, opts, func(format string, args ...any) {
		logf(format, args...)
	})
	if err != nil {
		return Result{}, err
	}

	data, err := rep.JSON()
	if err != nil {
		return Result{}, err
	}
	html, err := rep.HTML()
	if err != nil {
		return Result{}, err
	}
	res := Result{JSON: string(data), HTML: string(html)}
	return res, nil
}

// Cancel aborts an in-flight run (fuzz workers stop between requests).
func (w *Workspace) Cancel() {
	w.mu.Lock()
	cancel := w.cancel
	w.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// SaveHTML writes the last run's report to disk and returns the absolute path.
func (w *Workspace) SaveHTML(html, out string) (string, error) {
	if html == "" {
		return "", errors.New("no report to save yet")
	}
	if out == "" {
		return "", errors.New("no output path")
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(filepath.Ext(abs), ".html") {
		return "", errors.New("output path must end in .html")
	}
	w.mu.Lock()
	expected := w.lastSavePath
	w.mu.Unlock()
	if expected == "" || normalizePath(abs) != expected {
		return "", errors.New("output path does not match the chosen save location")
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return "", err
	}
	// Write to a temp file and rename: os.WriteFile follows an existing
	// symlink, which would let a swapped path divert the report elsewhere
	// between the dialog check and the write. Rename replaces the link itself.
	tmp, err := os.CreateTemp(filepath.Dir(abs), ".report-*.tmp")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return "", err
	}
	if _, err := tmp.WriteString(html); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, abs); err != nil {
		return "", err
	}
	return abs, nil
}

// Open loads a .kh file into the editor shape.
func (w *Workspace) Open(path string) (engine.Document, error) {
	if path == "" {
		return engine.Document{}, errors.New("no file selected")
	}
	if !w.isRegistered(path) {
		return engine.Document{}, errors.New("request file is outside the workspace")
	}
	doc, err := engine.LoadDocument(path)
	if err != nil {
		return engine.Document{}, err
	}
	return *doc, nil
}

// Modified returns the file's modification time in Unix nanoseconds, as a
// string because a JavaScript number cannot hold nanoseconds exactly. The
// window polls it to notice when the selected file is edited behind its back.
func (w *Workspace) Modified(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("no file selected")
	}
	if !w.isRegistered(path) {
		return "", errors.New("request file is outside the workspace")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(info.ModTime().UnixNano(), 10), nil
}

// Save writes the editor's document back to disk and returns the canonical
// reload, so the form shows exactly what the file now contains.
func (w *Workspace) Save(doc engine.Document) (engine.Document, error) {
	w.mu.Lock()
	running := w.cancel != nil
	roots := make(map[string]bool, len(w.roots))
	for k, v := range w.roots {
		roots[k] = v
	}
	w.mu.Unlock()
	if running {
		return engine.Document{}, errors.New("a run is in progress — stop it before saving")
	}
	if !strings.EqualFold(filepath.Ext(doc.Path), ".kh") {
		return engine.Document{}, errors.New("save target must be a .kh file")
	}
	if !withinRegisteredRoot(roots, doc.Path) {
		return engine.Document{}, errors.New("save target is outside the workspace")
	}
	saved, err := engine.SaveDocument(doc)
	if err != nil {
		return engine.Document{}, err
	}
	return *saved, nil
}

func withinRegisteredRoot(roots map[string]bool, path string) bool {
	p := filepath.Clean(path)
	for root := range roots {
		// Use the engine's symlink-aware check so a junction or symlink placed
		// inside a workspace cannot point Open/Run/Save at a file outside it.
		if engine.WithinDir(root, p) {
			return true
		}
	}
	return false
}
