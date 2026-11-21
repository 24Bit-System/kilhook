package spec

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/24Bit-System/kilhook/internal/diff"
)

// MaxBaselineBytes bounds the baseline read. Baselines are written by
// SaveBaseline, but the path comes from a .kh file that may be shared, so a
// corrupt or hostile file must not be able to exhaust memory.
const MaxBaselineBytes = 16 << 20

// Drift is one difference between a stored baseline response and the current
// one. Only structural changes are reported: a value change is a diff, a shape
// change is drift.
type Drift struct {
	Path   string `json:"path"`
	Change string `json:"change"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

// Compare reports shape drift between a baseline and the current response.
func Compare(baseline, current []byte) ([]Drift, error) {
	changes, err := diff.JSON(baseline, current)
	if err != nil {
		return nil, err
	}
	return CompareChanges(changes), nil
}

// CompareChanges filters an already computed diff down to the structural
// changes. The engine diffs the two bodies once and feeds both the report and
// the drift check from the same result instead of decoding each side twice.
func CompareChanges(changes []diff.Change) []Drift {
	var out []Drift
	for _, c := range changes {
		switch c.Kind {
		case diff.Added, diff.Removed, diff.TypeChanged:
			out = append(out, Drift{Path: c.Path, Change: c.Kind, Before: c.Before, After: c.After})
		}
	}
	return out
}

// LoadBaseline reads a stored last-known-good response.
func LoadBaseline(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxBaselineBytes+1))
	if err != nil {
		return nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	if len(data) > MaxBaselineBytes {
		return nil, fmt.Errorf("baseline %s: exceeds the %d byte limit", path, MaxBaselineBytes)
	}
	return data, nil
}

// SaveBaseline writes a response as the new last-known-good baseline. The body
// lands in a temp file in the destination directory and is renamed into place,
// so a crash mid-write cannot leave a truncated baseline that fails the next
// run with "baseline is not JSON" (the same discipline SaveDocument uses).
func SaveBaseline(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("baseline %s: %w", path, err)
	}
	tmp, err := os.CreateTemp(dir, ".baseline-*")
	if err != nil {
		return fmt.Errorf("baseline %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeded
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return fmt.Errorf("baseline %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("baseline %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("baseline %s: %w", path, err)
	}
	return nil
}
