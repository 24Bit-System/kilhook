package diff

import (
	"strconv"
	"strings"

	"github.com/sergi/go-diff/diffmatchpatch"
)

// Text compares two non-JSON bodies line by line and returns the changed lines.
func Text(before, after string) []Change {
	dmp := diffmatchpatch.New()
	chars1, chars2, lineArray := dmp.DiffLinesToChars(before, after)
	runes := dmp.DiffMain(chars1, chars2, false)
	runes = dmp.DiffCharsToLines(runes, lineArray)
	// The cleanup rebuilds the slice; the return value is the cleaned result.
	runes = dmp.DiffCleanupSemantic(runes)

	var out []Change
	line := 1
	for _, d := range runes {
		// Count and advance the line position for every chunk, including
		// blank ones: skipping them first would shift every later "line N"
		// (the only positional data a text change carries) by one.
		count := strings.Count(d.Text, "\n")
		if count == 0 {
			count = 1
		}
		text := strings.TrimSuffix(d.Text, "\n")
		switch d.Type {
		case diffmatchpatch.DiffEqual:
			line += count
		case diffmatchpatch.DiffDelete:
			if text != "" {
				out = append(out, Change{Path: "line " + strconv.Itoa(line), Kind: Removed, Before: text})
			}
			line += count
		case diffmatchpatch.DiffInsert:
			if text != "" {
				out = append(out, Change{Path: "line " + strconv.Itoa(line), Kind: Added, After: text})
			}
		}
	}
	return out
}
