package format

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Marshal renders the file back to .kh bytes: canonical two-space YAML, the
// "---" separator, then the body exactly as it was read. UI edits go through
// here; fuzz mutations never do (they are applied in memory only).
func (f *File) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(f); err != nil {
		return nil, fmt.Errorf("encode frontmatter: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("encode frontmatter: %w", err)
	}

	var out bytes.Buffer
	out.Write(buf.Bytes())
	out.WriteString("---\n")
	out.Write(f.Body)
	return out.Bytes(), nil
}
