package http

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// MaxEnvBytes bounds the environment file read. Env files are small; the cap
// only exists so a hostile workspace cannot make the app read a huge file when
// the user selects that environment.
const MaxEnvBytes = 1 << 20

// LoadEnvironment reads a YAML environment file (a flat map of names to
// scalar values) into a string map.
func LoadEnvironment(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("environment %s: %w", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxEnvBytes+1))
	if err != nil {
		return nil, fmt.Errorf("environment %s: %w", path, err)
	}
	if len(data) > MaxEnvBytes {
		return nil, fmt.Errorf("environment %s: exceeds the %d byte limit", path, MaxEnvBytes)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("environment %s: %w", path, err)
	}
	if raw == nil {
		return nil, fmt.Errorf("environment %s: file is empty", path)
	}
	vars := make(map[string]string, len(raw))
	for k, v := range raw {
		switch val := v.(type) {
		case string:
			vars[k] = val
		case int, int64, float64, bool:
			vars[k] = fmt.Sprint(val)
		case nil:
			vars[k] = ""
		default:
			return nil, fmt.Errorf("environment %s: %q must be a scalar, got %T", path, k, v)
		}
	}
	return vars, nil
}

// Interpolate replaces {{name}} placeholders. Every missing name is reported at
// once so a typo does not require a second run to find the next one.
func Interpolate(s string, vars map[string]string) (string, error) {
	var missing []string
	out := strings.Builder{}
	out.Grow(len(s))
	rest := s
	for {
		open := strings.Index(rest, "{{")
		if open < 0 {
			out.WriteString(rest)
			break
		}
		closeIdx := strings.Index(rest[open:], "}}")
		if closeIdx < 0 {
			out.WriteString(rest)
			break
		}
		closeIdx += open
		out.WriteString(rest[:open])
		name := strings.TrimSpace(rest[open+2 : closeIdx])
		val, ok := vars[name]
		if !ok {
			missing = append(missing, name)
			// Leave the placeholder intact so the message can be matched to
			// the source text.
			out.WriteString(rest[open : closeIdx+2])
		} else {
			out.WriteString(val)
		}
		rest = rest[closeIdx+2:]
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return "", fmt.Errorf("undefined variable(s): %s", strings.Join(dedupeStrings(missing), ", "))
	}
	return out.String(), nil
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// ParseURLPath returns just the path component of a URL, which is what OpenAPI
// operation matching compares against.
func ParseURLPath(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("url %q: %w", raw, err)
	}
	if u.Path == "" {
		return "/", nil
	}
	return u.Path, nil
}
