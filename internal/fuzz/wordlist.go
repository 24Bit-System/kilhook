package fuzz

import (
	"bufio"
	"embed"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

//go:embed wordlists/*.txt
var wordlists embed.FS

// Bounds for custom wordlists. A workspace may be cloned from somewhere else,
// so a wordlist is untrusted input: without these a multi-gigabyte file or a
// list of millions of lines could exhaust memory before the request cap is
// applied.
const (
	MaxWordlistBytes    = 5 << 20
	MaxWordlistPayloads = 200_000
	MaxMutations        = 1_000_000
)

// Payload is one input to inject, tagged with the fuzz method that produced it.
type Payload struct {
	Text   string
	Method string
	Typed  bool // injected as a JSON literal instead of a string
}

// Methods are the supported fuzz methods.
var Methods = []string{"injection", "boundary", "type_confusion"}

// ValidMethod reports whether m is a supported fuzz method.
func ValidMethod(m string) bool {
	for _, known := range Methods {
		if known == m {
			return true
		}
	}
	return false
}

// Bundled reports whether name selects one of the embedded wordlists rather
// than a file path. The empty name means the default list. Callers use this to
// decide whether a wordlist value is a path that must be resolved against the
// request file's directory.
func Bundled(name string) bool {
	return name == "" || strings.EqualFold(name, "default") || strings.EqualFold(name, "bundled")
}

// Payloads returns the payload list for a wordlist name ("default" or a file
// path) and the selected methods.
func Payloads(wordlist string, methods []string) ([]Payload, error) {
	if wordlist == "" {
		wordlist = "default"
	}
	if len(methods) == 0 {
		methods = []string{"injection"}
	}
	for _, m := range methods {
		if !ValidMethod(m) {
			return nil, fmt.Errorf("unknown fuzz method %q", m)
		}
	}

	if Bundled(wordlist) {
		// Build each method's list, then interleave them: a run capped below the
		// total payload count should still sample every method instead of
		// exhausting the first one.
		perMethod := make([][]Payload, 0, len(methods))
		seen := map[string]bool{}
		for _, m := range methods {
			lines, err := loadEmbedded(m)
			if err != nil {
				return nil, err
			}
			var list []Payload
			for _, line := range lines {
				for _, text := range expandTokens(line, m) {
					key := m + "\x00" + text
					if seen[key] {
						continue
					}
					seen[key] = true
					list = append(list, Payload{Text: text, Method: m, Typed: m == "type_confusion"})
				}
			}
			perMethod = append(perMethod, list)
		}
		return interleave(perMethod), nil
	}

	file, err := os.Open(wordlist)
	if err != nil {
		return nil, fmt.Errorf("wordlist %s: %w", wordlist, err)
	}
	defer file.Close()
	counted := &countingReader{r: io.LimitReader(file, MaxWordlistBytes+1)}
	var out []Payload
	sc := bufio.NewScanner(counted)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, text := range expandTokens(line, "custom") {
			if len(out) >= MaxWordlistPayloads {
				return nil, fmt.Errorf("wordlist %s: more than %d payloads", wordlist, MaxWordlistPayloads)
			}
			out = append(out, Payload{Text: text, Method: "custom"})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("wordlist %s: %w", wordlist, err)
	}
	if counted.n > MaxWordlistBytes {
		return nil, fmt.Errorf("wordlist %s: exceeds the %d-byte limit", wordlist, MaxWordlistBytes)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("wordlist %s: no payloads", wordlist)
	}
	return out, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func loadEmbedded(method string) ([]string, error) {
	data, err := wordlists.ReadFile("wordlists/" + method + ".txt")
	if err != nil {
		return nil, fmt.Errorf("bundled wordlist for %s: %w", method, err)
	}
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, sc.Err()
}

// expandTokens turns the readable wordlist tokens into real payloads.
func expandTokens(line, method string) []string {
	switch {
	case line == "<empty>":
		return []string{""}
	case line == "<longjson>":
		return []string{strings.Repeat("[", 200) + strings.Repeat("]", 200)}
	case strings.HasPrefix(line, "<repeat:") && strings.HasSuffix(line, ">"):
		inner := strings.TrimSuffix(strings.TrimPrefix(line, "<repeat:"), ">")
		parts := strings.Split(inner, ":")
		if len(parts) != 2 {
			return []string{line}
		}
		n, err := strconv.Atoi(parts[1])
		if err != nil || n < 0 || n > 1<<20 {
			return []string{line}
		}
		return []string{strings.Repeat(parts[0], n)}
	default:
		return []string{line}
	}
}

// interleave round-robins several payload lists into one.
func interleave(groups [][]Payload) []Payload {
	total := 0
	for _, g := range groups {
		total += len(g)
	}
	out := make([]Payload, 0, total)
	for i := 0; len(out) < total; i++ {
		for _, g := range groups {
			if i < len(g) {
				out = append(out, g[i])
			}
		}
	}
	return out
}

// BuildMutations pairs every target with every payload.
//
// Payloads are the outer loop so a request cap smaller than one target's payload
// count still reaches every target. With targets as the outer loop, a run capped
// below len(payloads) would only ever exercise the first target and silently
// skip the rest.
//
// The uncapped form is bounded by MaxMutations as a backstop; callers that know
// their request budget should use BuildMutationsCapped so the slice is never
// larger than the run can send.
func BuildMutations(targets []Target, payloads []Payload) []Mutation {
	return BuildMutationsCapped(targets, payloads, MaxMutations)
}

// BuildMutationsCapped is BuildMutations with an explicit upper bound on the
// number of mutations allocated. max <= 0 means no caller-imposed cap (the
// MaxMutations backstop still applies).
func BuildMutationsCapped(targets []Target, payloads []Payload, max int) []Mutation {
	if max <= 0 || max > MaxMutations {
		max = MaxMutations
	}
	limit := 0
	if len(payloads) > 0 {
		// Guard the multiply so a huge target count cannot overflow before the
		// cap is applied.
		if len(targets) > max/len(payloads) {
			limit = max
		} else {
			limit = len(targets) * len(payloads)
		}
	}
	out := make([]Mutation, 0, limit)
	if limit == 0 {
		return out
	}
	for _, p := range payloads {
		for _, t := range targets {
			if len(out) >= limit {
				return out
			}
			out = append(out, Mutation{Target: t, Payload: p.Text, Typed: p.Typed, Method: p.Method})
		}
	}
	return out
}
