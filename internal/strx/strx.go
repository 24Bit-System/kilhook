// Package strx holds tiny string helpers shared by the internal packages, so
// behaviour like rune-safe truncation is implemented exactly once.
package strx

import "unicode/utf8"

// Truncate shortens s to at most n bytes without ever cutting a UTF-8 rune in
// half, appending an ellipsis when it shortened anything.
func Truncate(s string, n int) string {
	if n < 0 {
		n = 0
	}
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
