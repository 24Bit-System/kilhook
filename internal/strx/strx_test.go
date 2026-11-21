package strx

import "testing"

func TestTruncate(t *testing.T) {
	cases := []struct{ in, want string }{
		{"short", "short"},
		{"exactly5", "exact…"},
		{"0123456789", "01234…"},
		{"héllo wörld", "héll…"}, // é is 2 bytes: limit 5 stops mid-word, not mid-rune
		{"日本語テキスト", "日…"}, // 3-byte runes: limit 5 keeps one whole rune
	}
	for _, c := range cases {
		if got := Truncate(c.in, 5); got != c.want {
			t.Errorf("Truncate(%q, 5) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := Truncate("abc", -1); got != "…" {
		t.Errorf("negative limit must clamp to 0, got %q", got)
	}
}
