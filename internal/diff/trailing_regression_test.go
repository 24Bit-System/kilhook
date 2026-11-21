package diff

import "testing"

func TestIsJSONRejectsTrailingBrace(t *testing.T) {
	for _, bad := range []string{`{"a":1}}`, `1}`, `{"a":1} junk`, `{"a":1} ,`} {
		if IsJSON([]byte(bad)) {
			t.Fatalf("IsJSON accepted trailing data: %s", bad)
		}
	}
	for _, good := range []string{`{"a":1}`, `[1,2]`, "1"} {
		if !IsJSON([]byte(good)) {
			t.Fatalf("IsJSON rejected valid JSON: %s", good)
		}
	}
}
