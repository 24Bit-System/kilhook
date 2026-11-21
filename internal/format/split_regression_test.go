package format

import "testing"

func TestSplitIgnoresMarkerInsideBlockScalar(t *testing.T) {
	input := "format: 1\nname: |\n  first\n  ---\n  last\nmethod: GET\nurl: http://x/\n---\nBODY\n"
	_, body, err := split([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "BODY\n" {
		t.Fatalf("body = %q", body)
	}
	f, _, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("the block scalar should parse: %v", err)
	}
	if f.Name != "first\n---\nlast\n" {
		t.Fatalf("name = %q", f.Name)
	}
}

func TestSplitStillFindsRealMarker(t *testing.T) {
	input := "format: 1\nname: X\nmethod: GET\nurl: http://x/\n---\n{\"a\":1}\n"
	_, body, err := split([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "{\"a\":1}\n" {
		t.Fatalf("body = %q", body)
	}
}
