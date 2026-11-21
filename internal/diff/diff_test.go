package diff

import (
	"strings"
	"testing"
)

func TestJSONFieldLevelChanges(t *testing.T) {
	before := []byte(`{"user":{"name":"a","age":30},"tags":["x","y"],"gone":1}`)
	after := []byte(`{"user":{"name":"b","age":30,"email":"e"},"tags":["x","y","z"]}`)

	changes, err := JSON(before, after)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range changes {
		got[c.Path] = c.Kind
	}
	want := map[string]string{
		"response.user.name":  Changed,
		"response.user.email": Added,
		"response.gone":       Removed,
		"response.tags[2]":    Added,
	}
	if len(got) != len(want) {
		t.Fatalf("changes = %+v", changes)
	}
	for path, kind := range want {
		if got[path] != kind {
			t.Errorf("%s: got %q want %q (all: %+v)", path, got[path], kind, changes)
		}
	}
}

func TestJSONTypeChange(t *testing.T) {
	changes, err := JSON([]byte(`{"id":1}`), []byte(`{"id":"1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Kind != TypeChanged || changes[0].Path != "response.id" {
		t.Fatalf("changes = %+v", changes)
	}
}

func TestJSONNoChanges(t *testing.T) {
	changes, err := JSON([]byte(`{"a":[1,2],"b":null}`), []byte(`{"b":null,"a":[1,2]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Fatalf("expected no changes, got %+v", changes)
	}
}

func TestJSONNumberEqualityIsNumeric(t *testing.T) {
	changes, err := JSON([]byte(`{"n":1}`), []byte(`{"n":1.0}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Fatalf("1 and 1.0 must compare equal, got %+v", changes)
	}
}

func TestJSONRejectsInvalid(t *testing.T) {
	if _, err := JSON([]byte("not json"), []byte(`{}`)); err == nil {
		t.Fatal("expected error for invalid baseline")
	}
	if _, err := JSON([]byte(`{}`), []byte("<html>")); err == nil {
		t.Fatal("expected error for invalid current")
	}
}

func TestTextDiffFallback(t *testing.T) {
	before := "line one\nline two\nline three\n"
	after := "line one\nline 2\nline three\nline four\n"
	changes := Text(before, after)

	var added, removed int
	for _, c := range changes {
		switch c.Kind {
		case Added:
			added++
		case Removed:
			removed++
		}
	}
	if added != 2 || removed != 1 {
		t.Fatalf("added=%d removed=%d changes=%+v", added, removed, changes)
	}
	joined := ""
	for _, c := range changes {
		joined += c.Summary() + "\n"
	}
	if !strings.Contains(joined, "line 2") || !strings.Contains(joined, "line four") {
		t.Fatalf("summaries = %s", joined)
	}
}

func TestIsJSON(t *testing.T) {
	if !IsJSON([]byte(`{"a":1}`)) || IsJSON([]byte("nope")) {
		t.Fatal("IsJSON misclassified")
	}
}

func TestJSONRendersLongStringsRuneSafely(t *testing.T) {
	// 150 × "ä" is 300 bytes, so render() truncates it; the cut must not land
	// inside a rune (strconv.Quote would show the broken byte as \xNN).
	before := []byte(`{"s":"` + strings.Repeat("a", 300) + `"}`)
	after := []byte(`{"s":"` + strings.Repeat("ä", 150) + `"}`)
	changes, err := JSON(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Kind != Changed {
		t.Fatalf("changes = %+v", changes)
	}
	if strings.Contains(changes[0].After, `\x`) {
		t.Fatalf("value was cut mid-rune: %s", changes[0].After)
	}
	if !strings.Contains(changes[0].Summary(), "~ response.s") {
		t.Fatalf("summary = %q", changes[0].Summary())
	}
}
