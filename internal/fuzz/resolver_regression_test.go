package fuzz

import (
	"strings"
	"testing"

	httpreq "github.com/24Bit-System/kilhook/internal/http"
)

func TestMutateCaseVariantHeaderReachesTheWire(t *testing.T) {
	base := &httpreq.Request{Method: "GET", URL: "http://h/x", Headers: map[string]string{"X-Foo": "base"}}
	mut, err := Mutate(base, Target{Raw: "header.x-foo", Kind: KindHeader, Path: []string{"x-foo"}}, "fuzzed", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mut.Headers["x-foo"]; ok {
		t.Fatalf("a duplicate case-variant key was created: %+v", mut.Headers)
	}
	if mut.Headers["X-Foo"] != "fuzzed" {
		t.Fatalf("payload did not replace the existing header: %+v", mut.Headers)
	}
}

func TestMutateBodyPreservesLargeIntegers(t *testing.T) {
	body := []byte(`{"id":1234567890123456789,"name":"a"}`)
	target := Target{Raw: "body.name", Kind: KindBody, Path: []string{"name"}}
	got, err := mutateBody(body, target.Path, "x", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"id":1234567890123456789`) {
		t.Fatalf("snowflake ID was corrupted: %s", got)
	}
}

func TestMutatePathPreservesRepeatedSlashes(t *testing.T) {
	got, err := mutatePath("http://h//users/42/", 1, "X")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://h//users/X/" {
		t.Fatalf("path slashes collapsed: %q", got)
	}
}

func TestTypedInjectionRejectsTrailingGarbage(t *testing.T) {
	body := []byte(`{"v":"a"}`)
	path := []string{"v"}
	got, err := mutateBody(body, path, "1 2", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"v":"1 2"`) {
		t.Fatalf("trailing garbage changed the injected literal: %s", got)
	}
}
