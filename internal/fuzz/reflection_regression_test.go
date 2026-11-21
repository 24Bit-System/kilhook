package fuzz

import (
	"testing"

	httpreq "github.com/24Bit-System/kilhook/internal/http"
)

func TestReflectionOnlyCountsSuccessResponses(t *testing.T) {
	d := DefaultDetector()
	payload := "reflected-payload-long"
	for _, status := range []int{200, 299} {
		resp := &httpreq.Response{StatusCode: status, Body: []byte("value: " + payload)}
		if got := d.Analyze(nil, "query.q", payload, resp); len(got) == 0 {
			t.Fatalf("%d response should report reflection", status)
		}
	}
	for _, status := range []int{101, 302, 400} {
		resp := &httpreq.Response{StatusCode: status, Body: []byte("value: " + payload)}
		for _, f := range d.Analyze(nil, "query.q", payload, resp) {
			if f.Kind == KindReflection {
				t.Fatalf("%d response must not report reflection", status)
			}
		}
	}
}
