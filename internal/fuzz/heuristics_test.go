package fuzz

import (
	"testing"

	httpreq "github.com/24Bit-System/kilhook/internal/http"
)

func TestErrorStringAlreadyInBaselineIsNotReported(t *testing.T) {
	base := &httpreq.Response{
		StatusCode: 200,
		Body:       []byte(`{"error":"SQLSTATE[42000]: syntax error at or near \"OR\""}`),
	}
	resp := &httpreq.Response{
		StatusCode: 200,
		Body:       []byte(`{"error":"SQLSTATE[42000]: syntax error at or near \"OR\""}`),
	}
	fs := DefaultDetector().Analyze(base, "query.q", "payload", resp)
	if hasKind(fs, KindErrorText) {
		t.Fatalf("an error string present in the baseline is not caused by the payload: %+v", fs)
	}
}

func TestErrorStringNewInResponseIsReported(t *testing.T) {
	base := &httpreq.Response{StatusCode: 200, Body: []byte(`{"ok":true}`)}
	resp := &httpreq.Response{
		StatusCode: 500,
		Body:       []byte(`SQLSTATE[42000]: syntax error at or near "OR"`),
	}
	fs := DefaultDetector().Analyze(base, "query.q", "payload", resp)
	if !hasKind(fs, KindErrorText) {
		t.Fatalf("a new error string should be reported: %+v", fs)
	}
}

func TestDifferentErrorStringStillReportedWhenBaselineHasAnother(t *testing.T) {
	base := &httpreq.Response{StatusCode: 200, Body: []byte(`SQLSTATE[42000]: old`)}
	resp := &httpreq.Response{
		StatusCode: 200,
		Body:       []byte("Traceback (most recent call last): boom"),
	}
	fs := DefaultDetector().Analyze(base, "query.q", "payload", resp)
	if !hasKind(fs, KindErrorText) {
		t.Fatalf("a different error pattern should survive baseline suppression: %+v", fs)
	}
}
