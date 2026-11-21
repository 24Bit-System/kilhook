package fuzz

import (
	"context"
	"testing"

	httpreq "github.com/24Bit-System/kilhook/internal/http"
)

func TestRunRejectsRateBelowMinimum(t *testing.T) {
	base := &httpreq.Request{Method: "GET", URL: "http://localhost:1/"}
	if _, err := Run(context.Background(), base, nil, nil, Config{RateLimit: 0.001}); err == nil {
		t.Fatal("a rate below MinRateLimit must be rejected")
	}
}

func TestLimiterHandlesTinyFiniteRate(t *testing.T) {
	l := newLimiter(1e-300)
	if l.interval <= 0 {
		t.Fatalf("limiter interval overflowed to %v", l.interval)
	}
}
