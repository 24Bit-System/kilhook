package engine

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// reachableNonLocalAddr returns an address of this machine that the loopback
// guard treats as non-local but that can actually be dialled. Link-local and
// down interfaces are common in containers, so probe each candidate.
func reachableNonLocalAddr(t *testing.T, port int) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("no network interfaces: %v", err)
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP.To4()
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			continue
		}
		target := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", target, 300*time.Millisecond)
		if err != nil {
			continue
		}
		conn.Close()
		return ip.String()
	}
	t.Skip("no reachable non-loopback local IPv4 address")
	return ""
}

func TestNonLocalFuzzIsSkippedWithWarning(t *testing.T) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	ip := reachableNonLocalAddr(t, port)
	rawURL := "http://" + ip + ":" + strconv.Itoa(port) + "/pets/1?q=base"
	dir := t.TempDir()
	path := filepath.Join(dir, "req.kh")
	content := "format: 1\nname: X\nmethod: GET\nurl: \"" + rawURL + "\"\n" +
		"fuzz:\n  targets: [query.q]\n  max_requests: 2\n---\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := Run(context.Background(), path, Options{}, nil)
	if err != nil {
		if strings.Contains(err.Error(), "request failed") {
			t.Skipf("cannot reach the local non-loopback address: %v", err)
		}
		t.Fatal(err)
	}
	if rep.Response == nil {
		t.Fatal("the baseline response must survive a skipped fuzz pass")
	}
	if rep.Fuzz != nil {
		t.Fatalf("fuzz must be skipped without --allow-nonlocal, got %+v", rep.Fuzz)
	}
	warned := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "not localhost") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("missing the skip warning: %v", rep.Warnings)
	}
	if rep.ExitCode != 2 {
		t.Fatalf("a skipped declared fuzz pass must be incomplete, exit code = %d", rep.ExitCode)
	}
}
