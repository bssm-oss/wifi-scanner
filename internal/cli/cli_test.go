package cli

import (
	"bytes"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--version"}, &stdout, &stderr, VersionInfo{Version: "test", Commit: "abc", Date: "now"})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "wifi-scanner test") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func TestRunFindsLocalPortJSON(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"--targets", "127.0.0.1",
		"--ports", net.JoinHostPort("", ""),
	}, &stdout, &stderr, VersionInfo{Version: "test"})
	if code == 0 {
		t.Fatalf("expected invalid port failure")
	}

	stdout.Reset()
	stderr.Reset()
	code = Run([]string{
		"--targets", "127.0.0.1",
		"--ports", strconvPort(port),
		"--timeout", (500 * time.Millisecond).String(),
		"--format", "json",
	}, &stdout, &stderr, VersionInfo{Version: "test"})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"port": `+strconvPort(port)) {
		t.Fatalf("unexpected stdout: %s stderr=%s", stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), `"url"`) {
		t.Fatalf("port-only mode should not synthesize URL: %s", stdout.String())
	}
}

func TestRunSitesOnlyJSON(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("<title>cli site</title>"))
		}),
	}
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"--targets", "127.0.0.1",
		"--ports", strconvPort(port),
		"--sites-only",
		"--site-timeout", time.Second.String(),
		"--format", "json",
	}, &stdout, &stderr, VersionInfo{Version: "test"})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"url": "http://127.0.0.1:`+strconvPort(port)+`"`) {
		t.Fatalf("stdout missing site URL: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"site": true`) || !strings.Contains(stdout.String(), `"http_status": 200`) {
		t.Fatalf("stdout missing site metadata: %s", stdout.String())
	}
}

func TestParseStatusRanges(t *testing.T) {
	ranges, err := parseStatusRanges("200-204,301")
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 2 || ranges[0].Start != 200 || ranges[0].End != 204 || ranges[1].Start != 301 || ranges[1].End != 301 {
		t.Fatalf("unexpected ranges: %#v", ranges)
	}
	if _, err := parseStatusRanges("99"); err == nil {
		t.Fatal("expected invalid status error")
	}
}

func strconvPort(port int) string {
	return strconv.Itoa(port)
}
