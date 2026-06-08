package cli

import (
	"bytes"
	"net"
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
}

func strconvPort(port int) string {
	return strconv.Itoa(port)
}
