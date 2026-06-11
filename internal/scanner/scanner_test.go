package scanner

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestScanTCPFindsLocalListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("hello scanner\r\n"))
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	results, err := Scan(context.Background(), Config{
		Targets:     []net.IP{net.ParseIP("127.0.0.1")},
		TCPPorts:    []int{port},
		Timeout:     time.Second,
		Concurrency: 4,
		Banner:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results want 1: %#v", len(results), results)
	}
	if results[0].Port != port || results[0].Protocol != "tcp" || results[0].Status != "open" {
		t.Fatalf("unexpected result: %#v", results[0])
	}
	if results[0].URL != "" {
		t.Fatalf("port-only scan should not synthesize URL, got %q", results[0].URL)
	}
	if !strings.Contains(results[0].Banner, "hello scanner") {
		t.Fatalf("expected banner, got %q", results[0].Banner)
	}
	<-done
}

func TestScanSitesOnlyFindsHTTPServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><title>asset app</title><body>ok</body></html>"))
		}),
	}
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Shutdown(context.Background())

	port := listener.Addr().(*net.TCPAddr).Port
	results, err := Scan(context.Background(), Config{
		Targets:     []net.IP{net.ParseIP("127.0.0.1")},
		TCPPorts:    []int{port},
		Timeout:     time.Second,
		Concurrency: 4,
		ProbeSites:  true,
		SitesOnly:   true,
		SiteTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results want 1: %#v", len(results), results)
	}
	wantURL := "http://127.0.0.1:" + strconv.Itoa(port)
	if results[0].URL != wantURL || !results[0].Site || results[0].HTTPStatus != http.StatusOK {
		t.Fatalf("unexpected site result: %#v", results[0])
	}
	if results[0].Title != "asset app" {
		t.Fatalf("got title %q", results[0].Title)
	}
}

func TestScanSitesOnlyFiltersDisallowedStatus(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}),
	}
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Shutdown(context.Background())

	port := listener.Addr().(*net.TCPAddr).Port
	results, err := Scan(context.Background(), Config{
		Targets:     []net.IP{net.ParseIP("127.0.0.1")},
		TCPPorts:    []int{port},
		Timeout:     time.Second,
		Concurrency: 4,
		ProbeSites:  true,
		SitesOnly:   true,
		SiteTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("404 should be filtered by default: %#v", results)
	}
}

func TestParseARPTable(t *testing.T) {
	input := `? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
? (192.168.1.20) at 11:22:33:44:55:66 on en0 ifscope [ethernet]
? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]`
	results := ParseARPTable(input)
	if len(results) != 2 {
		t.Fatalf("got %d results want 2", len(results))
	}
	if results[0].Source != "arp" || results[0].Protocol != "host" {
		t.Fatalf("unexpected ARP result: %#v", results[0])
	}
}

func TestHTTPBannerProbe(t *testing.T) {
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
		_, _ = bufio.NewReader(conn).ReadString('\n')
		_, _ = conn.Write([]byte("HTTP/1.0 200 OK\r\nServer: test\r\n\r\n"))
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	banner := readBanner(conn, 8080, time.Second)
	if !strings.Contains(banner, "HTTP/1.0 200 OK") {
		t.Fatalf("unexpected banner: %q", banner)
	}
}
