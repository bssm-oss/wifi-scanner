package scanner

import (
	"bufio"
	"context"
	"net"
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
	wantURL := "https://127.0.0.1:" + strconv.Itoa(port)
	if results[0].URL != wantURL {
		t.Fatalf("got URL %q want %q", results[0].URL, wantURL)
	}
	if !strings.Contains(results[0].Banner, "hello scanner") {
		t.Fatalf("expected banner, got %q", results[0].Banner)
	}
	<-done
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
