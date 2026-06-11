package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bssm-oss/wifi-scanner/internal/scanner"
)

func TestWriteFormats(t *testing.T) {
	results := []scanner.Result{{
		IP:         "127.0.0.1",
		Port:       8080,
		URL:        "http://127.0.0.1:8080",
		Protocol:   "tcp",
		Status:     "open",
		Site:       true,
		HTTPStatus: 200,
		Title:      "test app",
		Source:     "connect",
		Banner:     "HTTP/1.0 200 OK",
	}}
	for _, format := range []string{"table", "json", "csv"} {
		var buf bytes.Buffer
		if err := Write(&buf, format, results); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if !strings.Contains(buf.String(), "127.0.0.1") {
			t.Fatalf("%s output missing IP: %s", format, buf.String())
		}
		if !strings.Contains(buf.String(), "http://127.0.0.1:8080") {
			t.Fatalf("%s output missing URL: %s", format, buf.String())
		}
	}
}

func TestWritePortOnlyTableOmitsURLColumns(t *testing.T) {
	results := []scanner.Result{{
		IP:       "127.0.0.1",
		Port:     22,
		Protocol: "tcp",
		Status:   "open",
		Source:   "connect",
	}}
	var buf bytes.Buffer
	if err := Write(&buf, "table", results); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "URL") || strings.Contains(buf.String(), "SITE") {
		t.Fatalf("port-only table should not include site columns: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "127.0.0.1") || !strings.Contains(buf.String(), "22") {
		t.Fatalf("port-only table missing result: %s", buf.String())
	}
}
