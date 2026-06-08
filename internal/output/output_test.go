package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bssm-oss/wifi-scanner/internal/scanner"
)

func TestWriteFormats(t *testing.T) {
	results := []scanner.Result{{
		IP:       "127.0.0.1",
		Port:     8080,
		URL:      "https://127.0.0.1:8080",
		Protocol: "tcp",
		Status:   "open",
		Source:   "connect",
		Banner:   "HTTP/1.0 200 OK",
	}}
	for _, format := range []string{"table", "json", "csv"} {
		var buf bytes.Buffer
		if err := Write(&buf, format, results); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if !strings.Contains(buf.String(), "127.0.0.1") {
			t.Fatalf("%s output missing IP: %s", format, buf.String())
		}
		if !strings.Contains(buf.String(), "https://127.0.0.1:8080") {
			t.Fatalf("%s output missing URL: %s", format, buf.String())
		}
	}
}
