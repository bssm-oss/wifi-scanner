package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"text/tabwriter"

	"github.com/bssm-oss/wifi-scanner/internal/scanner"
)

func Write(w io.Writer, format string, results []scanner.Result) error {
	switch format {
	case "", "table":
		return writeTable(w, results)
	case "json":
		return writeJSON(w, results)
	case "csv":
		return writeCSV(w, results)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func writeTable(w io.Writer, results []scanner.Result) error {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "URL\tIP\tPORT\tPROTO\tSTATUS\tSOURCE\tLATENCY_MS\tBANNER"); err != nil {
		return err
	}
	for _, r := range results {
		port := "-"
		if r.Port > 0 {
			port = strconv.Itoa(r.Port)
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n", r.URL, r.IP, port, r.Protocol, r.Status, r.Source, r.LatencyMS, r.Banner); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func writeJSON(w io.Writer, results []scanner.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func writeCSV(w io.Writer, results []scanner.Result) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"url", "ip", "port", "protocol", "status", "source", "latency_ms", "banner"}); err != nil {
		return err
	}
	for _, r := range results {
		port := ""
		if r.Port > 0 {
			port = strconv.Itoa(r.Port)
		}
		if err := cw.Write([]string{
			r.URL,
			r.IP,
			port,
			r.Protocol,
			r.Status,
			r.Source,
			strconv.FormatInt(r.LatencyMS, 10),
			r.Banner,
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
