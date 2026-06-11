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
	if hasSiteMetadata(results) {
		if _, err := fmt.Fprintln(tw, "URL\tIP\tPORT\tPROTO\tSTATUS\tSITE\tHTTP\tSOURCE\tLATENCY_MS\tTITLE\tBANNER"); err != nil {
			return err
		}
		for _, r := range results {
			if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n", r.URL, r.IP, portString(r.Port), r.Protocol, r.Status, yesNo(r.Site), httpStatus(r.HTTPStatus), r.Source, r.LatencyMS, r.Title, r.Banner); err != nil {
				return err
			}
		}
		return tw.Flush()
	}
	if _, err := fmt.Fprintln(tw, "IP\tPORT\tPROTO\tSTATUS\tSOURCE\tLATENCY_MS\tBANNER"); err != nil {
		return err
	}
	for _, r := range results {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n", r.IP, portString(r.Port), r.Protocol, r.Status, r.Source, r.LatencyMS, r.Banner); err != nil {
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
	if hasSiteMetadata(results) {
		if err := cw.Write([]string{"url", "ip", "port", "protocol", "status", "site", "http_status", "content_type", "title", "source", "latency_ms", "banner"}); err != nil {
			return err
		}
		for _, r := range results {
			if err := cw.Write([]string{
				r.URL,
				r.IP,
				portCSV(r.Port),
				r.Protocol,
				r.Status,
				strconv.FormatBool(r.Site),
				httpStatus(r.HTTPStatus),
				r.ContentType,
				r.Title,
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
	if err := cw.Write([]string{"ip", "port", "protocol", "status", "source", "latency_ms", "banner"}); err != nil {
		return err
	}
	for _, r := range results {
		if err := cw.Write([]string{
			r.IP,
			portCSV(r.Port),
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

func hasSiteMetadata(results []scanner.Result) bool {
	for _, r := range results {
		if r.URL != "" || r.Site || r.HTTPStatus != 0 || r.ContentType != "" || r.Title != "" {
			return true
		}
	}
	return false
}

func portString(port int) string {
	if port <= 0 {
		return "-"
	}
	return strconv.Itoa(port)
}

func portCSV(port int) string {
	if port <= 0 {
		return ""
	}
	return strconv.Itoa(port)
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return ""
}

func httpStatus(status int) string {
	if status == 0 {
		return ""
	}
	return strconv.Itoa(status)
}
