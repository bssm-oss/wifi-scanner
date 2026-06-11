package ports

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

var DefaultTCP = []int{
	21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465,
	587, 993, 995, 1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389,
	3001, 4000, 4200, 5000, 5001, 5173, 5432, 5900, 6379, 7000,
	7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9200, 9300,
	9443, 10000, 11211, 27017,
}

var DefaultUDP = []int{53, 67, 68, 123, 137, 161, 1900, 5353}

func ParseTCP(spec string, deep bool) ([]int, error) {
	spec = strings.TrimSpace(strings.ToLower(spec))
	if spec == "" {
		if deep {
			return fullRange(), nil
		}
		return clone(DefaultTCP), nil
	}
	return parse(spec, DefaultTCP)
}

func ParseUDP(spec string) ([]int, error) {
	spec = strings.TrimSpace(strings.ToLower(spec))
	if spec == "" || spec == "none" || spec == "off" {
		return nil, nil
	}
	if spec == "default" || spec == "top" {
		return clone(DefaultUDP), nil
	}
	return parse(spec, DefaultUDP)
}

func parse(spec string, defaults []int) ([]int, error) {
	switch spec {
	case "default", "top":
		return clone(defaults), nil
	case "all":
		return fullRange(), nil
	}

	seen := make(map[int]struct{})
	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if strings.Contains(token, "-") {
			start, end, err := parseRange(token)
			if err != nil {
				return nil, err
			}
			for p := start; p <= end; p++ {
				seen[p] = struct{}{}
			}
			continue
		}
		port, err := parsePort(token)
		if err != nil {
			return nil, err
		}
		seen[port] = struct{}{}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("no ports parsed from %q", spec)
	}

	out := make([]int, 0, len(seen))
	for port := range seen {
		out = append(out, port)
	}
	sort.Ints(out)
	return out, nil
}

func parseRange(token string) (int, int, error) {
	parts := strings.SplitN(token, "-", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid port range %q", token)
	}
	start, err := parsePort(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, err
	}
	end, err := parsePort(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, err
	}
	if start > end {
		return 0, 0, fmt.Errorf("invalid descending port range %q", token)
	}
	return start, end, nil
}

func parsePort(token string) (int, error) {
	port, err := strconv.Atoi(token)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", token)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %d is outside 1-65535", port)
	}
	return port, nil
}

func fullRange() []int {
	out := make([]int, 65535)
	for i := range out {
		out[i] = i + 1
	}
	return out
}

func clone(in []int) []int {
	out := append([]int(nil), in...)
	sort.Ints(out)
	return out
}
