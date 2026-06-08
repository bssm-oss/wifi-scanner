package main

import (
	"os"

	"github.com/bssm-oss/wifi-scanner/internal/cli"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	code := cli.Run(os.Args[1:], os.Stdout, os.Stderr, cli.VersionInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	})
	os.Exit(code)
}
