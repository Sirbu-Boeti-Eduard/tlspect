package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"tlspect/cmd/tlspect/output"
	"tlspect/cmd/tlspect/scanner"
)

func main() {
	var port, timeout int
	var jsonOutput, noColor bool
	var failUnder int
	flag.IntVar(&port, "port", 443, "TLS port to audit")
	flag.IntVar(&timeout, "timeout", 5, "timeout per network operation in seconds")
	flag.BoolVar(&jsonOutput, "json", false, "emit the report as JSON")
	flag.BoolVar(&noColor, "no-color", false, "disable ANSI colors in terminal output")
	flag.IntVar(&failUnder, "fail-under", -1, "exit 1 when the score is below this value (0-100)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: tlspect [flags] host\n\nExample: tlspect example.com")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if port < 1 || port > 65535 || timeout < 1 || timeout > 60 || failUnder < -1 || failUnder > 100 {
		fmt.Fprintln(os.Stderr, "tlspect: port must be 1-65535, timeout 1-60 seconds, and fail-under -1 to 100")
		os.Exit(2)
	}

	report, err := scanner.Scan(context.Background(), flag.Arg(0), scanner.Options{Port: port, Timeout: time.Duration(timeout) * time.Second})
	if err != nil {
		fmt.Fprintln(os.Stderr, "tlspect:", err)
		os.Exit(1)
	}
	if jsonOutput {
		err = output.JSON(os.Stdout, report)
	} else {
		err = output.Terminal(os.Stdout, report, !noColor)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tlspect:", err)
		os.Exit(1)
	}
	if failUnder >= 0 && report.Score < failUnder {
		os.Exit(1)
	}
}
