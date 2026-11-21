// Oracle for the differential fuzzer: libinjection-go's verdict for each input.
//
// Reads one hex-encoded input per line on stdin. Writes one line per input:
// "<isSQLi 0|1> <fingerprint or -> <isXSS 0|1>", or "panic" when libinjection-go panics.
// Output is flushed whenever no more input is buffered.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"

	libinjection "github.com/corazawaf/libinjection-go"
)

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriterSize(os.Stdout, 1<<16)
	defer out.Flush()
	for {
		line, err := in.ReadString('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
		}
		if line != "" || err == nil {
			data, decodeErr := hex.DecodeString(line)
			if decodeErr != nil {
				fmt.Fprintln(os.Stderr, "bad hex:", decodeErr)
				os.Exit(2)
			}
			fmt.Fprintln(out, check(string(data)))
		}
		if err != nil {
			return
		}
		if in.Buffered() == 0 {
			out.Flush()
		}
	}
}

func check(s string) (result string) {
	defer func() {
		if recover() != nil {
			result = "panic"
		}
	}()
	sqli, fp := libinjection.IsSQLi(s)
	if fp == "" {
		fp = "-"
	}
	xss := libinjection.IsXSS(s)
	return fmt.Sprintf("%d %s %d", b2i(sqli), fp, b2i(xss))
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
