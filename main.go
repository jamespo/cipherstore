// Command cipherstore is a single-binary interface to a SQLCipher database of
// logins and other secrets.
//
// It is both the daemon (`cipherstore start`) and the client for every other
// command; see README.md for the full description.
package main

import (
	"os"

	"github.com/jamespo/cipherstore/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
