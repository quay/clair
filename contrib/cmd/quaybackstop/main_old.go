//go:build !go1.23

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "This command was compiled with an old go version: 1.23 or greater is required.")
	os.Exit(2)
}
