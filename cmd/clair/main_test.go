package main

import (
	"flag"
	"os"
	"testing"
)

// TestMain is here to call flag.Parse for the keyserver test.
func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}
