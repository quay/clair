//go:build unix

package main

import (
	"os"
	"syscall"
)

var platformShutdown = []os.Signal{syscall.SIGTERM}
