//go:build linux

package main

import (
	"os"
	"syscall"
)

var signals = []os.Signal{
	syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP,
}
