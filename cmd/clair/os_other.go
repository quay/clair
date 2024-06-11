//go:build !unix

package main

import "os"

var platformShutdown = []os.Signal{}
