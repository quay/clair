//go:build !linux

package main

import "os"

var signals = []os.Signal{}
