//go:build !linux
// +build !linux

package auto

// CPU is a no-op on this platform.
func CPU() {}
