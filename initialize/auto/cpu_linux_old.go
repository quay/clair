//go:build linux && !go1.17 && !go1.16
// +build linux,!go1.17,!go1.16

package auto

// CPU is a no-op on this platform.
func CPU() {}
