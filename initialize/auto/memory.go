//go:build !linux || (linux && !go1.19)

package auto

// Memory is a no-op on this platform.
func Memory() {}
