//go:build !linux

package main

// Notify sends information back to a supervisor process.
func notify(_ ...any) error {
	return nil
}
