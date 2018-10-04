package dbtest

import "time"

// Lock is the database lock struct that's used only for testing purpose.
type Lock struct {
	Name  string
	Owner string
	Until time.Time
}
