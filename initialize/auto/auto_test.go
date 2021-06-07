package auto

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Reset the logging slice, as the init function will have triggered and
	// written things into it.
	msgs = msgs[:0]
	os.Exit(m.Run())
}
