package echo

import (
	"context"
	"sync"
	"time"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/matchers/registry"
	"github.com/quay/claircore/updater"
)

var (
	once   sync.Once
	regerr error
)

func init() {
	ctx, done := context.WithTimeout(context.Background(), 1*time.Minute)
	defer done()
	once.Do(func() { regerr = register(ctx) })
}

// Error reports if an error was encountered when initializing the Echo
// updater and matcher.
func Error() error {
	return regerr
}

func register(ctx context.Context) error {
	f, err := NewFactory(ctx)
	if err != nil {
		return err
	}
	updater.Register("echo", f)

	registry.Register("echo-matcher", driver.MatcherStatic(&Matcher{}))

	return nil
}
