package notifier

import "context"

// Locker is any context-based locking API.
type Locker interface {
	TryLock(context.Context, string) (context.Context, context.CancelFunc)
	Lock(context.Context, string) (context.Context, context.CancelFunc)
	Close(context.Context) error
}
