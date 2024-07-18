package httptransport

import (
	"context"
	"fmt"
	"net/http"

	"github.com/quay/clair/v4/httptransport/internal/details"
)

// ApiError writes an error with the provided HTTP status code and message.
//
// ApiError does not return, but instead causes the goroutine to exit.
//
// Deprecated: This is implemented via [details.Error], which provides a
// richer API.
func apiError(ctx context.Context, w http.ResponseWriter, code int, f string, v ...interface{}) {
	err := genericError{
		status: code,
		err:    fmt.Errorf(f, v...),
	}
	details.Error(ctx, w, &err)
}

type genericError struct {
	status int
	err    error
}

func (e *genericError) Error() string {
	return e.err.Error()
}

func (e *genericError) Unwrap() error {
	return e.err
}

func (e *genericError) ErrorStatus() int {
	return e.status
}
