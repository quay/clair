package types

import "fmt"

// Error is the HTTP v1 API error return object, a.k.a
// https://clairproject.org/api/http/v1/error.schema.json.
type Error struct {
	Code   int
	format string
	args   []any
}

// NewError constructs an [Error].
func NewError(code int, format string, a ...any) *Error {
	return &Error{
		Code:   code,
		format: format,
		args:   a,
	}
}

func (e *Error) Error() string {
	return fmt.Sprintf(e.format, e.args...)
}
