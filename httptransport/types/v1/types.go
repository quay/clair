// Package types provides JSON Schemas for the HTTP API.
package types

import (
	"embed"
	"fmt"
)

//go:generate sh -euc "for f in *.json; do <$DOLLAR{f} >$DOLLAR{f}_ jq -e .; mv $DOLLAR{f}_ $DOLLAR{f}; done"

//go:embed *.schema.json
var Schema embed.FS

// Error is the HTTP v1 API error return object.
type Error struct {
	Code   int
	format string
	args   []any
}

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
