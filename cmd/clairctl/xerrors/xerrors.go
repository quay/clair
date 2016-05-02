package xerrors

import "errors"

var (
	ServiceUnavailable = errors.New("service is unavailable")
	Unauthorized       = errors.New("unauthorized access")
	NotFound           = errors.New("image not found")
	InternalError      = errors.New("client quit unexpectedly")
	ErrDisallowed      = errors.New("analysing official images is not allowed")
)
