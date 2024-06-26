// Package details contains helpers for implementing [RFC 9457], "Problem Details
// for HTTP APIs."
//
// See the documentation on [Error] for how keys in the response are
// constructed.
//
// [RFC 9457]: https://datatracker.ietf.org/doc/html/rfc9457
package details

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"

	"github.com/quay/zlog"

	"github.com/quay/clair/v4/internal/json"
	"github.com/quay/clair/v4/internal/json/jsontext"
)

// StatusClientClosedRequest is a nonstandard HTTP status code used when the
// client has gone away.
//
// This convention is cribbed from Nginx.
const StatusClientClosedRequest = 499

// ErrorTrailer contains errors encountered while writing the error response, if
// any.
const ErrorTrailer = `Clair-Error`

// Default JSON encoding options.
var opts = json.JoinOptions(json.DefaultOptionsV2())

// Pool of JSON encoders.
var encPool = sync.Pool{
	New: func() any { return jsontext.NewEncoder(io.Discard) },
}

// Error constructs and sends a problem detail response, then causes the
// goroutine to panic with [http.ErrAbortHandler]. Well-written handlers should
// be structured to clean up or record events correctly in this instance.
//
// To customize the returned problem detail response, the error provided to this
// function can provide any combination of the following methods:
//
//   - ErrorStatus() int
//   - ErrorType() string
//   - ErrorTitle() string
//   - ErrorDetail() string
//   - ErrorInstance() string
//   - ErrorExtension() map[string]any
//
// The ErrorStatus method is always consulted and used for the HTTP response
// code if present, otherwise [http.StatusInternalServerError] is used. All
// other methods are used if present. If ErrorDetail is not provided, the value
// of the Error method will be used instead.
//
// These methods correspond to the keys defined in RFC 9457, and so should
// follow the guidance there. This means that the values returned by ErrorType
// and ErrorInstance should be URIs if possible.
func Error(ctx context.Context, w http.ResponseWriter, err error) {
	disconnect := false
	code := http.StatusInternalServerError
	select {
	case <-ctx.Done():
		disconnect = true
	default:
	}
	// Emit the log line in the defer path.
	defer func() {
		// If the client has disconnected, this will show up as a
		// `disconnect=true, code=NNN` pair here and `code=499` in other HTTP
		// metrics.
		zlog.Debug(ctx).
			Bool("disconnect", disconnect).
			Int("code", code).
			AnErr("error", err).
			Msg("http error response")
	}()

	// Always check for the status code.
	if i, ok := err.(errStatus); ok {
		code = i.ErrorStatus()
	}
	// Exit immediately if there's no client to read the response.
	if disconnect {
		w.WriteHeader(StatusClientClosedRequest)
		panic(http.ErrAbortHandler)
	}

	// The client is connected and presumably wants the error; configure the
	// response headers.
	h := w.Header()
	h.Del("link")
	h.Set("content-type", "application/problem+json")
	h.Set("x-content-type-options", "nosniff")
	h.Set("trailer", ErrorTrailer)
	w.WriteHeader(code)

	enc := encPool.Get().(*jsontext.Encoder)
	defer func() { encPool.Put(enc) }()
	enc.Reset(w, opts)

	// Construct and write the details object in one pass.
	wErr := func() error {
		if err := enc.WriteToken(jsontext.ObjectStart); err != nil {
			return err
		}

		var et errType
		if errors.As(err, &et) {
			if err := errors.Join(
				enc.WriteValue(jsontext.Value(`"type"`)), enc.WriteToken(jsontext.String(et.ErrorType())),
			); err != nil {
				return err
			}
		}
		var eti errTitle
		if errors.As(err, &eti) {
			if err := errors.Join(
				enc.WriteValue(jsontext.Value(`"title"`)), enc.WriteToken(jsontext.String(eti.ErrorTitle())),
			); err != nil {
				return err
			}
		}

		var detail string
		var ed errDetail
		if errors.As(err, &ed) {
			detail = ed.ErrorDetail()
		} else {
			detail = err.Error()
		}
		if err := errors.Join(
			enc.WriteValue(jsontext.Value(`"detail"`)), enc.WriteToken(jsontext.String(detail)),
		); err != nil {
			return err
		}

		var ei errInstance
		if errors.As(err, &ei) {
			if err := errors.Join(
				enc.WriteValue(jsontext.Value(`"instance"`)), enc.WriteToken(jsontext.String(ei.ErrorInstance())),
			); err != nil {
				return err
			}
		}

		var ee errExtension
		if errors.As(err, &ee) {
			for k, v := range ee.ErrorExtension() {
				if err := errors.Join(
					enc.WriteToken(jsontext.String(k)), json.MarshalEncode(enc, v, opts),
				); err != nil {
					return err
				}
			}
		}

		return enc.WriteToken(jsontext.ObjectEnd)
	}()
	if wErr != nil {
		h.Set(ErrorTrailer, wErr.Error())
	}

	switch err := http.NewResponseController(w).Flush(); {
	case errors.Is(err, nil):
	case errors.Is(err, http.ErrNotSupported):
		// Skip
	default:
		zlog.Warn(ctx).
			Err(err).
			Msg("unable to flush http response")
	}

	panic(http.ErrAbortHandler)
}

type errType interface {
	ErrorType() string
}
type errStatus interface {
	ErrorStatus() int
}
type errTitle interface {
	ErrorTitle() string
}
type errDetail interface {
	ErrorDetail() string
}
type errInstance interface {
	ErrorInstance() string
}
type errExtension interface {
	ErrorExtension() map[string]any
}
