package httptransport

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/quay/zlog"

	types "github.com/quay/clair/v4/httptransport/types/v1"
	"github.com/quay/clair/v4/internal/codec"
)

// StatusClientClosedRequest is a nonstandard HTTP status code used when the
// client has gone away.
//
// This convention is cribbed from Nginx.
const statusClientClosedRequest = 499

// ApiError writes a v1 error ("application/vnd.clair.error.v1+json") with the
// provided HTTP status code and message.
//
// ApiError does not return, but instead causes the goroutine to exit.
func apiError(ctx context.Context, w http.ResponseWriter, code int, f string, v ...any) {
	const errheader = `Clair-Error`
	const ctype = `application/vnd.clair.error.v1+json`
	disconnect := false
	select {
	case <-ctx.Done():
		disconnect = true
	default:
	}
	if ev := zlog.Debug(ctx); ev.Enabled() {
		ev.
			Bool("disconnect", disconnect).
			Int("code", code).
			Str("error", fmt.Sprintf(f, v...)).
			Msg("http error response")
	} else {
		ev.Send()
	}
	if disconnect {
		// Exit immediately if there's no client to read the response, anyway.
		w.WriteHeader(statusClientClosedRequest)
		panic(http.ErrAbortHandler)
	}

	h := w.Header()
	// Remove the links that use API relations: they should only be used on
	// successful responses.
	h[`Link`] = slices.DeleteFunc(h[`Link`], func(v string) bool {
		return strings.Contains(v, `rel="https://projectquay.io/clair/v1`)
	})
	h.Set("content-type", ctype)
	h.Set("x-content-type-options", "nosniff")
	h.Set("trailer", errheader)
	w.WriteHeader(code)

	enc := codec.GetEncoder(w, codec.SchemeV1)
	val := types.Error{
		Code:    code,
		Message: fmt.Sprintf(f, v...),
	}
	if err := enc.Encode(&val); err != nil {
		h.Set(errheader, err.Error())
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

// CheckMethod returns if the request method is in the "allow" slice, or calls
// [apiError] with appropriate arguments.
func checkMethod(ctx context.Context, w http.ResponseWriter, r *http.Request, allow ...string) {
	if slices.Contains(allow, r.Method) {
		return
	}
	w.Header().Set(`Allow`, strings.Join(allow, ", "))
	apiError(ctx, w, http.StatusMethodNotAllowed, "method %q disallowed", r.Method)
}
