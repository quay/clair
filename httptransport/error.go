package httptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"

	"github.com/quay/zlog"
)

// ApiError writes an untyped (that is, "application/json") error with the
// provided HTTP status code and message.
//
// ApiError does not return, but instead causes the goroutine to exit.
func apiError(ctx context.Context, w http.ResponseWriter, code int, f string, v ...interface{}) {
	const errheader = `Clair-Error`
	h := w.Header()
	h.Del("link")
	h.Set("content-type", "application/json")
	h.Set("x-content-type-options", "nosniff")
	h.Set("trailer", errheader)
	w.WriteHeader(code)
	if ev := zlog.Debug(ctx); ev.Enabled() {
		ev.
			Int("code", code).
			Str("error", fmt.Sprintf(f, v...)).
			Msg("http error response")
	}

	var buf bytes.Buffer
	buf.WriteString(`{"code":"`)
	switch code {
	case http.StatusBadRequest:
		buf.WriteString("bad-request")
	case http.StatusMethodNotAllowed:
		buf.WriteString("method-not-allowed")
	case http.StatusNotFound:
		buf.WriteString("not-found")
	case http.StatusTooManyRequests:
		buf.WriteString("too-many-requests")
	default:
		buf.WriteString("internal-error")
	}
	buf.WriteByte('"')
	if f != "" {
		buf.WriteString(`,"message":`)
		b, _ := json.Marshal(fmt.Sprintf(f, v...)) // OK use of encoding/json.
		buf.Write(b)
	}
	buf.WriteByte('}')

	if _, err := buf.WriteTo(w); err != nil {
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
	runtime.Goexit()
}
