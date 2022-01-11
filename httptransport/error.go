package httptransport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// ApiError writes an untyped (that is, "application/json") error with the
// provided HTTP status code and message.
func apiError(w http.ResponseWriter, code int, f string, v ...interface{}) {
	const errheader = `Clair-Error`
	h := w.Header()
	h.Del("link")
	h.Set("content-type", "application/json")
	h.Set("x-content-type-options", "nosniff")
	h.Set("trailer", errheader)
	w.WriteHeader(code)

	var buf bytes.Buffer
	buf.WriteString(`{"code":"`)
	switch code {
	case http.StatusBadRequest:
		buf.WriteString("bad-request")
	case http.StatusMethodNotAllowed:
		buf.WriteString("method-not-allowed")
	case http.StatusNotFound:
		buf.WriteString("not-found")
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
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}
