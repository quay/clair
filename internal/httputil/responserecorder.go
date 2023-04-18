package httputil

import "net/http"

// ResponseRecorder returns a ResponseWriter that records the HTTP status and
// body length into the provided pointers, and returns another response writer
// that understand the go 1.20 http `Unwrap` scheme.
func ResponseRecorder(status *int, length *int64, w http.ResponseWriter) http.ResponseWriter {
	// Handle nils being passed, just to be nice.
	if length == nil {
		length = new(int64)
	}
	if status == nil {
		status = new(int)
	}
	return &responseRecord{
		ResponseWriter: w,
		status:         status,
		length:         length,
	}
}

var _ http.ResponseWriter = (*responseRecord)(nil)

type responseRecord struct {
	http.ResponseWriter
	status    *int
	length    *int64
	writecall bool
}

func (r *responseRecord) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func (r *responseRecord) WriteHeader(c int) {
	if r.writecall {
		return
	}
	*r.status = c
	r.ResponseWriter.WriteHeader(c)
	r.writecall = true
}

func (r *responseRecord) Write(b []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	n, err := r.ResponseWriter.Write(b)
	*r.length += int64(n)
	return n, err
}
