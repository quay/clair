package codec

import "io"

// JSONReader returns an io.ReadCloser backed by a pipe being fed by a JSON
// encoder.
func JSONReader(v interface{}) io.ReadCloser {
	r, w := io.Pipe()
	// This unsupervised goroutine should be fine, because the writer will error
	// once the reader is closed.
	go func() {
		enc := GetEncoder(w)
		defer PutEncoder(enc)
		defer w.Close()
		if err := enc.Encode(v); err != nil {
			w.CloseWithError(err)
		}
	}()
	return r
}
