package nvd

import "io"

// NestedReadCloser wraps an io.Reader and implements io.ReadCloser by closing every embed
// io.ReadCloser.
// It allows chaining io.ReadCloser together and still keep the ability to close them all in a
// simple manner.
type NestedReadCloser struct {
	io.Reader
	NestedReadClosers []io.ReadCloser
}

// Close closes the gzip.Reader and the underlying io.ReadCloser.
func (nrc *NestedReadCloser) Close() {
	for _, nestedReadCloser := range nrc.NestedReadClosers {
		nestedReadCloser.Close()
	}
}
