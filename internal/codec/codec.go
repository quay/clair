// Package codec is a unified place for configuring and allocating JSON encoders
// and decoders.
package codec

import (
	"io"
)

// Encoder encodes.
type Encoder interface {
	Encode(in any) error
}

// Decoder decodes.
type Decoder interface {
	Decode(out any) error
}

// All the exported functions delegate to an unexported version, which is
// provided by whichever implementation is selected at compile time.

// GetEncoder returns an encoder configured to write to w.
func GetEncoder(w io.Writer) Encoder {
	return getEncoder(w)
}

// PutEncoder returns an encoder to the pool.
func PutEncoder(v Encoder) {
	putEncoder(v)
}

// GetDecoder returns a decoder configured to read from r.
func GetDecoder(r io.Reader) Decoder {
	return getDecoder(r)
}

// PutDecoder returns a decoder to the pool.
func PutDecoder(v Decoder) {
	putDecoder(v)
}
