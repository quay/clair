// Package codec is a unified place for configuring and allocating JSON encoders
// and decoders.
package codec

import (
	"io"
	"sync"

	"github.com/ugorji/go/codec"
)

var jsonHandle codec.JsonHandle

func init() {
	// This is documented to cause "smart buffering".
	jsonHandle.WriterBufferSize = 4096
	jsonHandle.ReaderBufferSize = 4096
	// Force calling time.Time's Marshal function. This causes an allocation on
	// every time.Time value, but is the same behavior as the stdlib json
	// encoder. If we decide nulls are OK, this should get removed.
	jsonHandle.TimeNotBuiltin = true
}

// Encoder and decoder pools, to reuse if possible.
var (
	encPool = sync.Pool{
		New: func() interface{} {
			return codec.NewEncoder(nil, &jsonHandle)
		},
	}
	decPool = sync.Pool{
		New: func() interface{} {
			return codec.NewDecoder(nil, &jsonHandle)
		},
	}
)

// Encoder encodes.
type Encoder = codec.Encoder

// GetEncoder returns an encoder configured to write to w.
func GetEncoder(w io.Writer) *Encoder {
	e := encPool.Get().(*Encoder)
	e.Reset(w)
	return e
}

// PutEncoder returns an encoder to the pool.
func PutEncoder(e *Encoder) {
	e.Reset(nil)
	encPool.Put(e)
}

// Decoder decodes.
type Decoder = codec.Decoder

// GetDecoder returns a decoder configured to read from r.
func GetDecoder(r io.Reader) *Decoder {
	d := decPool.Get().(*Decoder)
	d.Reset(r)
	return d
}

// PutDecoder returns a decoder to the pool.
func PutDecoder(d *Decoder) {
	d.Reset(nil)
	decPool.Put(d)
}
