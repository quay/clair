//go:build !go1.25 || !goexperiment.jsonv2

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
		New: func() any {
			return codec.NewEncoder(nil, &jsonHandle)
		},
	}
	decPool = sync.Pool{
		New: func() any {
			return codec.NewDecoder(nil, &jsonHandle)
		},
	}
)

// GetEncoder returns an encoder configured to write to w.
func getEncoder(w io.Writer) Encoder {
	e := encPool.Get().(*codec.Encoder)
	e.Reset(w)
	return e
}

// PutEncoder returns an encoder to the pool.
func putEncoder(v Encoder) {
	e := v.(*codec.Encoder)
	e.Reset(nil)
	encPool.Put(e)
}

// GetDecoder returns a decoder configured to read from r.
func getDecoder(r io.Reader) Decoder {
	d := decPool.Get().(*codec.Decoder)
	d.Reset(r)
	return d
}

// PutDecoder returns a decoder to the pool.
func putDecoder(v Decoder) {
	d := v.(*codec.Decoder)
	d.Reset(nil)
	decPool.Put(d)
}
