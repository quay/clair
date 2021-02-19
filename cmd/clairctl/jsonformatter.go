package main

import (
	"io"

	"github.com/quay/clair/v4/internal/codec"
)

var _ Formatter = (*jsonFormatter)(nil)

// JsonFormatter is a very simple formatter; it just calls
// (*json.Encoder).Encode.
type jsonFormatter struct {
	enc *codec.Encoder
	c   io.Closer
}

func (f *jsonFormatter) Format(r *Result) error {
	return f.enc.Encode(r.Report)
}
func (f *jsonFormatter) Close() error {
	codec.PutEncoder(f.enc)
	return f.c.Close()
}
