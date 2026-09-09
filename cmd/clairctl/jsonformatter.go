package main

import (
	"io"

	"github.com/quay/clair/v4/internal/codec"
)

var _ Formatter = (*jsonFormatter)(nil)

// JsonFormatter outputs JSON.
type jsonFormatter struct {
	enc codec.Encoder
	c   io.Closer
}

func (f *jsonFormatter) Format(r *Result) error {
	return f.enc.Encode(r.Report)
}

func (f *jsonFormatter) Close() error {
	return f.c.Close()
}
