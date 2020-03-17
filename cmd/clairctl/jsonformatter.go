package main

import (
	"encoding/json"
	"io"
)

var _ Formatter = (*jsonFormatter)(nil)

// JsonFormatter is a very simple formatter; it just calls
// (*json.Encoder).Encode.
type jsonFormatter struct {
	enc *json.Encoder
	io.Closer
}

func (f *jsonFormatter) Format(r *Result) error {
	return f.enc.Encode(r.Report)
}
