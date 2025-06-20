//go:build go1.25 && goexperiment.jsonv2

package codec

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
)

// The interface built on json/v2 does not use its own pool and instead relies
// on the json package's pooling.

var options = json.JoinOptions(
	json.DefaultOptionsV2(),
	jsontext.Multiline(false),
	jsontext.SpaceAfterColon(false),
	jsontext.SpaceAfterComma(false),
	json.OmitZeroStructFields(true),
	json.FormatNilMapAsNull(true),
	json.FormatNilSliceAsNull(true),
)

type fwdWriter struct {
	io.Writer
}

func (w fwdWriter) Encode(in any) error {
	return json.MarshalWrite(w.Writer, in, options)
}

type fwdReader struct {
	io.Reader
}

func (r fwdReader) Decode(out any) error {
	return json.UnmarshalRead(r.Reader, out, options)
}

// GetEncoder returns an encoder configured to write to w.
func getEncoder(w io.Writer) Encoder { return fwdWriter{w} }

func putEncoder(v Encoder) {}

// GetDecoder returns a decoder configured to read from r.
func getDecoder(r io.Reader) Decoder { return fwdReader{r} }

func putDecoder(v Decoder) {}
