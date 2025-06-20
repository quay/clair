package codec

import (
	"io"

	"github.com/quay/clair/v4/internal/apijson"
	"github.com/quay/clair/v4/internal/json"
	"github.com/quay/clair/v4/internal/json/jsontext"
)

// SchemeV1Options is the set of [json.Options] used with [SchemeV1].
var SchemeV1Options = json.JoinOptions(
	json.DefaultOptionsV2(),
	jsontext.Multiline(false),
	jsontext.SpaceAfterColon(false),
	jsontext.SpaceAfterComma(false),
	json.OmitZeroStructFields(true),
	json.FormatNilMapAsNull(true),
	json.FormatNilSliceAsNull(true),
	apijson.Options,
)

func v1Encoder(w io.Writer) Encoder {
	return &fwdWriter{w: w}
}

type fwdWriter struct {
	w io.Writer
}

// Encode implements [Encoder].
func (w *fwdWriter) Encode(in any) error {
	return json.MarshalWrite(w.w, in, SchemeV1Options)
}

func v1Decoder(r io.Reader) Decoder {
	return &fwdReader{r}
}

type fwdReader struct {
	r io.Reader
}

// Decode implements [Decoder].
func (r *fwdReader) Decode(out any) error {
	return json.UnmarshalRead(r.r, out, SchemeV1Options)
}
