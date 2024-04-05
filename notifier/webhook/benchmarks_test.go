package webhook

import (
	stdjson "encoding/json"
	"io"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/quay/clair/v4/internal/codec"
	"github.com/quay/clair/v4/internal/json"
	"github.com/quay/clair/v4/notifier"
)

func BenchmarkEncodingJSON(b *testing.B) {
	enc := stdjson.NewEncoder(io.Discard)
	obj := notifier.Callback{
		NotificationID: uuid.New(),
	}
	if err := obj.Callback.UnmarshalBinary([]byte("http://example.com/")); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := enc.Encode(&obj)
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkCodecJSON(b *testing.B) {
	enc := codec.GetEncoder(io.Discard)
	obj := notifier.Callback{
		NotificationID: uuid.New(),
	}
	if err := obj.Callback.UnmarshalBinary([]byte("http://example.com/")); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := enc.Encode(&obj)
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkExperimentalJSON(b *testing.B) {
	id := uuid.New()
	url, err := url.Parse("http://example.com")
	if err != nil {
		b.Fatal(err)
	}
	obj := callbackRequest{
		ID:  &id,
		URL: url,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := json.MarshalWrite(io.Discard, &obj, options())
		if err != nil {
			b.Error(err)
		}
	}
}
