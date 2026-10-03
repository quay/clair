package codec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func Example() {
	enc := GetEncoder(os.Stdout)
	enc.Encode([]string{"a", "slice", "of", "strings"})
	fmt.Fprintln(os.Stdout)
	enc.Encode(nil)
	fmt.Fprintln(os.Stdout)
	enc.Encode(map[string]string{})
	fmt.Fprintln(os.Stdout)
	// Output: ["a","slice","of","strings"]
	// null
	// {}
}

func BenchmarkDecode(b *testing.B) {
	b.ReportAllocs()
	want := map[string]string{
		"a": strings.Repeat(`A`, 2048),
		"b": strings.Repeat(`B`, 2048),
		"c": strings.Repeat(`C`, 2048),
		"d": strings.Repeat(`D`, 2048),
	}
	got := make(map[string]string, len(want))

	for b.Loop() {
		dec := GetDecoder(JSONReader(want))
		err := dec.Decode(&got)
		if err != nil {
			b.Error(err)
		}
		if !cmp.Equal(got, want) {
			b.Error(cmp.Diff(got, want))
		}
	}
}

func BenchmarkDecodeStdlib(b *testing.B) {
	b.ReportAllocs()
	want := map[string]string{
		"a": strings.Repeat(`A`, 2048),
		"b": strings.Repeat(`B`, 2048),
		"c": strings.Repeat(`C`, 2048),
		"d": strings.Repeat(`D`, 2048),
	}
	got := make(map[string]string, len(want))

	for b.Loop() {
		x, err := json.Marshal(want)
		if err != nil {
			b.Error(err)
		}
		if err := json.Unmarshal(x, &got); err != nil {
			b.Error(err)
		}
		if !cmp.Equal(got, want) {
			b.Error(cmp.Diff(got, want))
		}
	}
}

func TestTimeNotNull(t *testing.T) {
	type s struct {
		Time time.Time
	}
	var b bytes.Buffer
	enc := GetEncoder(&b)

	// Example encoding of a populated time:
	if err := enc.Encode(s{Time: time.Unix(0, 0).UTC()}); err != nil {
		t.Error(err)
	}
	t.Log(b.String())
	b.Reset()

	// Now encode a zero time and make sure it's a string.
	if err := enc.Encode(s{}); err != nil {
		t.Error(err)
	}
	t.Log(b.String())
	if strings.Contains(b.String(), "null") {
		t.Error("wanted non-null encoding")
	}
}

func TestScheme(t *testing.T) {
	t.Logf("Default: %v", SchemeDefault)
	t.Run("Decoder", func(t *testing.T) {
		t.Run("Implicit", func(t *testing.T) {
			dec := GetDecoder(bytes.NewBufferString(`true`))
			var got bool
			if err := dec.Decode(&got); err != nil {
				t.Error(err)
			}
			if want := true; got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
		t.Run("Explicit", func(t *testing.T) {
			dec := GetDecoder(bytes.NewBufferString(`true`), SchemeV1)
			var got bool
			if err := dec.Decode(&got); err != nil {
				t.Error(err)
			}
			if want := true; got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
		t.Run("TooManyArgs", func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Error("expected panic")
					return
				}
				err, ok := r.(error)
				if !ok {
					t.Error("expected to recover an error")
					return
				}
				t.Log(err)
				if !errors.Is(err, errExtraArgs) {
					t.Error("unexpected recover")
				}
			}()
			GetDecoder(bytes.NewBufferString(`true`), SchemeV1, SchemeV1)
		})
		t.Run("Invalid", func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Error("expected panic")
					return
				}
				err, ok := r.(error)
				if !ok {
					t.Error("expected to recover an error")
					return
				}
				t.Log(err)
				var invalid invalidScheme
				if !errors.As(err, &invalid) {
					t.Error("unexpected recover")
				}
			}()
			GetDecoder(bytes.NewBufferString(`true`), Scheme(999))
		})
	})
	t.Run("Encoder", func(t *testing.T) {
		t.Run("Implicit", func(t *testing.T) {
			var buf bytes.Buffer
			enc := GetEncoder(&buf, SchemeV1)
			if err := enc.Encode(true); err != nil {
				t.Error(err)
			}
			if got, want := buf.String(), "true"; got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
		t.Run("Explicit", func(t *testing.T) {
			var buf bytes.Buffer
			enc := GetEncoder(&buf)
			if err := enc.Encode(true); err != nil {
				t.Error(err)
			}
			if got, want := buf.String(), "true"; got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
		t.Run("TooManyArgs", func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Error("expected panic")
					return
				}
				err, ok := r.(error)
				if !ok {
					t.Error("expected to recover an error")
					return
				}
				t.Log(err)
				if !errors.Is(err, errExtraArgs) {
					t.Error("unexpected recover")
				}
			}()
			GetEncoder(io.Discard, SchemeV1, SchemeV1)
		})
		t.Run("Invalid", func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Error("expected panic")
					return
				}
				err, ok := r.(error)
				if !ok {
					t.Error("expected to recover an error")
					return
				}
				t.Log(err)
				var invalid invalidScheme
				if !errors.As(err, &invalid) {
					t.Error("unexpected recover")
				}
			}()
			GetEncoder(io.Discard, Scheme(999))
		})
	})
}
