package codec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/kaptinlin/jsonschema"
	"github.com/quay/claircore"
	"golang.org/x/tools/txtar"

	"github.com/quay/clair/v4/httptransport/types/v1"
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
			t.Skip("TODO")
		})
		t.Run("Explicit", func(t *testing.T) {
			t.Skip("TODO")
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

func TestCustom(t *testing.T) {
	t.Run("Roundtrip", func(t *testing.T) {
		roundtripFromArchive[claircore.Manifest](t)
		roundtripFromArchive[claircore.Layer](t)
		roundtripFromArchive[claircore.Package](t)
		roundtripFromArchive[claircore.Distribution](t)
		roundtripFromArchive[claircore.Repository](t)
		roundtripFromArchive[claircore.Environment](t)
		roundtripFromArchive[claircore.Vulnerability](t)
		roundtripFromArchive[claircore.Range](t)
		roundtripFromArchive[claircore.IndexReport](t)
		roundtripFromArchive[claircore.VulnerabilityReport](t)
	})
}

const jsonschemaRoot = `https://clairproject.org/api/http/v1/`

var jsonschemaCompiler = sync.OnceValue(func() *jsonschema.Compiler {
	loaderFunc := func(u string) (io.ReadCloser, error) {
		if strings.HasPrefix(u, jsonschemaRoot) {
			return types.Schema.Open(path.Base(u))
		}
		return nil, errors.ErrUnsupported
	}
	return jsonschema.GetDefaultCompiler().
		SetDefaultBaseURI(jsonschemaRoot).
		RegisterLoader(`http`, loaderFunc).
		RegisterLoader(`https`, loaderFunc)
})

func roundtripFromArchive[T any](t *testing.T) {
	typ := reflect.TypeFor[T]().Name()
	file := path.Join(`testdata`, typ+`.txtar`)
	ar, err := txtar.ParseFile(file)
	if err != nil {
		t.Skip(err)
	}
	var testnames []string
	for _, f := range ar.Files {
		n := f.Name
		n = strings.TrimSuffix(n, ".in.json")
		n = strings.TrimSuffix(n, ".want.json")
		testnames = append(testnames, n)
	}
	slices.Sort(testnames)
	testnames = slices.Compact(testnames)
	var tcs []roundtripTestcase[T]

	for _, n := range testnames {
		var tc roundtripTestcase[T]
		tc.Name = n
		for _, f := range ar.Files {
			switch strings.TrimPrefix(f.Name, n) {
			case ".in.json":
				tc.In = f.Data
			case ".want.json":
				tc.Want = f.Data
			default:
			}
		}
		if tc.In != nil && tc.Want != nil {
			tcs = append(tcs, tc)
		}
	}

	t.Run(typ, func(t *testing.T) {
		if len(tcs) == 0 {
			t.Skip("no fixtures found")
		}
		t.Log("found tests:", strings.Join(testnames, ", "))
		for _, tc := range tcs {
			t.Run(tc.Name, tc.Run)
		}
	})
}

type roundtripTestcase[T any] struct {
	Name string
	In   []byte
	Want []byte
}

func (tc *roundtripTestcase[T]) Run(t *testing.T) {
	s := tc.GetSchema(t)
	var b bytes.Buffer
	func() {
		var v T
		dec := GetDecoder(bytes.NewReader(tc.In))
		if err := dec.Decode(&v); err != nil {
			t.Error(err)
		}

		enc := GetEncoder(&b)
		if err := enc.Encode(&v); err != nil {
			t.Error(err)
		}
	}()
	if t.Failed() {
		return
	}

	var got, want map[string]any
	err := errors.Join(json.Unmarshal(b.Bytes(), &got), json.Unmarshal(tc.Want, &want))
	if err != nil {
		t.Error(err)
	}
	which := [2]string{"got", "want"}
	for i, res := range []*jsonschema.EvaluationResult{
		s.ValidateMap(got), s.ValidateMap(want),
	} {
		if res.Valid {
			continue
		}
		for k, v := range res.Errors {
			t.Errorf("%s: %s: %v", which[i], k, v)
		}
	}
	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}

func (tc *roundtripTestcase[T]) GetSchema(t *testing.T) *jsonschema.Schema {
	typ := reflect.TypeFor[T]().Name()
	ref, ok := schemaName[typ]
	if !ok {
		ref = jsonschemaRoot + strings.ToLower(typ) + ".schema.json"
	}
	s, err := jsonschemaCompiler().GetSchema(ref)
	if err != nil {
		t.Fatalf("unable to get schema for %q (%q): %v", typ, ref, err)
	}
	return s
}

var schemaName = map[string]string{
	"IndexReport":         jsonschemaRoot + "index_report.schema.json",
	"VulnerabilityReport": jsonschemaRoot + "vulnerability_report.schema.json",
}
