package apijson_test

import (
	"bytes"
	"errors"
	"path"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/quay/claircore"
	"golang.org/x/tools/txtar"

	"github.com/quay/clair/v4/httptransport/types/v1"
	"github.com/quay/clair/v4/internal/apijson"
	"github.com/quay/clair/v4/internal/json"
	"github.com/quay/clair/v4/internal/json/jsontext"
)

func TestRoundtrip(t *testing.T) {
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
}

const jsonschemaRoot = `https://clairproject.org/api/http/v1/`

func roundtripFromArchive[T any](t *testing.T) {
	typ := reflect.TypeFor[T]().Name()
	file := path.Join(`testdata`, typ+`.txtar`)
	ar, err := txtar.ParseFile(file)
	if err != nil {
		t.Fatal(err)
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

var options = json.JoinOptions(
	json.DefaultOptionsV2(),
	jsontext.Multiline(false),
	jsontext.SpaceAfterColon(false),
	jsontext.SpaceAfterComma(false),
	json.OmitZeroStructFields(true),
	json.FormatNilMapAsNull(true),
	json.FormatNilSliceAsNull(true),
	apijson.Options,
)

type roundtripTestcase[T any] struct {
	Name string
	In   []byte
	Want []byte
}

func (tc *roundtripTestcase[T]) Run(t *testing.T) {
	s := tc.GetSchema(t)
	var b bytes.Buffer
	var v T
	var err error

	err = json.UnmarshalRead(bytes.NewReader(tc.In), &v, options)
	if err != nil {
		t.Error(err)
	}
	err = json.MarshalWrite(&b, &v, options)
	if err != nil {
		t.Error(err)
	}
	if t.Failed() {
		return
	}

	var got, want map[string]any
	err = errors.Join(json.Unmarshal(b.Bytes(), &got), json.Unmarshal(tc.Want, &want))
	if err != nil {
		t.Error(err)
	}
	which := [2]string{"got", "want"}
	for i, err := range []error{
		s.Validate(got), s.Validate(want),
	} {
		if err != nil {
			t.Errorf("%s: %v", which[i], err)
		}
	}
	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}

func (tc *roundtripTestcase[T]) GetSchema(t testing.TB) *jsonschema.Resolved {
	typ := reflect.TypeFor[T]().Name()
	ref, ok := schemaName[typ]
	if !ok {
		ref = jsonschemaRoot + strings.ToLower(typ) + ".schema.json"
	}
	s, ok := types.SchemaByURL()[ref]
	if !ok {
		t.Fatalf("unknown schema: %v", ref)
	}
	return s
}

var schemaName = map[string]string{
	"IndexReport":         jsonschemaRoot + "index_report.schema.json",
	"VulnerabilityReport": jsonschemaRoot + "vulnerability_report.schema.json",
}
