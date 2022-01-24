package config_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"testing/quick"

	"github.com/google/go-cmp/cmp"

	"github.com/quay/clair/config"
)

func TestBase64(t *testing.T) {
	roundtrip := func(in []byte) bool {
		b1 := config.Base64(in)
		txt, err := b1.MarshalText()
		if err != nil {
			return false
		}
		out := new(config.Base64)
		if err := out.UnmarshalText(txt); err != nil {
			return false
		}
		return bytes.Equal(in, []byte(*out))
	}
	if err := quick.Check(roundtrip, nil); err != nil {
		t.Error(err)
	}
}

func TestAuthUnmarshal(t *testing.T) {
	t.Run("PSK", func(t *testing.T) {
		type testcase struct {
			In   string
			Want config.AuthPSK
		}
		tt := []testcase{
			{
				In: `{"key":"ZGVhZGJlZWZkZWFkYmVlZg==","iss":["iss"]}`,
				Want: config.AuthPSK{
					Key:    []byte("deadbeefdeadbeef"),
					Issuer: []string{"iss"},
				},
			},
		}

		check := func(t *testing.T, tc testcase) {
			v := config.AuthPSK{}
			if err := json.Unmarshal([]byte(tc.In), &v); err != nil {
				t.Error(err)
			}
			if got, want := v, tc.Want; !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
		}
		for _, tc := range tt {
			check(t, tc)
		}
	})

	t.Run("Keyserver", func(t *testing.T) {
		type testcase struct {
			In   string
			Want config.AuthKeyserver
		}
		tt := []testcase{
			{
				In: `{"api":"quay/keys","intraservice":"ZGVhZGJlZWZkZWFkYmVlZg=="}`,
				Want: config.AuthKeyserver{
					API:          "quay/keys",
					Intraservice: []byte("deadbeefdeadbeef"),
				},
			},
		}

		check := func(t *testing.T, tc testcase) {
			v := config.AuthKeyserver{}
			if err := json.Unmarshal([]byte(tc.In), &v); err != nil {
				t.Error(err)
			}
			if got, want := v, tc.Want; !cmp.Equal(got, want) {
				t.Error(cmp.Diff(got, want))
			}
		}
		for _, tc := range tt {
			check(t, tc)
		}
	})
}

func TestAuthMarshal(t *testing.T) {
	want := `{"key":"ZGVhZGJlZWZkZWFkYmVlZg==","iss":["iss"]}`
	in := config.AuthPSK{
		Key:    []byte("deadbeefdeadbeef"),
		Issuer: []string{"iss"},
	}
	gotb, err := json.Marshal(in)
	if err != nil {
		t.Error(err)
	}
	if got := string(gotb); !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}
