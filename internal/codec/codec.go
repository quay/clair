// Package codec is a unified place for configuring and allocating JSON encoders
// and decoders.
package codec

import (
	"errors"
	"fmt"
	"io"
)

// Encoder encodes.
type Encoder interface {
	Encode(in any) error
}

// Decoder decodes.
type Decoder interface {
	Decode(out any) error
}

// Scheme indicates an API type scheme.
//
// This allows the same program type to have different wire representations.
type Scheme uint

//go:generate go run golang.org/x/tools/cmd/stringer -type Scheme -trimprefix Scheme

const (
	_ Scheme = iota
	// SchemeV1 outputs v1 HTTP API objects for the relevant domain objects.
	SchemeV1
)

// SchemeDefault is the [Scheme] selected when no [Scheme] argument is passed to
// [GetEncoder]/[GetDecoder].
const SchemeDefault = SchemeV1

var _ error = invalidScheme(0)

type invalidScheme Scheme

func (i invalidScheme) Error() string {
	return fmt.Sprintf("programmer error: bad encoding scheme: %v", Scheme(i).String())
}

var errExtraArgs = errors.New("programmer error: multiple extra arguments")

// All the exported functions delegate to an unexported version, which is
// provided by whichever implementation is selected at compile time.

// GetEncoder returns an [Encoder] configured to write to "w".
//
// An optional [Scheme] may be passed to change the encoding scheme.
func GetEncoder(w io.Writer, v ...Scheme) Encoder {
	s := SchemeDefault
	switch len(v) {
	case 0:
	case 1:
		s = v[0]
	default:
		panic(errExtraArgs)
	}
	switch s {
	case SchemeV1:
		return v1Encoder(w)
	}
	panic(invalidScheme(s))
}

// GetDecoder returns a [Decoder] configured to read from "r".
//
// An optional [Scheme] may be passed to change the encoding scheme.
func GetDecoder(r io.Reader, v ...Scheme) Decoder {
	s := SchemeDefault
	switch len(v) {
	case 0:
	case 1:
		s = v[0]
	default:
		panic(errExtraArgs)
	}
	switch s {
	case SchemeV1:
		return v1Decoder(r)
	}
	panic(invalidScheme(s))
}
