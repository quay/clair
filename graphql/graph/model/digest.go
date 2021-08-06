package model

import (
	"errors"
	"io"

	"github.com/99designs/gqlgen/graphql"
	"github.com/quay/claircore"
)

func MarshalDigest(d claircore.Digest) graphql.Marshaler {
	return graphql.WriterFunc(func(w io.Writer) {
		io.WriteString(w, d.String())
	})
}

func UnmarshalDigest(v interface{}) (claircore.Digest, error) {
	s, ok := v.(string)
	if !ok {
		return claircore.Digest{}, errors.New("id must be passed as string")
	}
	return claircore.ParseDigest(s)
}
