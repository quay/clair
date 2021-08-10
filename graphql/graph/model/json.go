package model

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/99designs/gqlgen/graphql"
)

func MarshalJSONObject(m json.RawMessage) graphql.Marshaler {
	return graphql.WriterFunc(func(w io.Writer) { w.Write(m) })
}

func UnmarshalJSONObject(v interface{}) (json.RawMessage, error) {
	return nil, errors.New("unacceptable input")
}
