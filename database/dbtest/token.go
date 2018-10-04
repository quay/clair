package dbtest

import "github.com/coreos/clair/pkg/pagination"

type MockPage struct {
	StartID int64
}

func MustUnmarshalToken(key pagination.Key, token pagination.Token) MockPage {
	if token == pagination.FirstPageToken {
		return MockPage{}
	}

	p := MockPage{}
	if err := key.UnmarshalToken(token, &p); err != nil {
		panic(err)
	}

	return p
}

func MustMarshalToken(key pagination.Key, v interface{}) pagination.Token {
	token, err := key.MarshalToken(v)
	if err != nil {
		panic(err)
	}

	return token
}
