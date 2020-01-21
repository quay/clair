package main

import (
	"context"
	"net/http"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
)

type psk struct {
	key []byte
	iss string
}

func (p *psk) Check(_ context.Context, r *http.Request) bool {
	wt, ok := fromHeader(r)
	if !ok {
		return false
	}
	tok, err := jwt.ParseSigned(wt)
	if err != nil {
		return false
	}
	cl := jwt.Claims{}
	if err := tok.Claims(p.key, &cl); err != nil {
		return false
	}
	if err := cl.ValidateWithLeeway(jwt.Expected{
		Issuer: p.iss,
		Time:   time.Now(),
	}, 15*time.Second); err != nil {
		return false
	}
	return true
}

// PSKAuth returns an AuthCheck that validates a JWT with the supplied key and
// ensures the issuer claim matches.
func PSKAuth(key []byte, issuer string) (AuthCheck, error) {
	return &psk{
		key: key,
		iss: issuer,
	}, nil
}
