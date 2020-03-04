package auth

import (
	"context"
	"net/http"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
)

// PSK implements the AuthCheck interface.
//
// When Check is called the JWT on the incoming http request
// will be validated against a pre-shared-key.
type PSK struct {
	key []byte
	iss string
}

// NewPSK returns an instance of a PSK
func NewPSK(key []byte, issuer string) (*PSK, error) {
	return &PSK{
		key: key,
		iss: issuer,
	}, nil
}

// Check implements AuthCheck
func (p *PSK) Check(_ context.Context, r *http.Request) bool {
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
