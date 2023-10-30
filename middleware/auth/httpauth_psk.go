package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/quay/zlog"
)

// PSK implements the AuthCheck interface.
//
// When Check is called the JWT on the incoming http request
// will be validated against a pre-shared-key.
type PSK struct {
	key []byte
	iss []string
}

// NewPSK returns an instance of a PSK
func NewPSK(key []byte, issuer []string) (*PSK, error) {
	return &PSK{
		key: key,
		iss: issuer,
	}, nil
}

// Check implements AuthCheck
func (p *PSK) Check(_ context.Context, r *http.Request) bool {
	ctx := zlog.ContextWithValues(r.Context(), "component", "middleware/auth/PSK.Check")

	wt, ok := fromHeader(r)
	if !ok {
		zlog.Debug(ctx).Msg("failed to retrieve jwt from header")
		return false
	}
	tok, err := jwt.ParseSigned(wt)
	if err != nil {
		zlog.Debug(ctx).Err(err).Msg("failed to parse jwt")
		return false
	}
	cl := jwt.Claims{}
	if err := tok.Claims(p.key, &cl); err != nil {
		zlog.Debug(ctx).Err(err).Msg("failed to parse jwt")
		return false
	}

	ctx = zlog.ContextWithValues(ctx, "iss", cl.Issuer)
	if err := cl.ValidateWithLeeway(jwt.Expected{
		Time: time.Now(),
	}, 15*time.Second); err != nil {
		zlog.Debug(ctx).Err(err).Msg("could not validate claims")
		return false
	}

	for i, iss := range p.iss {
		if iss == cl.Issuer {
			break
		}
		if i == len(p.iss)-1 {
			zlog.Debug(ctx).Err(err).Msg("could not verify issuer")
			return false
		}
	}

	return true
}
