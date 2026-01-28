package auth

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
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
func (p *PSK) Check(ctx context.Context, r *http.Request) bool {
	wt, ok := fromHeader(r)
	if !ok {
		slog.DebugContext(ctx, "failed to retrieve jwt from header")
		return false
	}
	tok, err := jwt.ParseSigned(wt)
	if err != nil {
		slog.DebugContext(ctx, "failed to parse jwt", "reason", err)
		return false
	}
	cl := jwt.Claims{}
	if err := tok.Claims(p.key, &cl); err != nil {
		slog.DebugContext(ctx, "failed to parse jwt", "reason", err)
		return false
	}

	log := slog.With("iss", cl.Issuer)
	if err := cl.ValidateWithLeeway(jwt.Expected{
		Time: time.Now(),
	}, 15*time.Second); err != nil {
		log.DebugContext(ctx, "could not validate claims", "reason", err)
		return false
	}

	for i, iss := range p.iss {
		if iss == cl.Issuer {
			break
		}
		if i == len(p.iss)-1 {
			slog.DebugContext(ctx, "could not verify issuer", "reason", err)
			return false
		}
	}

	return true
}
