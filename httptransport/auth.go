package httptransport

import (
	"errors"
	"net/http"

	"github.com/quay/clair/config"

	"github.com/quay/clair/v4/middleware/auth"
)

// AuthHandler returns an http.Handler wrapping the provided Handler, as
// described by the provided Config.
func authHandler(cfg *config.Config, next http.Handler) (http.Handler, error) {
	var checks []auth.Checker

	// Keep this ordered "best" to "worst".
	switch {
	case cfg.Auth.PSK != nil:
		cfg := cfg.Auth.PSK
		issuers := make([]string, 0, 1+len(cfg.Issuer))
		issuers = append(issuers, IntraserviceIssuer)
		issuers = append(issuers, cfg.Issuer...)

		psk, err := auth.NewPSK(cfg.Key, issuers)
		if err != nil {
			return nil, err
		}
		checks = append(checks, psk)
	case cfg.Auth.Keyserver != nil:
		return nil, errors.New("quay keyserver support has been removed")
	default:
		return next, nil
	}

	return auth.Handler(next, checks...), nil
}
