package httptransport

import (
	"fmt"
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
	case cfg.Auth.Keyserver != nil:
		cfg := cfg.Auth.Keyserver
		ks, err := auth.NewQuayKeyserver(cfg.API)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize quay keyserver: %v", err)
		}
		checks = append(checks, ks)
		if cfg.Intraservice != nil {
			psk, err := auth.NewPSK(cfg.Intraservice, []string{IntraserviceIssuer})
			if err != nil {
				return nil, fmt.Errorf("failed to initialize quay keyserver: %w", err)
			}
			checks = append(checks, psk)
		}
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
	default:
		return next, nil
	}

	return auth.Handler(next, checks...), nil
}
