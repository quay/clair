package httputil

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/quay/clair/config"
	"github.com/quay/zlog"
)

// NewSigner constructs a signer according to the provided Config and claim.
//
// The returned Signer only adds headers for the hosts specified in the
// following spots:
//
//   - $.notifier.webhook.target
//   - $.notifier.indexer_addr
//   - $.notifier.matcher_addr
//   - $.matcher.indexer_addr
func NewSigner(ctx context.Context, cfg *config.Config, cl jwt.Claims) (*Signer, error) {
	if cfg.Auth.PSK == nil {
		zlog.Debug(ctx).
			Str("component", "internal/httputil/NewSigner").
			Msg("authentication disabled")
		return new(Signer), nil
	}
	s := Signer{
		use:   make(map[string]struct{}),
		claim: cl,
	}
	if cfg.Notifier.Webhook != nil {
		if err := s.Add(ctx, cfg.Notifier.Webhook.Target); err != nil {
			return nil, err
		}
	}
	if err := s.Add(ctx, cfg.Notifier.IndexerAddr); err != nil {
		return nil, err
	}
	if err := s.Add(ctx, cfg.Notifier.MatcherAddr); err != nil {
		return nil, err
	}
	if err := s.Add(ctx, cfg.Matcher.IndexerAddr); err != nil {
		return nil, err
	}

	sk := jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       []byte(cfg.Auth.PSK.Key),
	}
	signer, err := jose.NewSigner(sk, nil)
	if err != nil {
		return nil, err
	}
	s.signer = signer
	if zlog.Debug(ctx).Enabled() {
		as := make([]string, 0, len(s.use))
		for a := range s.use {
			as = append(as, a)
		}
		zlog.Debug(ctx).Strs("authorities", as).
			Msg("enabling signing for authorities")
	}
	return &s, nil
}

// Add marks the authority in "uri" as one that expects signed requests.
func (s *Signer) Add(ctx context.Context, uri string) error {
	if uri == "" {
		return nil
	}
	u, err := url.Parse(uri)
	if err != nil {
		return err
	}
	a := u.Host
	s.use[a] = struct{}{}
	return nil
}

// Signer signs requests.
type Signer struct {
	signer jose.Signer
	use    map[string]struct{}
	claim  jwt.Claims
}

// Sign modifies the passed [http.Request] as needed.
func (s *Signer) Sign(ctx context.Context, req *http.Request) error {
	if s == nil || s.signer == nil {
		return nil
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if _, ok := s.use[host]; !ok {
		return nil
	}
	cl := s.claim
	now := time.Now()
	cl.IssuedAt = jwt.NewNumericDate(now)
	cl.NotBefore = jwt.NewNumericDate(now.Add(-jwt.DefaultLeeway))
	cl.Expiry = jwt.NewNumericDate(now.Add(jwt.DefaultLeeway))
	h, err := jwt.Signed(s.signer).Claims(&cl).CompactSerialize()
	if err != nil {
		return err
	}
	req.Header.Add("authorization", "Bearer "+h)
	return nil
}
