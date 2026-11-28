package httputil

import (
	"context"
	"github.com/quay/clair/config"
	"github.com/quay/zlog"
	"gopkg.in/square/go-jose.v2/jwt"
	"testing"
)

func TestNewSigner(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)
	cfg := config.Config{}
	signer, err := NewSigner(ctx, &cfg, jwt.Claims{})
	if err != nil {
		t.Error("signer initialization with empty config should succeed")
	}
	if signer.use != nil {
		t.Error("signed request authority map should be non-initialized")
	}
	err = signer.Add(ctx, "http://test-url")
	if err == nil {
		t.Error("Adding host to non-initialized signed request authority map should fail")
	}
}
