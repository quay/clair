package httputil

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLocalOnly(t *testing.T) {
	tt := []struct {
		Network string
		Addr    string
		Err     *net.AddrError
	}{
		{Network: "tcp4", Addr: "192.168.0.1:443"},
		{Network: "tcp4", Addr: "10.0.0.1:80"},
		{Network: "tcp4", Addr: "127.0.0.1:443"},
		{Network: "tcp6", Addr: "[fe80::]:443"},
		{Network: "unix", Addr: "/run/sock"},
		{
			Network: "ip6",
			Addr:    "::1",
			Err: &net.AddrError{
				Addr: "ip6!::1",
				Err:  `disallowed by policy: network "ip6"`,
			},
		},
		{
			Network: "tcp4",
			Addr:    "127.256:443",
			Err: &net.AddrError{
				Addr: "127.256:443",
				Err:  `unable to parse address: ParseAddr("127.256"): IPv4 field has value >255`,
			},
		},
		{
			Network: "tcp4",
			Addr:    "224.0.0.1:443",
			Err: &net.AddrError{
				Addr: "224.0.0.1:443",
				Err:  "disallowed by policy: address is multicast",
			},
		},
		{
			Network: "tcp4",
			Addr:    "8.8.8.8:443",
			Err: &net.AddrError{
				Addr: "8.8.8.8:443",
				Err:  "disallowed by policy: not loopback, link-local, or private",
			},
		},
		{
			Network: "tcp6",
			Addr:    "[2000::]:443",
			Err: &net.AddrError{
				Addr: "[2000::]:443",
				Err:  "disallowed by policy: not loopback, link-local, or private",
			},
		},
	}
	// CtlLocalOnly doesn't emit logs, don't bother with zlog.
	ctx := context.Background()
	for _, tc := range tt {
		t.Logf("%s!%s", tc.Network, tc.Addr)
		var got *net.AddrError
		err := ctlLocalOnly(ctx, tc.Network, tc.Addr, nil)
		switch {
		case err == nil:
		case !errors.As(err, &got):
			t.Errorf("returned error not *net.AddrError, is %T", got)
			continue
		}
		if want := tc.Err; !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	}
}
