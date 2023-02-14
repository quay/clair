package httputil

import (
	"errors"
	"net"
	"testing"
)

func TestLocalOnly(t *testing.T) {
	tt := []struct {
		Network string
		Addr    string
		Err     *net.AddrError
	}{
		{
			Network: "tcp4",
			Addr:    "192.168.0.1:443",
			Err:     nil,
		},
		{
			Network: "tcp4",
			Addr:    "127.0.0.1:443",
			Err:     nil,
		},
		{
			Network: "tcp6",
			Addr:    "[fe80::]:443",
			Err:     nil,
		},
		{
			Network: "tcp4",
			Addr:    "8.8.8.8:443",
			Err: &net.AddrError{
				Addr: "tcp4!8.8.8.8:443",
				Err:  "disallowed by policy",
			},
		},
		{
			Network: "tcp6",
			Addr:    "[2000::]:443",
			Err: &net.AddrError{
				Addr: "tcp6![2000::]:443",
				Err:  "disallowed by policy",
			},
		},
	}
	for _, tc := range tt {
		t.Logf("%s!%s", tc.Network, tc.Addr)
		var nErr *net.AddrError
		got := ctlLocalOnly(tc.Network, tc.Addr, nil)
		if errors.As(got, &nErr) {
			if tc.Err.Err != nErr.Err || tc.Err.Addr != nErr.Addr {
				t.Errorf("got: %v, want: %v", got, tc.Err)
			}
		}
	}
}
