package httputil

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/quay/clair/v4/cmd"
	"golang.org/x/net/publicsuffix"
)

// NewClient constructs an [http.Client] that disallows access to public
// networks, controlled by the localOnly flag.
//
// If disallowed, the reported error will be a [*net.AddrError] with the "Err"
// value of "disallowed by policy".
func NewClient(ctx context.Context, localOnly bool) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	dialer := &net.Dialer{}
	// Set a control function if we're restricting subnets.
	if localOnly {
		dialer.Control = ctlLocalOnly
	}
	tr.DialContext = dialer.DialContext

	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: tr,
		Jar:       jar,
	}, nil
}

func ctlLocalOnly(network, address string, _ syscall.RawConn) error {
	// Future-proof for QUIC by allowing UDP here.
	if !strings.HasPrefix(network, "tcp") && !strings.HasPrefix(network, "udp") {
		return &net.AddrError{
			Addr: network + "!" + address,
			Err:  "disallowed by policy",
		}
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return &net.AddrError{
			Addr: network + "!" + address,
			Err:  "martian address",
		}
	}
	addr := net.ParseIP(host)
	if addr == nil {
		return &net.AddrError{
			Addr: network + "!" + address,
			Err:  "martian address",
		}
	}
	if !addr.IsPrivate() &&
		!addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() {
		return &net.AddrError{
			Addr: network + "!" + address,
			Err:  "disallowed by policy",
		}
	}
	return nil
}

// NewRequestWithContext is a wrapper around [http.NewRequestWithContext] that
// sets some defaults in the returned request.
func NewRequestWithContext(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	// The one OK use of the normal function.
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	p, err := os.Executable()
	if err != nil {
		p = `clair?`
	} else {
		p = filepath.Base(p)
	}
	req.Header.Set("user-agent", fmt.Sprintf("%s/%s", p, cmd.Version))
	return req, nil
}
