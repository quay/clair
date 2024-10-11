package httputil

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/net/publicsuffix"

	"github.com/quay/clair/v4/cmd"
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
		dialer.ControlContext = ctlLocalOnly
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

func ctlLocalOnly(_ context.Context, network, address string, _ syscall.RawConn) error {
	// Now that this has a Context'd version, we could jam a policy engine in
	// here if someone really feeling froggy.
	switch {
	case strings.HasPrefix(network, "tcp"): // OK
	case strings.HasPrefix(network, "udp"): // OK
	case strings.HasPrefix(network, "unix"):
		// Local by definition.
		return nil
	default:
		return &net.AddrError{
			Addr: network + "!" + address,
			Err:  fmt.Sprintf("disallowed by policy: network %q", network),
		}
	}

	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return &net.AddrError{
			Addr: address,
			Err:  fmt.Sprintf("unable to parse address: %v", err),
		}
	}
	switch addr := ap.Addr(); {
	case addr.IsMulticast():
		// Assert this is a unicast address.
		// There was a draft RFC for handling HTTP/3 over multicast QUIC, but it's expired so this seems OK to do.
		return &net.AddrError{
			Addr: ap.String(),
			Err:  "disallowed by policy: address is multicast",
		}
	case addr.IsLoopback(): // OK
	case addr.IsLinkLocalUnicast(): // OK
	case addr.IsPrivate(): // OK
	default:
		return &net.AddrError{
			Addr: ap.String(),
			Err:  "disallowed by policy: not loopback, link-local, or private",
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
