package stomp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	gostomp "github.com/go-stomp/stomp/v3"
	"github.com/quay/clair/config"
	"github.com/quay/zlog"
)

// failOver will return the first successful connection made against the provided
// brokers, or an existing connection if not closed.
//
// failOver is safe for concurrent usage.
type failOver struct {
	tls     *tls.Config
	login   *config.Login
	addrs   []string
	timeout time.Duration
}

// Dial will dial the provided address in accordance with the provided Config.
//
// Note: the STOMP protocol does not support multiplexing operations over a
// single TCP connection. A TCP connection must be made for each STOMP
// connection.
func (f *failOver) Dial(ctx context.Context, addr string) (*gostomp.Conn, error) {
	var opts []func(*gostomp.Conn) error
	if f.login != nil {
		opts = append(opts, gostomp.ConnOpt.Login(f.login.Login, f.login.Passcode))
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		opts = append(opts, gostomp.ConnOpt.Host(host))
	}

	var d interface {
		DialContext(context.Context, string, string) (net.Conn, error)
	} = &net.Dialer{
		Timeout: f.timeout,
	}
	if f.tls != nil {
		d = &tls.Dialer{
			NetDialer: d.(*net.Dialer),
			Config:    f.tls,
		}
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to broker @ %v: %w", addr, err)
	}

	stompConn, err := gostomp.Connect(conn, opts...)
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, fmt.Errorf("stomp connect handshake to broker @ %v failed: %w", addr, err)
	}

	return stompConn, err
}

// Connection returns a new connection to the first broker that successfully
// handshakes.
//
// The caller MUST call conn.Disconnect() to close the underlying TCP connection
// when finished.
func (f *failOver) Connection(ctx context.Context) (*gostomp.Conn, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "notifier/stomp/failOver.Connection")

	for _, addr := range f.addrs {
		conn, err := f.Dial(ctx, addr)
		if err != nil {
			zlog.Debug(ctx).
				Str("broker", addr).
				Err(err).
				Msg("failed to dial broker, attempting next")
			continue
		}
		return conn, nil
	}
	return nil, fmt.Errorf("exhausted all brokers and unable to make connection")
}
