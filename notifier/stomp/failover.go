package stomp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"

	gostomp "github.com/go-stomp/stomp"
	"github.com/rs/zerolog"
)

// failOver will return the first successful connection made against the provided
// brokers, or an existing connection if not closed.
//
// failOver is safe for concurrent usage.
type failOver struct {
	Config
}

// Dial will dial the provided uri in accordance with the
// provided Config.
//
// Note: the STOMP protocol does not support multiplexing
// operations over a single tcp connection.
// A tcp connection must be made for each STOMP connection.
func (f *failOver) Dial(uri string) (*gostomp.Conn, error) {
	opts := []func(*gostomp.Conn) error{}

	if f.Login != nil {
		opts = append(opts, gostomp.ConnOpt.Login(f.Login.Login, f.Login.Passcode))
	}

	var conn io.ReadWriteCloser
	var err error
	if f.tls != nil {
		conn, err = tls.Dial("tcp", uri, f.tls)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to tls broker @ %v: %v", uri, err)
		}
	} else {
		conn, err = net.Dial("tcp", uri)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to broker @ %v: %v", uri, err)
		}
	}

	stompConn, err := gostomp.Connect(conn, opts...)
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, fmt.Errorf("stomp connect handshake to broker @ %v failed: %v", uri, err)
	}

	return stompConn, err
}

// Connection returns a new connection to the first successfully handshook broker.
//
// f's Config field must have it's Validate() method called before this method is used.
//
// The caller MUST call conn.Disconnect() to close the underlying tcp connection
// when finished.
func (f *failOver) Connection(ctx context.Context) (*gostomp.Conn, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "notifier/stomp/failover").
		Logger()
	ctx = log.WithContext(ctx)

	for _, uri := range f.URIs {
		conn, err := f.Dial(uri)
		if err != nil {
			log.Debug().Str("broker", uri).Msg("failed to dial broker. attempting next")
			continue
		}
		return conn, nil
	}
	return nil, fmt.Errorf("exhausted all brokers and unable to make connection.")
}
