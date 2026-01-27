package amqp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/url"
	"sync"

	"github.com/quay/clair/config"
	amqp "github.com/rabbitmq/amqp091-go"
)

// failOver will return the first successful connection made against the provided
// brokers, or an existing connection if not closed.
//
// failOver is safe for concurrent usage.
type failOver struct {
	sync.RWMutex
	conn     *amqp.Connection
	tls      *tls.Config
	exchange *config.Exchange
	uris     []*url.URL
}

// Connection returns an AMQP connection to the first broker which successfully
// handshakes.
func (f *failOver) Connection(ctx context.Context) (*amqp.Connection, error) {
	f.RLock()
	if f.conn != nil && !f.conn.IsClosed() {
		slog.DebugContext(ctx, "reusing connection", "address", f.conn.LocalAddr())
		f.RUnlock()
		return f.conn, nil
	}
	f.RUnlock()

	for _, uri := range f.uris {
		log := slog.With("broker", uri)
		// safe to always call DialTLS per docs:
		// 'DialTLS will use the provided tls.Config when it encounters an amqps:// scheme and will dial a plain connection when it encounters an amqp:// scheme.'
		conn, err := amqp.DialTLS(uri.String(), f.tls)
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			log.InfoContext(ctx, "failed to connect to AMQP broker; attempting next broker",
				"reason", err)
			continue
		}
		ch, err := conn.Channel()
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			log.InfoContext(ctx, "could not obtain initial AMQP channel; attempting next broker",
				"reason", err)
			continue
		}
		// if the name is "" it's the default exchange which
		// cannot be declared.
		if f.exchange.Name != "" {
			err = ch.ExchangeDeclarePassive(
				f.exchange.Name,
				f.exchange.Type,
				f.exchange.Durable,
				f.exchange.AutoDelete,
				// these will not be considered in a passive declare
				false,
				false,
				nil,
			)
			if err != nil {
				if conn != nil {
					conn.Close()
				}
				log.InfoContext(ctx, "could not declare AMQP exchange; attempting next broker",
					"reason", err)
				continue
			}
		}
		ch.Close()

		f.Lock()
		defer f.Unlock()
		// only set our connection if its necessary still
		// if not close the conn to ensure no leak occurs
		if f.conn == nil || f.conn.IsClosed() {
			f.conn = conn
		} else {
			conn.Close()
		}
		return f.conn, nil
	}
	return nil, fmt.Errorf("all failover URIs failed to connect")
}
