package amqp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"sync"

	"github.com/quay/clair/config"
	"github.com/quay/zlog"
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
	ctx = zlog.ContextWithValues(ctx,
		"component", "notifier/amqp/failOver.Connection")

	f.RLock()
	if f.conn != nil && !f.conn.IsClosed() {
		zlog.Debug(ctx).
			Msg("existing connection exist and is not closed. returning this connection")
		f.RUnlock()
		return f.conn, nil
	}
	f.RUnlock()

	for _, uri := range f.uris {
		ctx := zlog.ContextWithValues(ctx, "broker", uri.String())
		// safe to always call DialTLS per docs:
		// 'DialTLS will use the provided tls.Config when it encounters an amqps:// scheme and will dial a plain connection when it encounters an amqp:// scheme.'
		conn, err := amqp.DialTLS(uri.String(), f.tls)
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			zlog.Info(ctx).
				Msg("failed to connect to AMQP broker. attempting next broker")
			continue
		}
		ch, err := conn.Channel()
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			zlog.Info(ctx).
				Msg("could not obtain initial AMQP channel for passive exchange declare. attempting next broker")
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
				zlog.Info(ctx).
					Msg("could not obtain initial AMQP channel for passive exchange declare. attempting next broker")
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
