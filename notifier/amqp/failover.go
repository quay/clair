package amqp

import (
	"context"
	"fmt"
	"sync"

	"github.com/rs/zerolog"
	samqp "github.com/streadway/amqp"
)

// failOver will return the first successful connection made against the provided
// brokers, or an existing connection if not closed.
//
// failOver is safe for concurrent usage.
type failOver struct {
	Config
	sync.RWMutex
	conn *samqp.Connection
}

// Connection returns an AMQP connection to the first broker which successfully
// handshakes.
//
// f's Config field must have it's Validate() method called before this method
// is used.
func (f *failOver) Connection(ctx context.Context) (*samqp.Connection, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "notifier/amqp/failover").
		Logger()
	ctx = log.WithContext(ctx)

	f.RLock()
	if f.conn != nil && !f.conn.IsClosed() {
		log.Debug().Msg("existing connection exist and is not closed. returning this connection")
		f.RUnlock()
		return f.conn, nil
	}
	f.RUnlock()

	for _, uri := range f.URIs {
		// safe to always call DialTLS per docs:
		// 'DialTLS will use the provided tls.Config when it encounters an amqps:// scheme and will dial a plain connection when it encounters an amqp:// scheme.'
		conn, err := samqp.DialTLS(uri, f.tls)
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			log.Info().Str("broker", uri).Msg("failed to connect to AMQP broker. attempting next broker")
			continue
		}
		ch, err := conn.Channel()
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			log.Info().Str("broker", uri).Msg("could not obtain initial AMQP channel for passive exchange declare. attempting next broker")
			continue
		}
		// if the name is "" it's the default exchange which
		// cannot be declared.
		if f.Exchange.Name != "" {
			err = ch.ExchangeDeclarePassive(
				f.Exchange.Name,
				f.Exchange.Type,
				f.Exchange.Durable,
				f.Exchange.AutoDelete,
				// these will not be considered in a passive declare
				false,
				false,
				nil,
			)
			if err != nil {
				if conn != nil {
					conn.Close()
				}
				log.Info().Str("broker", uri).Msg("could not obtain initial AMQP channel for passive exchange declare. attempting next broker")
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
