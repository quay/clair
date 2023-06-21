package stomp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/go-stomp/stomp/v3"
	"github.com/google/uuid"
	"github.com/quay/clair/config"
	"github.com/quay/claircore"
	"github.com/quay/claircore/test/integration"
	"github.com/quay/zlog"
	"golang.org/x/sync/errgroup"

	"github.com/quay/clair/v4/notifier"
)

func setURI(t *testing.T, cfg config.STOMP, uri string) (next config.STOMP, dial string, opt []func(*stomp.Conn) error) {
	const (
		defaultStompBrokerURI = "localhost:61613"
	)
	t.Helper()
	switch {
	case uri == "":
		t.Logf("using default broker URI: %q", defaultStompBrokerURI)
		cfg.URIs = append(cfg.URIs, defaultStompBrokerURI)
		return cfg, defaultStompBrokerURI, nil
	case strings.Contains(uri, "://"): // probably a URL
		u, err := url.Parse(uri)
		if err != nil {
			t.Logf("weird test URI: %q: %v", uri, err)
			return setURI(t, cfg, "")
		}
		t.Logf("using broker address: %q", u.Host)
		cfg.URIs = append(cfg.URIs, u.Host)
		t.Logf("using broker vhost: %q", u.Hostname())
		opt = append(opt, stomp.ConnOpt.Host(u.Hostname()))
		if u := u.User; u != nil {
			t.Logf("using login: %q", u.String())
			cfg.Login = &config.Login{
				Login: u.Username(),
			}
			cfg.Login.Passcode, _ = u.Password()
			opt = append(opt, stomp.ConnOpt.Login(cfg.Login.Login, cfg.Login.Passcode))
		}
		return cfg, u.Host, opt
	default:
		t.Logf("using broker URI: %q", uri)
		cfg.URIs = append(cfg.URIs, uri)
		return cfg, uri, nil
	}
}

type logAdapter struct{ *testing.T }

var _ stomp.Logger = logAdapter{}

func (a logAdapter) Debugf(format string, value ...interface{})   { a.Logf(format, value...) }
func (a logAdapter) Infof(format string, value ...interface{})    { a.Logf(format, value...) }
func (a logAdapter) Warningf(format string, value ...interface{}) { a.Logf(format, value...) }
func (a logAdapter) Debug(msg string)                             { a.Log(msg) }
func (a logAdapter) Info(msg string)                              { a.Log(msg) }
func (a logAdapter) Warning(msg string)                           { a.Log(msg) }
func (a logAdapter) Error(msg string)                             { a.T.Error(msg) }

func consumer(ctx context.Context, t *testing.T, dial string, opt []func(*stomp.Conn) error, queue string, ct int, hook func(*testing.T, *stomp.Message)) func() error {
	return func() error {
		conn, err := stomp.Dial("tcp", dial, opt...)
		if err != nil {
			return fmt.Errorf("failed to connect to broker at %q: %w", dial, err)
		}
		defer conn.Disconnect()
		t.Log("consumer: connect OK")

		sub, err := conn.Subscribe(queue, stomp.AckClient)
		if err != nil {
			return fmt.Errorf("failed to subscribe to %q: %w", queue, err)
		}
		defer sub.Unsubscribe()
		t.Log("consumer: subscribe OK")

		// read messages
		for i := 0; i < ct; i++ {
			var m *stomp.Message
			select {
			case m = <-sub.C:
				conn.Ack(m)
			case <-ctx.Done():
				return context.Cause(ctx)
			}
			hook(t, m)
			if t.Failed() {
				return errors.New("hook failed")
			}
		}
		return nil
	}
}

// TestDeliverer confirms a notification
// callback is successfully delivered to the stomp broker.
func TestDeliverer(t *testing.T) {
	t.Parallel()
	// This is only really made to work with RabbitMQ. Previous revisions of the
	// code tested against ActiveMQ, but this was migrated to make the setup
	// simpler.
	integration.Skip(t)
	ctx := zlog.Test(context.Background(), t)
	const (
		callback = "http://clair-notifier/notifier/api/v1/notifications/"
	)

	var (
		queue = `/queue/` + uuid.New().String()
		conf  = config.STOMP{
			Callback:    callback,
			Destination: queue,
			Direct:      false,
			URIs: []string{
				"nohost1:5672", // Put a bogus host in here to hit the failover code.
			},
		}
	)
	conf, dial, opt := setURI(t, conf, os.Getenv("STOMP_CONNECTION_STRING"))
	opt = append(opt, stomp.ConnOpt.Logger(logAdapter{t}))

	// test parallel usage
	eg, ctx := errgroup.WithContext(ctx)
	const n = 4
	eg.Go(consumer(ctx, t, dial, opt, queue, n, func(t *testing.T, m *stomp.Message) {
		if got, want := m.ContentType, "application/json"; got != want {
			t.Errorf("msg content type mismatch: got %q, want %q", got, want)
		}
		var msgBody map[string]string
		if err := json.Unmarshal(m.Body, &msgBody); err != nil {
			t.Errorf("cannot unmarshal msg body into map: %v", err)
		}
		nid, ok := msgBody["notification_id"]
		if !ok {
			t.Error(`cannot find "notification_id" key in msg body`)
		}
		t.Logf("recv note %q", nid)
		cb, ok := msgBody["callback"]
		if !ok {
			t.Error(`cannot find "callback" key in msg body`)
		}
		if got, want := cb, callback+nid; got != want {
			t.Errorf("callback mismatch: got: %q, want: %q", got, want)
		}
	}))
	for i := 0; i < n; i++ {
		eg.Go(func() error {
			noteID := uuid.New()
			d, err := New(&conf)
			if err != nil {
				return fmt.Errorf("could not create deliverer: %v", err)
			}
			// will error if message cannot be delivered to broker
			err = d.Deliver(ctx, noteID)
			if err != nil {
				return fmt.Errorf("failed to deliver message: %v", err)
			}
			t.Logf("sent note %q", noteID)
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		t.Error(err)
	}
}

// TestDirectDeliverer confirms delivery of notifications directly
// to the STOMP queue with rollup works correctly.
func TestDirectDeliverer(t *testing.T) {
	t.Parallel()
	integration.Skip(t)
	ctx := zlog.Test(context.Background(), t)

	table := []struct {
		name         string
		rollup       int
		notes        int
		expectedMsgs int
	}{
		{name: "Rollup0", rollup: 0, notes: 1, expectedMsgs: 1},
		{name: "Rollup1", rollup: 1, notes: 5, expectedMsgs: 5},
		{name: "Overflow", rollup: 10, notes: 5, expectedMsgs: 1},
		{name: "Odds", rollup: 3, notes: 7, expectedMsgs: 3},
		{name: "OddsRollup", rollup: 3, notes: 8, expectedMsgs: 3},
		{name: "OddsNotes", rollup: 4, notes: 7, expectedMsgs: 2},
		{name: "Large", rollup: 100, notes: 1000, expectedMsgs: 10},
	}

	for _, tt := range table {
		queue := `/queue/` + uuid.New().String()
		t.Run(tt.name, func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			// deliverer test
			conf := config.STOMP{
				Direct:      true,
				Rollup:      tt.rollup,
				Destination: queue,
			}
			conf, dial, opt := setURI(t, conf, os.Getenv("STOMP_CONNECTION_STRING"))

			noteID := uuid.New()
			notes := make([]notifier.Notification, 0, tt.notes)
			for i := 0; i < tt.notes; i++ {
				notes = append(notes, notifier.Notification{
					ID:       uuid.New(),
					Manifest: claircore.MustParseDigest("sha256:35c102085707f703de2d9eaad8752d6fe1b8f02b5d2149f1d8357c9cc7fb7d0a"),
					Reason:   notifier.Added,
					Vulnerability: notifier.VulnSummary{
						Description: fmt.Sprintf("test-vuln-%d", i),
					},
				})
			}
			t.Logf("created %d notes", len(notes))

			// test parallel usage
			eg, ctx := errgroup.WithContext(ctx)
			const n = 4
			var ct int
			eg.Go(consumer(ctx, t, dial, opt, queue, n*tt.expectedMsgs, func(t *testing.T, m *stomp.Message) {
				if got, want := m.ContentType, "application/json"; got != want {
					t.Errorf("msg content type mismatch: got %q, want %q", got, want)
				}
				var msgBody []notifier.Notification
				if err := json.Unmarshal(m.Body, &msgBody); err != nil {
					t.Errorf("cannot unmarshal msg body into slice of notifications: %v", err)
				}
				rollup := tt.rollup
				if tt.rollup == 0 {
					rollup++
				}
				if got, want := len(msgBody), rollup; got > want {
					t.Errorf("more notes in msg than expected: got %d, want %d", got, want)
				}
				ct += len(msgBody)
			}))
			defer func() {
				got, want := ct, tt.notes*n
				t.Logf("consumer: read notes: got %d, want %d", got, want)
				if got != want {
					t.Fail()
				}
			}()
			for i := 0; i < n; i++ {
				id := i
				eg.Go(func() error {
					d, err := NewDirectDeliverer(&conf)
					if err != nil {
						return fmt.Errorf("could not create deliverer: %w", err)
					}
					t.Logf("deliverer(%d): created %p", id, d)
					if err := d.Notifications(ctx, notes); err != nil {
						return fmt.Errorf("failed to provide notifications to direct deliverer: %w", err)
					}
					t.Logf("deliverer(%d): added %d notes", id, len(notes))
					if err := d.Deliver(ctx, noteID); err != nil {
						return fmt.Errorf("failed to deliver message: %w", err)
					}
					t.Logf("deliverer(%d): delivered", id)
					return nil
				})
			}
			if err := eg.Wait(); err != nil {
				t.Error(err)
			}
		})
	}
}
