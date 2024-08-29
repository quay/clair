//go:build go1.23

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

func (a *App) SetQuayGABIAuth(s string) error {
	if s == "" {
		return errors.New("bad Quay GABI auth: empty string")
	}
	a.QuayGABIAuth = &s
	return nil
}

func (a *App) SetQuayGABI(s string) (err error) {
	a.QuayGABI, err = url.Parse(s)
	return err
}

func (a *App) SetQuayConfig(s string) error {
	slog.Debug("quay config flag", "argument", s)
	a.QuayConfig = new(quayConfig)
	f, err := os.Open(s)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := yaml.NewDecoder(f).Decode(&a.QuayConfig); err != nil {
		return err
	}
	if !strings.HasPrefix(a.QuayConfig.URI, "postgresql://") {
		return fmt.Errorf(`unrecognized database URI: %q (only "postgresql" is supported)`, a.QuayConfig.URI)
	}

	a.quayDB = sync.OnceValues(func() (*pgxpool.Pool, error) {
		cfg, err := pgxpool.ParseConfig(a.QuayConfig.URI)
		if err != nil {
			return nil, err
		}
		if p := a.QuayConfig.Args.SSL.CA; p != nil {
			tlsCfg := cfg.ConnConfig.TLSConfig.Clone()
			certPool := tlsCfg.RootCAs
			if certPool == nil {
				certPool, err = x509.SystemCertPool()
				if err != nil {
					return nil, err
				}
			}
			pem, err := os.ReadFile(*p)
			if err != nil {
				return nil, err
			}
			if !certPool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("unable to add CA from %q (is it PEM encoded CA certificate(s)?)", *p)
			}
		}
		cfg.MaxConns = int32(runtime.GOMAXPROCS(0)) // This is how many goroutines we'll have checking manifest existence.
		init, done := context.WithTimeoutCause(context.Background(), 10*time.Second,
			errors.New("too slow to do initial connection to Quay database"))
		defer done()
		return pgxpool.ConnectConfig(init, cfg)
	})

	return nil
}

// Just enough Quay config to be dangerous.
type quayConfig struct {
	Args struct {
		SSL struct {
			CA *string `json:"ca" yaml:"ca"`
		} `json:"ssl" yaml:"ssl"`
	} `json:"DB_CONNECTION_ARGS" yaml:"DB_CONNECTION_ARGS"`
	URI string `json:"DB_URI" yaml:"DB_URI"`
}

// SelectMissing selects manifests that are absent from Quay (or filters
// manifests that are present in Quay, if one prefers).
//
// The current implementation fans out to GOMAXPROCS goroutines and fans back in
// to an iterator.
func (a *App) SelectMissing(ctx context.Context, manifests iter.Seq[[]string]) (iter.Seq[[]string], func() error) {
	// Gone signals that the returned iterator's reader has stopped.
	gone := make(chan struct{})
	// In is pages from the "manifests" iterator.
	// Out is filtered pages for returning to the iterator reader.
	in, out := make(chan []string), make(chan []string)

	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(runtime.GOMAXPROCS(0) + 1) // allow GOMAXPROCS workers and 1 reader.
	// Reader goroutine
	eg.Go(func() error {
		next, stop := iter.Pull(manifests)
		defer stop()
		defer close(in)
		for i := 1; ; i++ {
			ms, ok := next()
			if !ok {
				return nil
			}
			select {
			case in <- ms:
			case <-ctx.Done():
				return context.Cause(ctx)
			case <-gone:
				return nil
			}
		}
	})
	// Inner is a function closing over the channel and returning an iterator
	// returning filtered manifests.
	var inner func(<-chan []string) iter.Seq2[[]string, error]

	switch {
	// Prefer the GABI interface.
	case a.QuayGABI != nil:
		queryFormatter := func(enc *json.Encoder, str *strings.Builder) func([]string) error {
			return func(ms []string) error {
				str.Reset()
				str.WriteString(`SELECT * FROM unnest(`)
				fmtPostgresqlArray(str, ms)
				str.WriteString(`) EXCEPT ALL SELECT digest FROM manifest WHERE digest = ANY(`)
				fmtPostgresqlArray(str, ms)
				str.WriteString(`);`)
				return enc.Encode(query(str))
			}
		}
		inner = func(in <-chan []string) iter.Seq2[[]string, error] {
			buf := &bytes.Buffer{}
			enc := json.NewEncoder(buf)
			enc.SetEscapeHTML(false)
			mkQuery := queryFormatter(enc, new(strings.Builder))
			return func(yield func([]string, error) bool) {
				var ok bool
				for {
					var ms []string
					select {
					case ms, ok = <-in:
						if !ok {
							return
						}
					case <-ctx.Done():
						yield(nil, context.Cause(ctx))
						return
					case <-gone:
						return
					}
					if err := mkQuery(ms); err != nil {
						yield(nil, err)
						return
					}

					qRes, err := a.GABIQuery(ctx, a.QuayGABI, buf)
					if err != nil {
						yield(nil, err)
						return
					}

					// Skip the initial value, it's the list of columns
					rows := qRes.Result[1:]
					vals := make([]string, len(rows))
					for i, row := range rows {
						vals[i] = row[0]
					}
					if !yield(nil, err) {
						return
					}
				}
			}
		}
	// Second favorite: direct database access.
	case a.quayDB != nil:
		pool, err := a.quayDB()
		if err != nil {
			return nil, func() error { return err }
		}
		const query = `SELECT * FROM unnest($1::TEXT[]) EXCEPT ALL SELECT digest FROM manifest WHERE digest = ANY($1::TEXT[]);`
		inner = func(in <-chan []string) iter.Seq2[[]string, error] {
			return func(yield func([]string, error) bool) {
				var ok bool
				for {
					var ms []string
					select {
					case ms, ok = <-in:
						if !ok {
							return
						}
					case <-ctx.Done():
						yield(nil, context.Cause(ctx))
						return
					case <-gone:
						return
					}
					vals := make([]string, a.PageCount)
					err := pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
						rows, err := c.Query(ctx, query, ms)
						if err != nil {
							return err
						}
						defer rows.Close()

						i := 0
						for rows.Next() {
							if err := rows.Scan(&vals[i]); err != nil {
								return err
							}
							i++
						}
						if err := rows.Err(); err != nil {
							return err
						}
						vals = vals[:i]
						return nil
					})
					if err != nil {
						yield(nil, err)
						return
					}
					if !yield(vals, nil) {
						return
					}
				}
			}
		}
	}

	// Worker goroutines.
	for eg.TryGo(func() error {
		defer func() {
			slog.Debug("worker done", "worker", "quay")
		}()
		for ms, err := range inner(in) {
			if err != nil {
				return err
			}
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case <-gone:
				slog.Debug("dropped value", "worker", "quay")
			case out <- ms:
			}
		}
		return nil
	}) {
	}
	// Wait for workers+reader to finish and close the output channel. Causes
	// the returned iterator to fall out of its reading loop.
	go func() {
		eg.Wait()
		close(out)
		slog.Debug("output channel closed", "worker", "quay")
	}()

	return func(yield func([]string) bool) {
		ct := 0
		defer func() {
			slog.Debug("sequence done", "worker", "quay", "sent", ct)
		}()
		defer close(gone)
		for ms := range out {
			ct++
			if !yield(ms) {
				return
			}
		}
	}, eg.Wait
}
