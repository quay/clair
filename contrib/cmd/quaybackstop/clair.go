//go:build go1.23

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"log/slog"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quay/clair/v4/cmd"

	"github.com/go-jose/go-jose/v3"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/clair/config"
	"github.com/rogpeppe/go-internal/lockedfile"
	"golang.org/x/sync/errgroup"
)

func (a *App) SetClairGABI(s string) (err error) {
	a.ClairGABI, err = url.Parse(s)
	return err
}

func (a *App) SetClairGABIAuth(s string) error {
	if s == "" {
		return errors.New("bad Clair GABI auth: empty string")
	}
	a.ClairGABIAuth = &s
	return nil
}

func (a *App) SetClairConfig(s string) error {
	slog.Debug("clair config flag", "argument", s)
	a.ClairConfig = new(config.Config)
	if err := cmd.LoadConfig(a.ClairConfig, s, false); err != nil {
		return err
	}

	sk := jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       []byte(a.ClairConfig.Auth.PSK.Key),
	}
	signer, err := jose.NewSigner(sk, nil)
	if err != nil {
		return err
	}
	a.jwtSigner = signer

	a.clairDB = sync.OnceValues(func() (*pgxpool.Pool, error) {
		cfg, err := pgxpool.ParseConfig(a.ClairConfig.Indexer.ConnString)
		if err != nil {
			return nil, err
		}
		cfg.MaxConns = int32(1) // Should only need one -- only used for reading the set of Clair manifests.
		init, done := context.WithTimeoutCause(context.Background(), 10*time.Second,
			errors.New("too slow to do initial connection to Clair database"))
		defer done()
		return pgxpool.ConnectConfig(init, cfg)
	})
	return nil
}

func (a *App) SetIndexerAddr(s string) (err error) {
	a.IndexerAddr, err = url.Parse(s)
	return err
}

// AllManifests reports pages (slices of length [App.PageSize]) of all manifests
// in the Clair database.
//
// This process is single-threaded, although it might be able to be made
// concurrent with sufficient effort.
func (a *App) AllManifests(ctx context.Context) (iter.Seq[[]string], func() error) {
	var retErr error
	var inner func(*int64) iter.Seq2[[]string, error]
	var pageToken int64
	var lastPage bool
	qstr := fmt.Sprintf(
		`SELECT id, hash FROM manifest WHERE id > $1 ORDER BY id ASC LIMIT %d;`,
		a.PageSize)

	updateCursor := func() {}
	if a.CursorFile != nil {
		b, err := lockedfile.Read(*a.CursorFile)
		switch {
		case err == nil:
			_, err = fmt.Fscanln(bytes.NewReader(b), &pageToken)
		case errors.Is(err, fs.ErrNotExist):
			err = nil
		default:
		}
		if err != nil {
			return nil, func() error {
				return fmt.Errorf("unable to read cursor file %q: %w", *a.CursorFile, err)
			}
		}
		slog.Info("loaded id from cursor", "id", pageToken)

		updateCursor = func() {
			if lastPage {
				slog.Info("reached last page; resetting cursor for next run", "id", pageToken)
				pageToken = 0
			}
			err := lockedfile.Transform(*a.CursorFile, func(prev []byte) ([]byte, error) {
				if !bytes.Equal(b, prev) {
					return nil,
						fmt.Errorf("cursorfile changed while running, not updating (got %#q, expected %#q)",
							string(prev), string(b))
				}
				return append(strconv.AppendInt(nil, pageToken, 10), '\n'), nil
			})
			if err != nil {
				slog.Error("unable to write cursor file", "error", err)
				return
			}
			slog.Info("wrote cursor file", "file", *a.CursorFile, "id", pageToken)
		}
	}

	switch {
	// Prefer using the GABI interface.
	case a.ClairGABI != nil:
		inner = func(id *int64) iter.Seq2[[]string, error] {
			str := &strings.Builder{}
			buf := &bytes.Buffer{}
			enc := json.NewEncoder(buf)
			enc.SetEscapeHTML(false)
			fstr := strings.ReplaceAll(qstr, "$1", "%d")
			return func(yield func([]string, error) bool) {
				for {
					str.Reset()
					fmt.Fprintf(str, fstr, *id)
					if err := enc.Encode(query(str)); err != nil {
						yield(nil, err)
						return
					}

					var qRes *gabiResponse
					qRes, err := a.GABIQuery(ctx, a.ClairGABI, buf)
					if err != nil {
						yield(nil, err)
						return
					}

					// Skip the initial value, it's the list of columns
					rows := qRes.Result[1:]
					*id, err = strconv.ParseInt(rows[len(rows)-1][0], 10, 64)
					if err != nil {
						yield(nil, err)
						return
					}
					vals := make([]string, len(rows))
					for i, row := range rows {
						vals[i] = row[1]
					}
					if !yield(vals, nil) {
						return
					}
				}
			}
		}
	// Second favorite: direct database access.
	case a.clairDB != nil:
		pool, err := a.clairDB()
		if err != nil {
			retErr = err
			break
		}

		inner = func(id *int64) iter.Seq2[[]string, error] {
			return func(yield func([]string, error) bool) {
				for {
					vals := make([]string, a.PageCount)
					err := pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
						rows, err := c.Query(ctx, qstr, *id)
						if err != nil {
							return err
						}
						defer rows.Close()

						i := 0
						for rows.Next() {
							if err := rows.Scan(id, &vals[i]); err != nil {
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
					switch {
					case err == nil:
					case errors.Is(err, pgx.ErrNoRows):
					default:
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

	// Seq wraps "inner" and does page counting and error handling.
	seq := func(yield func([]string) bool) {
		next, stop := iter.Pull2(inner(&pageToken))
		defer stop()
		for i := 0; a.PageCount < 0 || i < a.PageCount; i++ {
			select {
			case <-ctx.Done():
				retErr = context.Cause(ctx)
				return
			default:
			}
			s, err, valid := next()
			if err != nil {
				retErr = err
				return
			}
			if !valid {
				slog.Debug("done reading manifests", "count", len(s), "want", a.PageSize, "valid", valid)
				lastPage = true
			}
			if !yield(s) || lastPage {
				return
			}
		}
	}

	return seq, func() error {
		defer updateCursor()
		if err := retErr; err != nil {
			return fmt.Errorf("querying Clair DB: %w", err)
		}
		return nil
	}
}

// IssueDeletes sends bulk manifest delete requests to Clair.
//
// If not in dry-run mode, this requires the Indexer address and any needed auth
// to be configured.
func (a *App) IssueDeletes(ctx context.Context, seq iter.Seq[[]string]) error {
	// Memoized endpoint -- done this way to make the dry-run mode play nice.
	u := sync.OnceValue(func() *url.URL {
		return a.IndexerAddr.JoinPath("manifest")
	})
	// Channel that feeds the workers. Closed by the reader.
	// The reader waits on the passed context.
	ch := make(chan []string)
	// Worker function: has its own dedicated buffer and JSON encoder.
	worker := func() error {
		buf := &bytes.Buffer{}
		enc := json.NewEncoder(buf)
		for todo := range ch {
			if a.DryRun {
				if len(todo) != 0 {
					slog.Debug("would delete", "manifests", todo)
				}
				continue
			}

			if err := enc.Encode(todo); err != nil {
				return err
			}
			req, err := a.NewRequestWithContext(ctx, http.MethodDelete, u(), buf)
			if err != nil {
				return err
			}

			res, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			switch res.StatusCode {
			case http.StatusOK:
				if err := res.Body.Close(); err != nil {
					return err
				}
			default:
				return errors.Join(
					fmt.Errorf("unexpected response: %s", res.Status),
					res.Body.Close(),
				)
			}
		}
		return nil
	}

	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(runtime.GOMAXPROCS(0) + 1) // allow GOMAXPROCS workers and 1 reader.
	// Reader goroutine
	eg.Go(func() error {
		next, stop := iter.Pull(seq)
		defer stop()
		defer close(ch)
		zCt, i := 0, 0
		defer func() {
			if i%10 != 0 { // Don't print the status if the last page already did.
				total := i * a.PageSize
				slog.Info("manifests checked", "total", total, "exists", zCt, "removeable", total-zCt)
			}
		}()

		for todo, ok := next(); ok; todo, ok = next() {
			i++
			zCt += (a.PageSize - len(todo))
			if i%10 == 0 {
				total := i * a.PageSize
				slog.Info("manifests checked", "total", total, "exists", zCt, "removeable", total-zCt)
			}
			select {
			case ch <- todo:
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		}
		return nil
	})
	// Worker goroutines.
	for eg.TryGo(worker) {
	}

	return eg.Wait()
}
