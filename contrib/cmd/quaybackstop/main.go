//go:build go1.23

// Quaybackstop is a helper command to ensure that Quay's GC decisions are
// propagated back to Clair.
//
// This command can read either from [GABI] services or backing databases
// directly. For Quay, database support is limited to PostgreSQL; Clair only
// supports PostgreSQL.
//
// There's support for controlling the load on the database via the
// "page-count", "page-size", and "cursor-file" flags. See the help output for
// more information.
//
// [GABI]: https://github.com/app-sre/gabi
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/clair/config"
)

func main() {
	var code int
	defer func() {
		if code != 0 {
			os.Exit(code)
		}
	}()
	ctx := context.Background()
	ctx, done := signal.NotifyContext(ctx, append(signals, os.Interrupt)...)
	defer done()
	var app App
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	flag.CommandLine.Usage = usage(flag.CommandLine)
	flag.BoolFunc("D", "print debugging output (-D=2 for more output)", setLogging(opts))
	flag.BoolVar(&app.DryRun, "n", false, "dry-run: do not issue delete requests")
	flag.IntVar(&app.PageSize, "page-size", 100, "pull pages of `SIZE` from the Quay database")
	flag.IntVar(&app.PageCount, "page-count", -1, "only process `N` pages before stopping (-1 for \"all\")")
	flag.Func("cursor-file", "resume state from `FILE` and write state if \"page-count\" is set", app.SetCursorFile)
	flag.Func("clair-gabi", "query Clair database via specified GABI `URL`", app.SetClairGABI)
	flag.Func("clair-gabi-auth", "use provided `TOKEN` for Clair GABI queries", app.SetClairGABIAuth)
	flag.Func("clair-config", "load Clair configuration from `FILE` and connect to database directly", app.SetClairConfig)
	flag.Func("quay-gabi", "query Quay database via specified GABI `URL`", app.SetQuayGABI)
	flag.Func("quay-gabi-auth", "use provided `TOKEN` for Quay GABI queries", app.SetQuayGABIAuth)
	flag.Func("quay-config", "load Quay configuration from `FILE` and connect to database directly", app.SetQuayConfig)
	flag.Func("indexer-addr", "issue deletes to indexer at `URL` (using credentials from \"clair-config\")", app.SetIndexerAddr)
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, opts)))

	if err := Run(ctx, app); err != nil {
		slog.Error("exiting with error", "err", err)
		code = 1
	}
}

// Usage returns a function printing the customized help output for the provided
// [flag.FlagSet].
func usage(set *flag.FlagSet) func() {
	buf := bufio.NewWriter(set.Output())
	words := []string{
		"Usage: quaybackstop", "[-D]", "[-page-size SIZE]", "[-page-count N]",
		"[-cursor-file FILE]", "[-indexer-addr URL | -n]",
		"[-clair-gabi URL [-clair-gabi-auth TOKEN]]", "[-clair-config FILE]",
		"[-quay-gabi URL [-quay-gabi-auth TOKEN] | -quay-config FILE]",
	}
	cols := 80
	if v, ok := os.LookupEnv("COLUMNS"); ok && v != "" {
		if c, err := strconv.Atoi(v); err == nil { // backwards conditional
			cols = c
		}
	}

	return func() {
		p, l := 0, 0
		for _, w := range words {
			if p+len(w)+1 > cols {
				buf.WriteByte('\n')
				p = 0
				l++
			}
			if p == 0 && l != 0 {
				p, _ = buf.WriteString(strings.Repeat(" ", len(words[0])))
			}
			if p != 0 {
				buf.WriteByte(' ')
				p++
			}
			ct, _ := buf.WriteString(w)
			p += ct
		}
		buf.WriteByte('\n')
		buf.WriteByte('\n')
		buf.WriteString("Quaybackstop is a helper command to ensure that Quay's GC decisions are\npropagated back to Clair.\n")
		buf.WriteByte('\n')
		buf.WriteString("OPTIONS:\n")
		buf.Flush()
		set.PrintDefaults()
	}
}

// SetLogging returns a function to be used as a [flag.BoolFunc] that sets the
// Level of the closed-over [*slog.HandlerOptions].
func setLogging(opts *slog.HandlerOptions) func(string) error {
	return func(s string) error {
		if ct, err := strconv.Atoi(s); err == nil {
			if ct != 0 {
				opts.Level = opts.Level.Level() + slog.Level(ct*int(slog.LevelDebug))
			} else {
				opts.Level = slog.LevelInfo
			}
			return nil
		}
		ok, err := strconv.ParseBool(s)
		if err != nil {
			return err
		}
		if ok {
			opts.Level = opts.Level.Level() + slog.LevelDebug
		} else {
			opts.Level = slog.LevelInfo
		}
		return nil
	}
}

// LevelTrace is a more granular logging level.
const LevelTrace = slog.LevelDebug + slog.LevelDebug

// Run is the main entrypoint.
func Run(ctx context.Context, app App) error {
	app.Status()
	if err := app.OK(); err != nil {
		return err
	}

	digests, clairErr := app.AllManifests(ctx)
	rm, quayErr := app.SelectMissing(ctx, digests)
	return errors.Join(app.IssueDeletes(ctx, rm), clairErr(), quayErr(), app.Close())
}

// App is the giant bag of state for the process.
//
// If tinkering with this struct, prefer "Set*" functions along with
// [flag.FlagSet.Func] to add new elements.
type App struct {
	clairDB func() (*pgxpool.Pool, error)
	quayDB  func() (*pgxpool.Pool, error)

	ClairGABI     *url.URL
	ClairGABIAuth *string
	ClairConfig   *config.Config

	QuayGABI     *url.URL
	QuayGABIAuth *string
	QuayConfig   *quayConfig

	IndexerAddr      *url.URL
	jwtSigner        jose.Signer
	clairTokenMu     *sync.RWMutex
	clairToken       *string
	clairTokenResign time.Time

	CursorFile *string
	PageSize   int
	PageCount  int

	DryRun bool
}

func (a *App) SetCursorFile(s string) (err error) {
	slog.Debug("cursor file flag", "argument", s)
	if s != "" {
		a.CursorFile = &s
	}
	return nil
}

// OK reports if the App is configured sanely.
func (a *App) OK() error {
	var errs []error
	if a.ClairConfig == nil && a.ClairGABI == nil {
		errs = append(errs, errors.New("no Clair config provided"))
	}
	if a.QuayConfig == nil && a.QuayGABI == nil {
		errs = append(errs, errors.New("no Quay config provided"))
	}
	if a.PageCount == 0 {
		errs = append(errs, errors.New("asked for 0 pages"))
	}
	return errors.Join(errs...)
}

// Status prints the current configuration as Debug messages.
func (a *App) Status() {
	slog.Debug("log level", "level", slog.LevelDebug)
	slog.Debug("page size", "count", a.PageSize)
	slog.Debug("page count", "count", a.PageCount)
	slog.LogAttrs(context.Background(), slog.LevelDebug, "cursor file", func() (as []slog.Attr) {
		ok := a.CursorFile != nil
		as = []slog.Attr{
			slog.Bool("provided", ok),
		}
		if ok {
			as = append(as, slog.String("file", *a.CursorFile))
		}
		return as
	}()...)
	slog.Debug("Clair GABI", "enabled", a.ClairGABI != nil, "URL", a.ClairGABI)
	slog.Debug("Clair GABI auth", "provided", a.ClairGABIAuth != nil)
	slog.Debug("Clair config", "provided", a.ClairConfig != nil)
	slog.Debug("Quay GABI", "enabled", a.QuayGABI != nil, "URL", a.QuayGABI)
	slog.Debug("Quay GABI auth", "provided", a.QuayGABIAuth != nil)
	slog.Debug("Quay config", "provided", a.QuayConfig != nil)
	slog.Debug("indexer address", "URL", a.IndexerAddr)
	slog.Debug("dry-run mode", "enabled", a.DryRun)
}

// Close closes any constructed database pools.
func (a *App) Close() error {
	var errs []error
	for _, f := range []func() (*pgxpool.Pool, error){
		a.clairDB,
		a.quayDB,
	} {
		if f == nil {
			continue
		}
		pool, err := f()
		errs = append(errs, err)
		if pool != nil {
			pool.Close()
		}
	}
	return errors.Join(errs...)
}

// NewRequestWithContext is a wrapper around [http.NewRequestWithContext] that
// sets defaults and authentication.
func (a *App) NewRequestWithContext(ctx context.Context, method string, url *url.URL, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url.String(), body)
	if err != nil {
		return nil, fmt.Errorf("unable to construct request: %w", err)
	}
	req.Header.Set("user-agent", ua())
	// Set auth headers if needed.
	var auth *string
	switch h := url.Hostname(); {
	case a.ClairGABI != nil && a.ClairGABI.Hostname() == h:
		auth = a.ClairGABIAuth
	case a.QuayGABI != nil && a.QuayGABI.Hostname() == h:
		auth = a.QuayGABIAuth
	case a.IndexerAddr != nil && a.ClairConfig != nil &&
		a.IndexerAddr.Hostname() == h:
		// This looks more complicated than it is.
		now := time.Now()

		a.clairTokenMu.RLock()
		if !a.clairTokenResign.IsZero() && a.clairTokenResign.Sub(now) > jwt.DefaultLeeway {
			auth = a.clairToken
		}
		a.clairTokenMu.RUnlock()
		if auth != nil {
			break
		}

		cl := jwt.Claims{Issuer: `quay`}
		cl.IssuedAt = jwt.NewNumericDate(now)
		cl.NotBefore = jwt.NewNumericDate(now.Add(-jwt.DefaultLeeway))
		a.clairTokenResign = now.Add(15 * time.Minute)
		cl.Expiry = jwt.NewNumericDate(a.clairTokenResign)
		tok, err := jwt.Signed(a.jwtSigner).Claims(&cl).CompactSerialize()
		if err != nil {
			return nil, fmt.Errorf("jwt construction: %w", err)
		}

		a.clairTokenMu.Lock()
		// Only update the stored token if we need to, but since we've taken the
		// expensive lock, make sure to at least populate the pointer.
		if a.clairTokenResign.IsZero() || a.clairTokenResign.Sub(now) < jwt.DefaultLeeway {
			a.clairToken = &tok
		}
		auth = a.clairToken
		a.clairTokenMu.Unlock()
	default:
	}
	if auth != nil {
		req.Header.Set("authorization", "Bearer "+*auth)
	}
	slog.Debug("constructed request", "URL", url, "auth", auth != nil)
	return req, nil
}

// GABIQuery does a GABI query to the server at "u".
func (a *App) GABIQuery(ctx context.Context, u *url.URL, buf *bytes.Buffer) (*gabiResponse, error) {
	url := u.JoinPath("query")
	slog.Log(ctx, LevelTrace, "GABI query", "query", buf, "url", url.String())

	req, err := a.NewRequestWithContext(ctx, http.MethodPost, url, buf)
	if err != nil {
		return nil, fmt.Errorf("unable to construct query: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable execute query: %w", err)
	}
	defer resp.Body.Close()

	var res gabiResponse
	switch resp.StatusCode {
	case http.StatusOK:
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return nil, fmt.Errorf("unable to read response: %w", err)
		}
	default:
		return nil, fmt.Errorf("unexpected response: %s", resp.Status)
	}
	if res.Error != "" {
		return nil, fmt.Errorf("gabi API error: %s", res.Error)
	}

	return &res, nil
}

// Query takes a full-formed SQL query (i.e. no parameter expansion is done) and
// returns a [gabiQuery] that can be marshaled to the correct JSON.
func query(str *strings.Builder) gabiQuery {
	return gabiQuery{str.String()}
}

// GabiQuery marshals to a JSON request body for GABI.
type gabiQuery struct {
	Query string `json:"query"`
}

// GabiResponse is the data returned from a GABI request.
type gabiResponse struct {
	Error  string     `json:"error"`
	Result [][]string `json:"result"`
}

// Ua builds and returns a "user-agent" header value.
var ua = sync.OnceValue(func() string {
	ua := "quaybackstop/"
	if info, ok := debug.ReadBuildInfo(); ok {
		ua += info.Main.Version
	} else {
		ua += "???"
	}
	return ua
})

// FmtPostgresqlArray writes an array literal with the contents of "strs" to
// "w".
//
// The input must not contain "'" characters.
func fmtPostgresqlArray(w io.Writer, strs []string) {
	io.WriteString(w, `ARRAY[`)
	for i, s := range strs {
		if i != 0 {
			w.Write([]byte(","))
		}
		w.Write([]byte("'"))
		io.WriteString(w, s)
		w.Write([]byte("'"))
	}
	w.Write([]byte("]"))
}
