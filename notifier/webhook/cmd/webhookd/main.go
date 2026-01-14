// Command webhookd is a server implementation of Clair's "webhook" notification
// protocol.
//
// This command is exempt from compatibility concerns beyond being compatible
// with the webhook protocol at the same point in the repository.
//
// This implementation is currently only suitable for debugging the notification
// subsystem, but ideas and implementations for extended functionality is
// welcome.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"path"
	"strconv"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"

	"github.com/quay/clair/v4/notifier"
)

func main() {
	var code int
	ctx, done := signal.NotifyContext(context.Background(), os.Interrupt)
	defer done()
	defer func() {
		done()
		if code != 0 {
			os.Exit(code)
		}
	}()
	var level slog.LevelVar
	flag.BoolFunc("D", "print debugging output", func(arg string) error {
		l := slog.LevelInfo
		if ok, _ := strconv.ParseBool(arg); ok {
			l = slog.LevelDebug
		}
		level.Set(l)
		return nil
	})
	addr := flag.String("listen", ":http", "address to listen on")
	keyEnc := flag.String("key", "", "base64 encoded PSK for signed requests")
	iss := flag.String("iss", "quay", "issuer for signed requests")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: &level,
	})))

	h := &Recv{
		Client: http.DefaultClient,
	}

	if len(*keyEnc) != 0 {
		b := []byte(*keyEnc)
		l := base64.StdEncoding.DecodedLen(len(b))
		key := make([]byte, l)
		n, err := base64.StdEncoding.Decode(key, b)
		if err != nil {
			slog.ErrorContext(ctx, "unable to decode key", "reason", err)
			code = 1
			return
		}
		key = key[:n]
		slog.DebugContext(ctx, "decoded key", "key", key)
		sk := jose.SigningKey{
			Algorithm: jose.HS256,
			Key:       key,
		}
		h.Signer, err = jose.NewSigner(sk, nil)
		if err != nil {
			slog.ErrorContext(ctx, "unable to create signer", "reason", err)
			code = 1
			return
		}
		h.Claim = &jwt.Claims{Issuer: *iss}
	}
	srv := http.Server{
		Addr:        *addr,
		Handler:     h,
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}
	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			slog.ErrorContext(ctx, "unable to start HTTP server", "reason", err)
			done()
			code = 1
			return
		}
	}()

	slog.InfoContext(ctx, "ready")
	defer func() {
		slog.InfoContext(ctx, "shutting down")
		if err := srv.Shutdown(ctx); err != nil && err != context.Canceled {
			slog.ErrorContext(ctx, "HTTP server shutdown", "reason", err)
		}
	}()
	<-ctx.Done()
}

// Recv implements the Clair notifier's "webhook" protocol.
type Recv struct {
	Client *http.Client
	Signer jose.Signer
	Claim  *jwt.Claims
}

const contentType = `application/json`

// ServeHTTP implements [http.Handler].
func (h *Recv) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rc := http.NewResponseController(w)
	defer rc.Flush()

	slog.DebugContext(ctx, "received hook", "request", (*logRequest)(r))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "", http.StatusMethodNotAllowed)
		slog.WarnContext(ctx, "bad request", "method", r.Method)
		return
	}
	if ct := r.Header.Get(`content-type`); ct != contentType {
		w.Header().Set("Accept-Post", contentType)
		http.Error(w, "", http.StatusUnsupportedMediaType)
		slog.WarnContext(ctx, "bad request", "content-type", ct)
		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			slog.WarnContext(ctx, "unable to close request body", "reason", err)
			panic(http.ErrAbortHandler)
		}
	}()
	var payload notifier.Callback
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("bad content: %v", err), http.StatusBadRequest)
		slog.WarnContext(ctx, "bad payload", "reason", err)
		return
	}
	whid := path.Base(payload.Callback.Path)

	var resp response
	for next := new(uuid.UUID); next != nil; next = resp.Page.Next {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, payload.Callback.String(), nil)
		if err != nil {
			http.Error(w, fmt.Sprintf("unable to create request: %v", err), http.StatusInternalServerError)
			slog.WarnContext(ctx, "unable to create request", "reason", err)
			return
		}
		if pg := resp.Page.Next; pg != nil {
			v := req.URL.Query()
			v.Set(`next`, pg.String())
			req.URL.RawQuery = v.Encode()
		}
		if err := h.sign(req); err != nil {
			http.Error(w, fmt.Sprintf("unable to sign request: %v", err), http.StatusInternalServerError)
			slog.WarnContext(ctx, "unable to sign request", "reason", err)
			return
		}

		slog.DebugContext(ctx, "making request", "request", (*logRequest)(req))

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, fmt.Sprintf("error making request: %v", err), http.StatusInternalServerError)
			slog.WarnContext(ctx, "unable to make request", "reason", err)
			return
		}
		defer res.Body.Close()

		slog.DebugContext(ctx, "got response", "response", (*logResponse)(res))
		if res.StatusCode != http.StatusOK {
			http.Error(w, fmt.Sprintf("bad response from upstream: %q", res.Status), http.StatusInternalServerError)
			slog.WarnContext(ctx, "bad status", "status", res.Status)
			return
		}

		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			http.Error(w, fmt.Sprintf("bad content from upstream: %v", err), http.StatusTeapot)
			slog.WarnContext(ctx, "bad content", "reason", err)
			return
		}

		for _, n := range resp.Notifications {
			slog.InfoContext(ctx, "notification", "id", whid, slog.Group("notification",
				"id", n.ID,
				"manifest", n.Manifest,
				"reason", n.Reason,
				"name", n.Vulnerability.Name,
			))
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, payload.Callback.String(), nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("unable to create request: %v", err), http.StatusInternalServerError)
		slog.WarnContext(ctx, "unable to create request", "reason", err)
		return
	}
	if err := h.sign(req); err != nil {
		http.Error(w, fmt.Sprintf("unable to sign request: %v", err), http.StatusInternalServerError)
		slog.WarnContext(ctx, "unable to sign request", "reason", err)
		return
	}
	slog.DebugContext(ctx, "making request", "request", (*logRequest)(req))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("error making request: %v", err), http.StatusInternalServerError)
		slog.WarnContext(ctx, "unable to make request", "reason", err)
		return
	}
	defer res.Body.Close()
	slog.DebugContext(ctx, "got response", "response", (*logResponse)(res))
	if res.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("bad response from upstream: %q", res.Status), http.StatusInternalServerError)
		slog.WarnContext(ctx, "bad status", "status", res.Status)
		return
	}
	slog.InfoContext(ctx, "deleted", "id", whid)
}

// Response is a page of notifications.
type response struct {
	Page          notifier.Page           `json:"page"`
	Notifications []notifier.Notification `json:"notifications"`
}

// Sign does what it says on the tin.
func (h *Recv) sign(req *http.Request) error {
	if h.Signer == nil {
		return nil
	}
	now := time.Now()
	cl := *h.Claim
	cl.IssuedAt = jwt.NewNumericDate(now)
	cl.NotBefore = jwt.NewNumericDate(now.Add(-jwt.DefaultLeeway))
	cl.Expiry = jwt.NewNumericDate(now.Add(jwt.DefaultLeeway))
	tok, err := jwt.Signed(h.Signer).Claims(&cl).CompactSerialize()
	if err != nil {
		return err
	}
	req.Header.Set("authorization", "Bearer "+tok)
	return nil
}

var (
	_ slog.LogValuer = (*logRequest)(nil)
	_ slog.LogValuer = (*logResponse)(nil)
)

type logRequest http.Request

// LogValue implements [slog.LogValuer].
func (l *logRequest) LogValue() slog.Value {
	req := (*http.Request)(l)
	b, err := httputil.DumpRequest(req, true)
	if err != nil {
		return slog.GroupValue(slog.String("error", err.Error()))
	}
	return slog.StringValue(string(b))
}

type logResponse http.Response

// LogValue implements [slog.LogValuer].
func (l *logResponse) LogValue() slog.Value {
	res := (*http.Response)(l)
	b, err := httputil.DumpResponse(res, true)
	if err != nil {
		return slog.GroupValue(slog.String("error", err.Error()))
	}
	return slog.StringValue(string(b))
}
