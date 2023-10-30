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
	"log"
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

// This program is unlike the other Clair binaries in that it uses the stdlib
// "log" package in a format that I like rather than "zlog".
func main() {
	debug := flag.Bool("D", false, "print debugging output")
	addr := flag.String("listen", ":http", "address to listen on")
	keyEnc := flag.String("key", "", "base64 encoded PSK for signed requests")
	iss := flag.String("iss", "quay", "issuer for signed requests")
	flag.Parse()

	h := &Recv{
		Debug:  *debug,
		Client: http.DefaultClient,
	}

	if len(*keyEnc) != 0 {
		b := []byte(*keyEnc)
		l := base64.StdEncoding.DecodedLen(len(b))
		key := make([]byte, l)
		n, err := base64.StdEncoding.Decode(key, b)
		if err != nil {
			log.Fatal(err)
		}
		key = key[:n]
		if h.Debug {
			log.Printf("D decoded key: %+#q", key)
		}
		sk := jose.SigningKey{
			Algorithm: jose.HS256,
			Key:       key,
		}
		h.Signer, err = jose.NewSigner(sk, nil)
		if err != nil {
			log.Fatal(err)
		}
		h.Claim = &jwt.Claims{Issuer: *iss}
	}
	ctx := context.Background()
	ctx, done := signal.NotifyContext(ctx, os.Interrupt)
	defer done()
	srv := http.Server{
		Addr:        *addr,
		Handler:     h,
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}
	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	log.Println(":", "ready")
	defer func() {
		log.Println(":", "shutting down")
		if err := srv.Shutdown(ctx); err != nil && err != context.Canceled {
			log.Println(err)
		}
	}()
	<-ctx.Done()
}

// Recv implements the Clair notifier's "webhook" protocol.
type Recv struct {
	Client *http.Client
	Signer jose.Signer
	Claim  *jwt.Claims
	Debug  bool
}

// ServeHTTP implements [http.Handler].
func (h *Recv) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	defer rc.Flush()

	if h.Debug {
		b, err := httputil.DumpRequest(r, true)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("D", "received hook:", strconv.Quote(string(b)))
	}

	if r.Method != http.MethodPost {
		http.Error(w, fmt.Sprintf("bad method: %s", r.Method), http.StatusBadRequest)
		log.Println("E", "bad method:", r.Method)
		return
	}
	if ct := r.Header.Get(`content-type`); ct != `application/json` {
		http.Error(w, fmt.Sprintf("bad content-type: %s", ct), http.StatusBadRequest)
		log.Println("E", "bad content-type:", r.Method)
		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Println("E", "unable to close:", err.Error())
			panic(http.ErrAbortHandler)
		}
	}()
	var payload notifier.Callback
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("bad content: %v", err), http.StatusBadRequest)
		log.Println("E", "bad content:", err.Error())
		return
	}
	whid := path.Base(payload.Callback.Path)

	var resp response
	for next := new(uuid.UUID); next != nil; next = resp.Page.Next {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, payload.Callback.String(), nil)
		if err != nil {
			http.Error(w, fmt.Sprintf("unable to create request: %v", err), http.StatusInternalServerError)
			log.Println("E", "unable to create request:", err.Error())
			return
		}
		if pg := resp.Page.Next; pg != nil {
			v := req.URL.Query()
			v.Set(`next`, pg.String())
			req.URL.RawQuery = v.Encode()
		}
		if err := h.sign(req); err != nil {
			http.Error(w, fmt.Sprintf("unable to sign request: %v", err), http.StatusInternalServerError)
			log.Println("E", "unable to sign request:", err.Error())
			return
		}

		if h.Debug {
			b, err := httputil.DumpRequest(req, true)
			if err != nil {
				log.Fatal(err)
			}
			log.Println("D", "making request:", strconv.Quote(string(b)))
		}

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, fmt.Sprintf("error making request: %v", err), http.StatusInternalServerError)
			log.Println("E", "unable to make request:", err.Error())
			return
		}
		defer res.Body.Close()

		if h.Debug {
			b, err := httputil.DumpResponse(res, true)
			if err != nil {
				log.Fatal(err)
			}
			log.Println("D", "got response:", strconv.Quote(string(b)))
		}

		if res.StatusCode != http.StatusOK {
			http.Error(w, fmt.Sprintf("bad response from upstream: %q", res.Status), http.StatusInternalServerError)
			log.Println("E", "bad status:", res.Status)
			return
		}

		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			http.Error(w, fmt.Sprintf("bad content from upstream: %v", err), http.StatusTeapot)
			log.Println("E", "bad content:", err)
			return
		}

		for _, n := range resp.Notifications {
			log.Println(":", whid, n.ID, n.Manifest, n.Reason, n.Vulnerability.Name)
		}
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, payload.Callback.String(), nil)
	if err != nil {
		log.Fatal(err)
	}
	if err := h.sign(req); err != nil {
		http.Error(w, fmt.Sprintf("unable to sign request: %v", err), http.StatusInternalServerError)
		log.Println("E", "unable to sign request:", err.Error())
		return
	}
	if h.Debug {
		b, err := httputil.DumpRequest(req, true)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("D", "making request:", strconv.Quote(string(b)))
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("error making request: %v", err), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()
	if h.Debug {
		b, err := httputil.DumpResponse(res, true)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("D", "got response:", strconv.Quote(string(b)))
	}
	if res.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("bad response from upstream: %q", res.Status), http.StatusInternalServerError)
		log.Println("E", "bad status:", res.Status)
		return
	}
	log.Println(":", "deleted:", whid)
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
