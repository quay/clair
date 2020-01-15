package main

import (
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/snappy"
	"github.com/markusthoemmes/goautoneg"
)

// Compress wraps the provided http.Handler and provides transparent body
// compression based on a Request's "Accept-Encoding" header.
func Compress(next http.Handler) http.Handler {
	h := compressHandler{
		next: next,
	}
	h.snappy.New = func() interface{} {
		return snappy.NewBufferedWriter(nil)
	}
	h.gzip.New = func() interface{} {
		w, _ := gzip.NewWriterLevel(nil, gzip.BestSpeed)
		return w
	}
	h.flate.New = func() interface{} {
		w, _ := flate.NewWriter(nil, flate.BestSpeed)
		return w
	}

	return &h
}

var _ http.Handler = (*compressHandler)(nil)

// CompressHandler performs transparent HTTP body compression.
type compressHandler struct {
	snappy, gzip, flate sync.Pool
	next                http.Handler
}

// Header is an interface that has the http.ResponseWriter's Header-related
// methods.
type header interface {
	Header() http.Header
	WriteHeader(int)
}

// ServeHTTP implements http.Handler.
func (c *compressHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var (
		flusher http.Flusher
		pusher  http.Pusher
		cw      io.WriteCloser
	)
	flusher, _ = w.(http.Flusher)
	pusher, _ = w.(http.Pusher)

	// Find the first accept-encoding we support.
	for _, a := range goautoneg.ParseAccept(r.Header.Get("accept-encoding")) {
		switch a.Type {
		case "gzip":
			w.Header().Set("content-encoding", "gzip")
			gz := c.gzip.Get().(*gzip.Writer)
			gz.Reset(w)
			defer c.gzip.Put(gz)
			cw = gz
		case "deflate":
			w.Header().Set("content-encoding", "deflate")
			z := c.flate.Get().(*flate.Writer)
			z.Reset(w)
			defer c.flate.Put(z)
			cw = z
		case "snappy": // Nonstandard
			w.Header().Set("content-encoding", "snappy")
			s := c.snappy.Get().(*snappy.Writer)
			s.Reset(w)
			defer c.snappy.Put(s)
			cw = s
		case "identity":
			w.Header().Set("content-encoding", "identity")
		case "*":
		default:
			continue
		}
		break
	}
	// Do some setup so we can see the error, albeit as a trailer.
	if cw != nil {
		const errHeader = `clair-error`
		w.Header().Add("trailer", errHeader)
		defer func() {
			if err := cw.Close(); err != nil {
				w.Header().Add(errHeader, err.Error())
			}
		}()
	}

	// Nw is the http.ResponseWriter for our next http.Handler.
	var nw http.ResponseWriter
	// This is a giant truth table to make anonymous types that satisfy as many
	// optional interfaces as possible.
	//
	// We care about 3 interfaces, so there are 2^3 == 8 combinations
	switch {
	case flusher == nil && pusher == nil && cw == nil:
		nw = w
	case flusher == nil && pusher == nil && cw != nil:
		nw = struct {
			header
			io.Writer
		}{w, cw}
	case flusher == nil && pusher != nil && cw == nil:
		nw = struct {
			http.ResponseWriter
			http.Pusher
		}{w, pusher}
	case flusher == nil && pusher != nil && cw != nil:
		nw = struct {
			header
			io.Writer
			http.Pusher
		}{w, cw, pusher}
	case flusher != nil && pusher == nil && cw == nil:
		nw = struct {
			http.ResponseWriter
			http.Flusher
		}{w, flusher}
	case flusher != nil && pusher == nil && cw != nil:
		nw = struct {
			header
			io.Writer
			http.Flusher
		}{w, cw, flusher}
	case flusher != nil && pusher != nil && cw == nil:
		nw = struct {
			http.ResponseWriter
			http.Flusher
			http.Pusher
		}{w, flusher, pusher}
	case flusher != nil && pusher != nil && cw != nil:
		nw = struct {
			header
			io.Writer
			http.Flusher
			http.Pusher
		}{w, cw, flusher, pusher}
	default:
		panic(fmt.Sprintf("unexpect type combination: %T/%T/%T", flusher, pusher, cw))
	}
	c.next.ServeHTTP(nw, r)
}
