package compress

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/snappy"
)

// Handler wraps the provided http.Handler and provides transparent body
// compression based on a Request's "Accept-Encoding" header.
func Handler(next http.Handler) http.Handler {
	h := handler{
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

var _ http.Handler = (*handler)(nil)

// handler performs transparent HTTP body compression.
type handler struct {
	snappy, gzip, flate sync.Pool
	next                http.Handler
}

// Header is an interface that has the http.ResponseWriter's Header-related
// methods.
type header interface {
	Header() http.Header
	WriteHeader(int)
}

// ParseAccept parses an "Accept-Encoding" header.
//
// Reports a sorted list of encodings and a map of disallowed encodings.
// Reports nil if no selections were present.
func parseAccept(h string) ([]accept, map[string]struct{}) {
	if h == "" {
		return nil, nil
	}

	segs := strings.Split(h, ",")
	ret := make([]accept, 0, len(segs))
	nok := make(map[string]struct{})
	for _, s := range segs {
		a := accept{}
		t, param, err := mime.ParseMediaType(s)
		if err != nil {
			continue
		}
		a.Type = t
		if q, ok := param["q"]; ok {
			if q == "0" {
				nok[t] = struct{}{}
				continue
			}
			qv, err := strconv.ParseFloat(param["q"], 64)
			if err != nil {
				nok[t] = struct{}{}
				continue
			}
			a.Q = qv
		}
		ret = append(ret, a)
	}

	sort.SliceStable(ret, func(i, j int) bool {
		return ret[i].Q > ret[j].Q
	})
	return ret, nok
}

type accept struct {
	Type string
	Q    float64
}

// ServeHTTP implements http.Handler.
func (c *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ae, nok := parseAccept(r.Header.Get("accept-encoding"))
	if ae == nil {
		// If there was no header, play it cool.
		c.next.ServeHTTP(w, r)
		return
	}
	var (
		flusher http.Flusher
		pusher  http.Pusher
		cw      io.WriteCloser
	)
	flusher, _ = w.(http.Flusher)
	pusher, _ = w.(http.Pusher)

	// Find the first accept-encoding we support.
	// See https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.1 for
	// all the semantics.
	for _, a := range ae {
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
			// If we hit a star, it's technically OK to return any encoding not
			// already specified. So, attempt to use gzip and then identity and
			// give up.
			// Clients that do extremely weird things like
			//	*;q=1.0, gzip;q=0.1, identity;q=0.1"
			// deserve extremely weird replies.
			_, gznok := nok["gzip"]
			_, idnok := nok["identity"]
			switch {
			case !gznok:
				w.Header().Set("content-encoding", "gzip")
				gz := c.gzip.Get().(*gzip.Writer)
				gz.Reset(w)
				defer c.gzip.Put(gz)
				cw = gz
			case !idnok:
				w.Header().Set("content-encoding", "identity")
			default:
				w.WriteHeader(http.StatusNotAcceptable)
				return
			}
		default:
			continue
		}
		break
	}
	// Do some setup so we can see the error, albeit as a trailer.
	if cw != nil {
		const errHeader = `Clair-Error`
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
	// We care about 3 interfaces, so there are 2^3 == 8 combinations.
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
		panic(fmt.Sprintf("unexpected type combination: %T/%T/%T", flusher, pusher, cw))
	}
	c.next.ServeHTTP(nw, r)
}
