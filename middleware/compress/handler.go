// Package compress implements an RFC9110 compliant handler for the
// "Accept-Encoding" header.
//
// This package supports "identity", "gzip", "deflate", and "zstd".
package compress

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

// Handler wraps the provided http.Handler and provides transparent body
// compression based on a Request's "Accept-Encoding" header.
//
// Each handler instance pools its own compressors.
func Handler(next http.Handler) http.Handler {
	h := handler{
		next: next,
	}
	h.zstd.New = func() interface{} {
		w, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
		if err != nil {
			panic(err)
		}
		return w
	}
	h.gzip.New = func() interface{} {
		w, err := gzip.NewWriterLevel(nil, gzip.BestSpeed)
		if err != nil {
			panic(err)
		}
		return w
	}
	h.flate.New = func() interface{} {
		w, err := flate.NewWriter(nil, flate.BestSpeed)
		if err != nil {
			panic(err)
		}
		return w
	}

	return &h
}

var _ http.Handler = (*handler)(nil)

// Handler performs transparent HTTP body compression.
type handler struct {
	zstd, gzip, flate sync.Pool
	next              http.Handler
}

// ParseAccept parses an "Accept-Encoding" header.
//
// Reports a sorted list of encodings and a map of disallowed encodings.
// Reports nil if no selections were present.
func parseAccept(h string) ([]accept, map[string]struct{}) {
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
	v, ok := r.Header["Accept-Encoding"]
	if !ok { // No header, use "identity".
		c.next.ServeHTTP(w, r)
		return
	}
	ae, nok := parseAccept(v[0])
	var zw zwriter
	// Find the first accept-encoding we support. See
	// https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3 for all the
	// semantics.
	//
	// NB The "identity" encoding shouldn't show up in the Content-Encoding
	// response header.
	for _, a := range ae {
		switch a.Type {
		case "gzip", "x-gzip":
			w.Header().Set("content-encoding", "gzip")
			gz := c.gzip.Get().(*gzip.Writer)
			gz.Reset(w)
			defer c.gzip.Put(gz)
			zw = gz
		case "deflate":
			w.Header().Set("content-encoding", "deflate")
			z := c.flate.Get().(*flate.Writer)
			z.Reset(w)
			defer c.flate.Put(z)
			zw = z
		case "zstd":
			w.Header().Set("content-encoding", "zstd")
			s := c.zstd.Get().(*zstd.Encoder)
			s.Reset(w)
			defer c.zstd.Put(s)
			zw = s
		case "identity":
			w.Header().Set("accept-encoding", acceptable)
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
				zw = gz
			case !idnok:
				// "Identity" isn't not OK, so fallthrough.
			default:
				w.Header().Set("accept-encoding", acceptable)
				w.WriteHeader(http.StatusUnsupportedMediaType)
				return
			}
		default:
			continue
		}
		break
	}
	// Now "zw" should be populated if it can be.
	if zw == nil {
		w.Header().Set("accept-encoding", acceptable)
		// If it's not, we need to make sure identity or "any" aren't
		// disallowed.
		_, idnok := nok["identity"]
		_, anynok := nok["*"]
		if idnok || anynok {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		// Couldn't pick something, fall back to identity.
		c.next.ServeHTTP(w, r)
		return
	}
	// Do some setup so we can see the error, albeit as a trailer.
	const errHeader = `Clair-Error`
	w.Header().Add("trailer", errHeader)
	defer func() {
		if err := zw.Close(); err != nil {
			w.Header().Add(errHeader, err.Error())
		}
	}()
	next := compressWriter{
		ResponseWriter: w,
		zwriter:        zw,
	}
	c.next.ServeHTTP(&next, r)
}

// Acceptable is a preformatted list of acceptable encodings.
const acceptable = `zstd, gzip, deflate`

// CompressWriter is compressing http.ResponseWriter that understands the go1.20
// ResponseController scheme.
type compressWriter struct {
	http.ResponseWriter
	zwriter
}

type zwriter interface {
	io.WriteCloser
	Flush() error
}

var _ http.ResponseWriter = (*compressWriter)(nil)

func (c *compressWriter) Unwrap() http.ResponseWriter {
	return c.ResponseWriter
}
func (c *compressWriter) Write(b []byte) (int, error) {
	return c.zwriter.Write(b)
}
func (c *compressWriter) FlushError() error {
	zFlush := c.zwriter.Flush()
	httpFlush := http.NewResponseController(c.ResponseWriter).Flush()
	if errors.Is(httpFlush, http.ErrNotSupported) {
		httpFlush = nil
	}
	return errors.Join(zFlush, httpFlush)
}
