package httptransport

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"mime"
	"net/http"
	"path"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/trace"

	"github.com/quay/claircore"
)

// GetDigest removes the last path element and parses it as a digest.
func getDigest(_ http.ResponseWriter, r *http.Request) (d claircore.Digest, err error) {
	dStr := path.Base(r.URL.Path)
	if dStr == "" {
		return d, errors.New("provide a single manifest hash")
	}
	return claircore.ParseDigest(dStr)
}

// PickContentType sets the response's "Content-Type" header.
//
// If "Accept" headers are not present in the request, the first element of the
// "allow" slice is used.
//
// If "Accept" headers are present, the first (ordered by "q" value) media type
// in the "allow" slice is chosen. If there are no common media types, "415
// Unsupported Media Type" is written and ErrMediaType is reported.
func pickContentType(w http.ResponseWriter, r *http.Request, allow []string) error {
	// There's no canonical algorithm for this, it's all server-dependent
	// behavior. Our algorithm is:
	//
	//	- Parse the Accept header(s) as MIME media types joined by commas.
	//	- Stable sort according to the "q" parameter, defaulting to 1.0 if
	//	  omitted (as specified)
	//	- Pick the first match.
	//
	// BUG(hank) Content type negotiation does an O(n*m) comparison driven on
	// user input, which may be a DoS issue.
	as, ok := r.Header["Accept"]
	if !ok {
		w.Header().Set("content-type", allow[0])
		return nil
	}
	var acceptable []accept
	for _, part := range as {
		for _, s := range strings.Split(part, ",") {
			a := accept{}
			mt, p, err := mime.ParseMediaType(strings.TrimSpace(s))
			if err != nil {
				return err
			}
			a.Q = 1.0
			if qs, ok := p["q"]; ok {
				a.Q, _ = strconv.ParseFloat(qs, 64)
			}
			typ := strings.Split(mt, "/")
			a.Type = typ[0]
			a.Subtype = typ[1]
			acceptable = append(acceptable, a)
		}
	}
	if len(acceptable) == 0 {
		w.Header().Set("content-type", allow[0])
		return nil
	}
	sort.SliceStable(acceptable, func(i, j int) bool { return acceptable[i].Q > acceptable[j].Q })
	for _, l := range acceptable {
		for _, a := range allow {
			if l.Match(a) {
				w.Header().Set("content-type", a)
				return nil
			}
		}
	}
	w.WriteHeader(http.StatusUnsupportedMediaType)
	return ErrMediaType
}

// ErrMediaType is returned if no common media types can be found for a given
// request.
var ErrMediaType = errors.New("no common media type")

type accept struct {
	Type, Subtype string
	Q             float64
}

// Match reports whether the type in the "accept" struct matches the provided
// media type, honoring wildcards.
//
// Match panics if the provided media type is not well-formed.
func (a *accept) Match(mt string) bool {
	if a.Type == "*" && a.Subtype == "*" {
		return true
	}
	i := strings.IndexByte(mt, '/')
	if i == -1 {
		// Programmer error -- inputs to this function should be static strings.
		panic(fmt.Sprintf("bad media type: %q", mt))
	}
	t, s := mt[:i], mt[i+1:]
	return a.Type == t && (a.Subtype == s || a.Subtype == "*")
}

var idPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 8)
		if _, err := crand.Read(b); err != nil {
			panic(err) // ???
		}
		s := binary.LittleEndian.Uint64(b)
		src := rand.NewSource(int64(s))
		return rand.New(src)
	},
}

// WithRequestID sets up a per-request ID and annotates the logging context and
// profile labels.
func withRequestID(r *http.Request) *http.Request {
	const key = `request_id`
	const profile = `profile_id`
	ctx := r.Context()
	sctx := trace.SpanContextFromContext(ctx)
	var tid string
	if sctx.HasTraceID() {
		tid = sctx.TraceID().String()
	} else {
		rng := idPool.Get().(*rand.Rand)
		defer idPool.Put(rng)
		tid = fmt.Sprintf("%016x", rng.Uint64())
	}
	ctx = zlog.ContextWithValues(ctx, key, tid)
	ctx = pprof.WithLabels(ctx, pprof.Labels(profile, tid))
	return r.WithContext(ctx)
}
