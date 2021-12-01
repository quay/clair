package httptransport

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

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
