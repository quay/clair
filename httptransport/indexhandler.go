package httptransport

import (
	"fmt"
	"net/http"
	"path"

	"github.com/quay/claircore"
	je "github.com/quay/claircore/pkg/jsonerr"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/internal/codec"
)

const (
	linkIndex  = `<%s>; rel="https://projectquay.io/clair/v1/index_report"`
	linkReport = `<%s>; rel="https://projectquay.io/clair/v1/vulnerability_report"`
)

// IndexHandler utilizes an Indexer to begin a
// Index of a manifest.
func IndexHandler(serv indexer.StateIndexer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		w.Header().Set("content-type", "application/json")
		if r.Method != http.MethodPost {
			resp := &je.Response{
				Code:    "method-not-allowed",
				Message: "endpoint only allows POST",
			}
			je.Error(w, resp, http.StatusMethodNotAllowed)
			return
		}
		state, err := serv.State(ctx)
		if err != nil {
			resp := &je.Response{
				Code:    "internal error",
				Message: "could not retrieve indexer state " + err.Error(),
			}
			je.Error(w, resp, http.StatusInternalServerError)
			return
		}

		var m claircore.Manifest
		dec := codec.GetDecoder(r.Body)
		defer codec.PutDecoder(dec)
		if err := dec.Decode(&m); err != nil {
			resp := &je.Response{
				Code:    "bad-request",
				Message: fmt.Sprintf("failed to deserialize manifest: %v", err),
			}
			je.Error(w, resp, http.StatusBadRequest)
			return
		}
		if m.Hash.String() == "" || len(m.Layers) == 0 {
			resp := &je.Response{
				Code:    "bad-request",
				Message: "bogus manifest",
			}
			je.Error(w, resp, http.StatusBadRequest)
			return
		}
		next := path.Join(IndexReportAPIPath, m.Hash.String())

		w.Header().Add("link", fmt.Sprintf(linkIndex, next))
		w.Header().Add("link", fmt.Sprintf(linkReport, path.Join(VulnerabilityReportPath, m.Hash.String())))
		validator := `"` + state + `"`
		if unmodified(r, validator) {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}

		// TODO Do we need some sort of background context embedded in the HTTP
		// struct?
		report, err := serv.Index(ctx, &m)
		if err != nil {
			resp := &je.Response{
				Code:    "index-error",
				Message: fmt.Sprintf("failed to start scan: %v", err),
			}
			w.Header().Del("link")
			je.Error(w, resp, http.StatusInternalServerError)
			return
		}

		w.Header().Set("etag", validator)
		w.Header().Set("location", next)
		defer writerError(w, &err)()
		w.WriteHeader(http.StatusCreated)
		enc := codec.GetEncoder(w)
		defer codec.PutEncoder(enc)
		err = enc.Encode(report)
	}
}
