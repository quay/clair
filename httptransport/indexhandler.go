package httptransport

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"

	oci "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/quay/claircore"
	je "github.com/quay/claircore/pkg/jsonerr"

	"github.com/quay/clair/v4/indexer"
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

		m, err := decodeManifest(ctx, r)
		if err != nil {
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
		report, err := serv.Index(ctx, m)
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
		err = json.NewEncoder(w).Encode(report)
	}
}

const (
	// Known manifest types we ingest.
	typeOCIManifest    = oci.MediaTypeImageManifest
	typeNativeManifest = `application/vnd.projectquay.clair.mainfest.v1+json`
)

// DecodeManifest switches on the Request's Content-Type to consume the body.
//
// Defaults to expecting a native ClairCore Manifest.
func decodeManifest(ctx context.Context, r *http.Request) (*claircore.Manifest, error) {
	defer r.Body.Close()
	var m claircore.Manifest

	t := r.Header.Get("content-type")
	if i := strings.IndexByte(t, ';'); i != -1 {
		t = strings.TrimSpace(t[:i])
	}
	switch t {
	case typeOCIManifest:
		var om oci.Manifest
		if err := json.NewDecoder(r.Body).Decode(&om); err != nil {
			return nil, err
		}
		if err := nativeFromOCI(&m, &om); err != nil {
			return nil, err
		}
	case typeNativeManifest, "application/json", "":
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown content-type %q", t)
	}
	return &m, nil
}

// These are the layer types we accept inside an OCI Manifest.
var ociLayerTypes = map[string]struct{}{
	oci.MediaTypeImageLayer:           {},
	oci.MediaTypeImageLayerGzip:       {},
	oci.MediaTypeImageLayer + "+zstd": {}, // The specs package doesn't have zstd, oddly.
}

// NativeFromOCI populates the Manifest from the OCI Manifest, reporting an
// error if something is invalid.
func nativeFromOCI(m *claircore.Manifest, o *oci.Manifest) error {
	const header = `header:`
	var err error

	m.Hash, err = claircore.ParseDigest(o.Config.Digest.String())
	if err != nil {
		return fmt.Errorf("unable to parse manifest digest %q: %w", o.Config.Digest, err)
	}

	for _, u := range o.Layers {
		if len(u.URLs) == 0 {
			// Manifest is missing URLs.
			// They're optional in the spec, but we need them for obvious reasons.
			return fmt.Errorf("missing URLs for layer %q", u.Digest)
		}
		if _, ok := ociLayerTypes[u.MediaType]; !ok {
			return fmt.Errorf("invalid media type for layer %q", u.Digest)
		}
		l := claircore.Layer{
			URI: u.URLs[0],
		}
		l.Hash, err = claircore.ParseDigest(u.Digest.String())
		if err != nil {
			return fmt.Errorf("unable to parse layer digest %q: %w", u.Digest, err)
		}
		for k, v := range u.Annotations {
			if !strings.HasPrefix(k, header) {
				continue
			}
			l.Headers[strings.TrimPrefix(k, header)] = []string{v}
		}
		m.Layers = append(m.Layers, &l)
	}

	return nil
}
