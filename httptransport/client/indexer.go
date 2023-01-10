package client

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"path"

	"github.com/quay/claircore"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/httptransport"
	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/internal/codec"
	"github.com/quay/clair/v4/internal/httputil"
)

var _ indexer.Service = (*HTTP)(nil)

func (s *HTTP) AffectedManifests(ctx context.Context, v []claircore.Vulnerability) (*claircore.AffectedManifests, error) {
	u, err := s.addr.Parse(httptransport.AffectedManifestAPIPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse api address: %v", err)
	}
	rd := codec.JSONReader(struct {
		V []claircore.Vulnerability `json:"vulnerabilities"`
	}{
		v,
	})
	req, err := httputil.NewRequestWithContext(ctx, http.MethodPost, u.String(), rd)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	if err := s.sign(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("content-type", `application/json`)
	resp, err := s.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &clairerror.ErrRequestFail{
			Code:   resp.StatusCode,
			Status: resp.Status,
		}
	}

	var a claircore.AffectedManifests
	switch ct := req.Header.Get("content-type"); ct {
	case "", `application/json`:
		dec := codec.GetDecoder(resp.Body)
		defer codec.PutDecoder(dec)
		if err := dec.Decode(&a); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unrecognized content-type %q", ct)
	}
	return &a, nil
}

// Index receives a Manifest and returns a IndexReport providing the indexed
// items in the resulting image.
//
// Index blocks until completion. An error is returned if the index operation
// could not start. If an error occurs during the index operation the error will
// be preset on the IndexReport.Err field of the returned IndexReport.
func (s *HTTP) Index(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error) {
	u, err := s.addr.Parse(httptransport.IndexAPIPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req, err := httputil.NewRequestWithContext(ctx, http.MethodPost, u.String(), codec.JSONReader(manifest))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	if err := s.sign(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("content-type", `application/json`)
	resp, err := s.c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &clairerror.ErrRequestFail{
			Code:   resp.StatusCode,
			Status: resp.Status,
		}
	}

	var ir claircore.IndexReport
	switch ct := resp.Header.Get("content-type"); ct {
	case "", `application/json`:
		dec := codec.GetDecoder(resp.Body)
		defer codec.PutDecoder(dec)
		if err := dec.Decode(&ir); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unrecognized content-type %q", ct)
	}
	return &ir, nil
}

// IndexReport retrieves a IndexReport given a manifest hash string
func (s *HTTP) IndexReport(ctx context.Context, manifest claircore.Digest) (*claircore.IndexReport, bool, error) {
	u, err := s.addr.Parse(path.Join(httptransport.IndexReportAPIPath, manifest.String()))
	if err != nil {
		return nil, false, fmt.Errorf("failed to create request: %v", err)
	}

	req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create request: %v", err)
	}
	if err := s.sign(ctx, req); err != nil {
		return nil, false, fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := s.c.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("failed to do request: %v", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, false, nil
	default:
		return nil, false, &clairerror.ErrIndexReportRetrieval{
			E: &clairerror.ErrRequestFail{
				Code:   resp.StatusCode,
				Status: resp.Status,
			},
		}
	}

	ir := &claircore.IndexReport{}
	dec := codec.GetDecoder(resp.Body)
	defer codec.PutDecoder(dec)
	if err := dec.Decode(ir); err != nil {
		return nil, false, &clairerror.ErrBadIndexReport{E: err}
	}
	return ir, true, nil
}

func (s *HTTP) State(ctx context.Context) (string, error) {
	u, err := s.addr.Parse(httptransport.IndexStateAPIPath)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	if err := s.sign(ctx, req); err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := s.c.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to do request: %v", err)
	}
	defer resp.Body.Close()
	buf := &bytes.Buffer{}
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// DeleteManifests deletes the specified manifests.
//
// Passing a digest of an unknown manifest is not an error.
func (s *HTTP) DeleteManifests(ctx context.Context, d ...claircore.Digest) ([]claircore.Digest, error) {
	// This implementation always uses the bulk delete endpoint.
	u, err := s.addr.Parse(httptransport.IndexAPIPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req, err := httputil.NewRequestWithContext(ctx, http.MethodDelete, u.String(), codec.JSONReader(d))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	if err := s.sign(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := s.c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %v", resp.Status)
	}
	var ret []claircore.Digest
	dec := codec.GetDecoder(resp.Body)
	defer codec.PutDecoder(dec)
	if err := dec.Decode(&ret); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return ret, nil
}
