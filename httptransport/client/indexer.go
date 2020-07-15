package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"

	"github.com/quay/claircore"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/httptransport"
	"github.com/quay/clair/v4/indexer"
)

var _ indexer.Service = (*HTTP)(nil)

func (s *HTTP) AffectedManifests(ctx context.Context, v []claircore.Vulnerability) (claircore.AffectedManifests, error) {
	var affected claircore.AffectedManifests
	buf := bytes.NewBuffer([]byte{})
	err := json.NewEncoder(buf).Encode(struct {
		V []claircore.Vulnerability `json:"vulnerabilities"`
	}{
		v,
	})
	if err != nil {
		return affected, &clairerror.ErrBadVulnerabilities{err}
	}

	u, err := s.addr.Parse(httptransport.AffectedManifestAPIPath)
	if err != nil {
		return affected, fmt.Errorf("failed to parse api address: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), buf)
	if err != nil {
		return affected, fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := s.c.Do(req)
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return affected, &clairerror.ErrRequestFail{Code: resp.StatusCode, Status: resp.Status}
	}
	err = json.NewDecoder(resp.Body).Decode(&affected)
	if err != nil {
		return affected, &clairerror.ErrBadAffectedManifests{err}
	}
	return affected, nil
}

// Index receives a Manifest and returns a IndexReport providing the indexed
// items in the resulting image.
//
// Index blocks until completion. An error is returned if the index operation
// could not start. If an error occurs during the index operation the error will
// be preset on the IndexReport.Err field of the returned IndexReport.
func (s *HTTP) Index(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error) {
	buf := bytes.NewBuffer([]byte{})
	err := json.NewEncoder(buf).Encode(manifest)
	if err != nil {
		return nil, &clairerror.ErrBadManifest{err}
	}

	u, err := s.addr.Parse(httptransport.IndexAPIPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := s.c.Do(req)
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &clairerror.ErrRequestFail{Code: resp.StatusCode, Status: resp.Status}
	}

	var sr *claircore.IndexReport
	err = json.NewDecoder(resp.Body).Decode(sr)
	if err != nil {
		return nil, &clairerror.ErrBadIndexReport{err}
	}

	return sr, nil
}

// IndexReport retrieves a IndexReport given a manifest hash string
func (s *HTTP) IndexReport(ctx context.Context, manifest claircore.Digest) (*claircore.IndexReport, bool, error) {
	u, err := s.addr.Parse(path.Join(httptransport.IndexReportAPIPath, manifest.String()))
	if err != nil {
		return nil, false, fmt.Errorf("failed to create request: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := s.c.Do(req)
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, false, fmt.Errorf("failed to do request: %v", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, &clairerror.ErrIndexReportRetrieval{&clairerror.ErrRequestFail{Code: resp.StatusCode, Status: resp.Status}}
	}

	ir := &claircore.IndexReport{}
	err = json.NewDecoder(resp.Body).Decode(ir)
	if err != nil {
		return nil, false, &clairerror.ErrBadIndexReport{err}
	}

	return ir, true, nil
}

func (s *HTTP) State(ctx context.Context) (string, error) {
	u, err := s.addr.Parse(httptransport.IndexStateAPIPath)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := s.c.Do(req)
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return "", fmt.Errorf("failed to do request: %v", err)
	}
	buf := &bytes.Buffer{}
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return "", err
	}
	return buf.String(), nil
}
