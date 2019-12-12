package indexer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"

	"github.com/quay/claircore"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/config"
)

// HttpClient implents the indexer service via HTTP
type httpClient struct {
	addr *url.URL
	c    *http.Client
}

// NewClient is a constructor for a Client
func NewHTTPClient(ctx context.Context, conf config.Config, client *http.Client) (*httpClient, error) {
	addr, err := url.Parse(conf.Matcher.IndexerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse configured url %s: %w", addr, err)
	}
	if client == nil {
		client = &http.Client{}
	}

	return &httpClient{addr, client}, nil
}

// Index receives a Manifest and returns a IndexReport providing the indexed
// items in the resulting image.
//
// Index blocks until completion. An error is returned if the index operation
// could not start. If an error occurs during the index operation the error will
// be preset on the IndexReport.Err field of the returned IndexReport.
func (s *httpClient) Index(ctx context.Context, manifest *claircore.Manifest) (*claircore.IndexReport, error) {
	buf := bytes.NewBuffer([]byte{})
	err := json.NewEncoder(buf).Encode(manifest)
	if err != nil {
		return nil, &clairerror.ErrBadManifest{err}
	}

	u, err := s.addr.Parse(IndexAPIPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := s.c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %v", err)
	}
	defer resp.Body.Close()
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
func (s *httpClient) IndexReport(ctx context.Context, manifestHash string) (*claircore.IndexReport, bool, error) {
	u, err := s.addr.Parse(path.Join(IndexReportAPIPath, manifestHash))
	if err != nil {
		return nil, false, fmt.Errorf("failed to create request: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := s.c.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("failed to do request: %v", err)
	}
	defer resp.Body.Close()
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

func (s *httpClient) State(ctx context.Context) (string, error) {
	u, err := s.addr.Parse(StateAPIPath)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
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
