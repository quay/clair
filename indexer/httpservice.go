package indexer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	clairerror "github.com/quay/clair/v4/clair-error"
	"github.com/quay/clair/v4/config"
	"github.com/quay/claircore"
)

// httpService implents the indexer Service via HTTP
type httpService struct {
	addr *url.URL
	c    *http.Client
}

// NewService is a constructor for a Service
func NewHTTPService(ctx context.Context, conf config.Config, client *http.Client) (Service, error) {
	addr, err := url.Parse(conf.Matcher.IndexerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse configured url %s: %w", addr, err)
	}
	if client == nil {
		client = &http.Client{}
	}

	return &httpService{addr, client}, nil
}

// Index receives a Manifest and returns a ScanReport providing the indexed
// items in the resulting image.
//
// Index blocks until completion. An error is returned if the index operation
// could not start. If an error occurs during the index operation the error will
// be preset on the ScanReport.Err field of the returned ScanReport.
func (s *httpService) Index(ctx context.Context, manifest *claircore.Manifest) (*claircore.ScanReport, error) {
	buf := bytes.NewBuffer([]byte{})
	err := json.NewEncoder(buf).Encode(manifest)
	if err != nil {
		return nil, &clairerror.ErrBadManifest{err}
	}

	url := url.URL{
		Scheme: s.addr.Scheme,
		Host:   s.addr.Hostname(),
		Path:   IndexAPIPath,
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url.String(), buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := s.c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &clairerror.ErrRequestFail{Code: resp.StatusCode, Status: resp.Status}
	}

	var sr *claircore.ScanReport
	err = json.NewDecoder(resp.Body).Decode(sr)
	if err != nil {
		return nil, &clairerror.ErrBadIndexReport{err}
	}

	return sr, nil
}

// IndexReport retrieves a IndexReport given a manifest hash string
func (s *httpService) IndexReport(ctx context.Context, manifestHash string) (*claircore.ScanReport, error) {
	url := url.URL{
		Scheme: s.addr.Scheme,
		Host:   s.addr.Hostname(),
		Path:   IndexReportAPIPath + "/" + manifestHash,
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	resp, err := s.c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %v", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, &clairerror.ErrIndexReportNotFound{manifestHash}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &clairerror.ErrIndexReportRetrieval{&clairerror.ErrRequestFail{Code: resp.StatusCode, Status: resp.Status}}
	}

	var sr *claircore.ScanReport
	err = json.NewDecoder(resp.Body).Decode(sr)
	if err != nil {
		return nil, &clairerror.ErrBadIndexReport{err}
	}

	return sr, nil
}
