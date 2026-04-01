package echo

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
)

var (
	_ driver.UpdaterSetFactory = (*Factory)(nil)
	_ driver.Configurable      = (*Factory)(nil)
	_ driver.Updater           = (*echoUpdater)(nil)
	_ driver.Configurable      = (*echoUpdater)(nil)
)

// Factory creates an Updater for Echo Linux.
//
// [Configure] must be called before [UpdaterSet].
type Factory struct {
	c       *http.Client
	jsonURL *url.URL
}

// NewFactory constructs a Factory.
//
// [Configure] must be called before [UpdaterSet].
func NewFactory(_ context.Context) (*Factory, error) {
	return &Factory{}, nil
}

// FactoryConfig is the configuration honored by the Factory.
type FactoryConfig struct {
	// URL is a URL to the Echo advisory JSON feed.
	URL string `json:"url" yaml:"url"`
}

// Configure implements [driver.Configurable].
func (f *Factory) Configure(_ context.Context, cf driver.ConfigUnmarshaler, c *http.Client) error {
	f.c = c
	var cfg FactoryConfig
	if err := cf(&cfg); err != nil {
		return fmt.Errorf("echo: factory configuration error: %w", err)
	}

	u, err := url.Parse(DefaultAdvisoryURL)
	if cfg.URL != "" {
		u, err = url.Parse(cfg.URL)
	}
	if err != nil {
		return fmt.Errorf("echo: bad advisory URL: %w", err)
	}
	f.jsonURL = u

	return nil
}

// UpdaterSet implements [driver.UpdaterSetFactory].
func (f *Factory) UpdaterSet(_ context.Context) (driver.UpdaterSet, error) {
	s := driver.NewUpdaterSet()

	u := &echoUpdater{
		jsonURL: f.jsonURL.String(),
	}

	if err := s.Add(u); err != nil {
		return s, fmt.Errorf("echo: unable to add updater: %w", err)
	}

	return s, nil
}

type echoUpdater struct {
	jsonURL string
	c       *http.Client
}

// Name implements [driver.Updater].
func (u *echoUpdater) Name() string {
	return "echo/updater"
}

// UpdaterConfig is the configuration for the updater.
type UpdaterConfig struct {
	// URL is a URL to the Echo advisory JSON feed.
	URL string `json:"url" yaml:"url"`
}

// Configure implements [driver.Configurable].
func (u *echoUpdater) Configure(_ context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	u.c = c
	var cfg UpdaterConfig
	if err := f(&cfg); err != nil {
		return err
	}
	if cfg.URL != "" {
		u.jsonURL = cfg.URL
		slog.Info("echo: configured advisory URL")
	}
	return nil
}

// Fetch implements [driver.Fetcher].
func (u *echoUpdater) Fetch(ctx context.Context, fingerprint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	log := slog.With("database", u.jsonURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.jsonURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("echo: failed to create request: %w", err)
	}
	if fingerprint != "" {
		req.Header.Set("If-Modified-Since", string(fingerprint))
	}

	resp, err := u.c.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, "", fmt.Errorf("echo: failed to retrieve advisory database: %w", err)
	}

	fp := resp.Header.Get("Last-Modified")

	switch resp.StatusCode {
	case http.StatusOK:
		if fingerprint == "" || fp != string(fingerprint) {
			log.InfoContext(ctx, "fetching latest advisory database")
			break
		}
		fallthrough
	case http.StatusNotModified:
		return nil, fingerprint, driver.Unchanged
	default:
		return nil, "", fmt.Errorf("echo: unexpected response: %v", resp.Status)
	}

	f, err := tmp.NewFile("", "echo.")
	if err != nil {
		return nil, "", err
	}

	var success bool
	defer func() {
		if !success {
			if err := f.Close(); err != nil {
				log.WarnContext(ctx, "unable to close spool", "reason", err)
			}
		}
	}()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return nil, "", fmt.Errorf("echo: failed to read http body: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, "", fmt.Errorf("echo: failed to seek body: %w", err)
	}
	log.InfoContext(ctx, "fetched latest advisory database successfully")

	success = true
	return f, driver.Fingerprint(fp), nil
}
