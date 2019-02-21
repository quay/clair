package clair

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

func retrieveLayerBlob(ctx context.Context, blobSha256 string, path string, headers map[string]string) (io.ReadCloser, error) {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return downloadLayerBlob(ctx, blobSha256, path, headers)
	}

	return loadLayerBlobFromFS(blobSha256)
}

func downloadLayerBlob(ctx context.Context, blobSha256 string, uri string, headers map[string]string) (io.ReadCloser, error) {
	request, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, RetrieveBlobError
	}

	if headers != nil {
		for k, v := range headers {
			request.Header.Set(k, v)
		}
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{},
		Proxy:           http.ProxyFromEnvironment,
	}

	client := &http.Client{Transport: tr}
	r, err := client.Do(request)
	if err != nil {
		log.WithError(err).Error("could not download layer")
		return nil, RetrieveBlobError
	}

	// Fail if we don't receive a 2xx HTTP status code.
	if is2xx(r.StatusCode) {
		log.WithField("status", r.StatusCode).Error("could not download layer: expected 2XX")
		return nil, RetrieveBlobError
	}

	return r.Body, nil
}

func is2xx(statusCode int) bool {
	return statusCode >= 200 && statusCode < 300
}

func loadLayerBlobFromFS(path string) (io.ReadCloser, error) {
	return os.Open(path)
}
