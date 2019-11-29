package indexer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	clairerror "github.com/quay/clair/v4/clair-error"
	je "github.com/quay/claircore/pkg/jsonerr"
)

const (
	IndexReportAPIPath = "/api/v1/index_report/"
)

func IndexReportHandler(service Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			resp := &je.Response{
				Code:    "method-not-allowed",
				Message: "endpoint only allows GET",
			}
			je.Error(w, resp, http.StatusMethodNotAllowed)
			return
		}

		manifestHash := strings.TrimPrefix(r.URL.Path, IndexReportAPIPath)
		if manifestHash == "" {
			resp := &je.Response{
				Code:    "bad-request",
				Message: "malformed path. provide a single manifest hash",
			}
			je.Error(w, resp, http.StatusBadRequest)
			return
		}

		report, err := service.IndexReport(context.Background(), manifestHash)
		if err != nil {
			var e *clairerror.ErrIndexReportNotFound
			if errors.As(err, &e) {
				resp := &je.Response{
					Code:    "not-found",
					Message: fmt.Sprintf("index report for manifest %s not found", manifestHash),
				}
				je.Error(w, resp, http.StatusNotFound)
				return
			}
			var ee *clairerror.ErrIndexReportRetrieval
			if errors.As(err, &ee) {
				resp := &je.Response{
					Code:    "retrieval-failure",
					Message: fmt.Sprintf("failed to retrieve manifest: %w", err),
				}
				je.Error(w, resp, http.StatusInternalServerError)
				return
			}
			resp := &je.Response{
				Code:    "unhandled-error",
				Message: fmt.Sprintf("%w", err),
			}
			je.Error(w, resp, http.StatusInternalServerError)
			return
		}

		err = json.NewEncoder(w).Encode(report)
		if err != nil {
			resp := &je.Response{
				Code:    "encoding-error",
				Message: fmt.Sprintf("failed to encode scan report: %v", err),
			}
			je.Error(w, resp, http.StatusInternalServerError)
			return
		}

		return
	}
}
