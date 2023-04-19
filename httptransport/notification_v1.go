package httptransport

import (
	"context"
	"errors"
	"net/http"
	"path"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/quay/zlog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/quay/clair/v4/internal/codec"
	"github.com/quay/clair/v4/internal/httputil"
	"github.com/quay/clair/v4/middleware/compress"
	"github.com/quay/clair/v4/notifier"
)

const defaultPageSize = 500

type notificationResponse struct {
	Page          notifier.Page           `json:"page"`
	Notifications []notifier.Notification `json:"notifications"`
}

// NotificationV1 is a Notification endpoint.
type NotificationV1 struct {
	inner http.Handler
	serv  notifier.Service
}

var _ http.Handler = (*NotificationV1)(nil)

// NewNotificationV1 returns an http.Handler serving the Notification V1 API rooted at
// "prefix".
func NewNotificationV1(_ context.Context, prefix string, srv notifier.Service, topt otelhttp.Option) (*NotificationV1, error) {
	prefix = path.Join("/", prefix) // Ensure the prefix is rooted and cleaned.
	m := http.NewServeMux()
	h := NotificationV1{
		inner: otelhttp.NewHandler(
			compress.Handler(m),
			"notificationv1",
			otelhttp.WithMessageEvents(otelhttp.ReadEvents, otelhttp.WriteEvents),
			topt,
		),
		serv: srv,
	}
	p := path.Join(prefix, "notification") + "/"
	m.Handle(p, notificationv1wrapper.wrapFunc(path.Join(p, ":id"), h.serveHTTP))
	return &h, nil
}

// ServeHTTP implements http.Handler.
func (h *NotificationV1) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	r = withRequestID(r)
	ctx := r.Context()
	var status int
	var length int64
	w = httputil.ResponseRecorder(&status, &length, w)
	defer func() {
		switch err := http.NewResponseController(w).Flush(); {
		case errors.Is(err, nil):
		case errors.Is(err, http.ErrNotSupported): // Skip
		default:
			zlog.Warn(ctx).
				Err(err).
				Msg("unable to flush http response")
		}
		zlog.Info(ctx).
			Str("remote_addr", r.RemoteAddr).
			Str("method", r.Method).
			Str("request_uri", r.RequestURI).
			Int("status", status).
			Int64("written", length).
			Dur("duration", time.Since(start)).
			Msg("handled HTTP request")
	}()
	h.inner.ServeHTTP(w, r)
}

func (h *NotificationV1) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.get(w, r)
	case http.MethodDelete:
		h.delete(w, r)
	default:
		apiError(r.Context(), w, http.StatusMethodNotAllowed, "endpoint only allows GET or DELETE")
	}
}

func (h *NotificationV1) delete(w http.ResponseWriter, r *http.Request) {
	ctx := zlog.ContextWithValues(r.Context(), "component", "httptransport/NotificationV1.delete")
	path := r.URL.Path
	id := filepath.Base(path)
	notificationID, err := uuid.Parse(id)
	if err != nil {
		zlog.Warn(ctx).Err(err).Msg("could not parse notification id")
		apiError(ctx, w, http.StatusBadRequest, "could not parse notification id: %v", err)
	}

	err = h.serv.DeleteNotifications(ctx, notificationID)
	if err != nil {
		zlog.Warn(ctx).Err(err).Msg("could not delete notification")
		apiError(ctx, w, http.StatusInternalServerError, "could not delete notification: %v", err)
	}
}

// Get will return paginated notifications to the caller.
func (h *NotificationV1) get(w http.ResponseWriter, r *http.Request) {
	ctx := zlog.ContextWithValues(r.Context(), "component", "httptransport/NotificationV1.get")
	path := r.URL.Path
	id := filepath.Base(path)
	notificationID, err := uuid.Parse(id)
	if err != nil {
		zlog.Warn(ctx).Err(err).Msg("could not parse notification id")
		apiError(ctx, w, http.StatusBadRequest, "could not parse notification id: %v", err)
	}

	// optional page_size parameter
	var pageSize int
	if param := r.URL.Query().Get("page_size"); param != "" {
		p, err := strconv.ParseInt(param, 10, 64)
		if err != nil {
			apiError(ctx, w, http.StatusBadRequest, "could not parse %q query param into integer", "page_size")
		}
		pageSize = int(p)
	}
	if pageSize == 0 {
		pageSize = defaultPageSize
	}

	// optional page parameter
	var next *uuid.UUID
	if param := r.URL.Query().Get("next"); param != "" {
		n, err := uuid.Parse(param)
		if err != nil {
			apiError(ctx, w, http.StatusBadRequest, "could not parse %q query param into integer", "next")
		}
		if n != uuid.Nil {
			next = &n
		}
	}

	allow := []string{"application/vnd.clair.notification.v1+json", "application/json"}
	switch err := pickContentType(w, r, allow); {
	case errors.Is(err, nil): // OK
	case errors.Is(err, ErrMediaType):
		apiError(ctx, w, http.StatusUnsupportedMediaType, "unable to negotiate common media type for %v", allow)
	default:
		apiError(ctx, w, http.StatusBadRequest, "malformed request: %v", err)
	}

	inP := &notifier.Page{
		Size: pageSize,
		Next: next,
	}
	notifications, outP, err := h.serv.Notifications(ctx, notificationID, inP)
	if err != nil {
		apiError(ctx, w, http.StatusInternalServerError, "failed to retrieve notifications: %v", err)
	}

	response := notificationResponse{
		Page:          outP,
		Notifications: notifications,
	}

	defer writerError(w, &err)()
	enc := codec.GetEncoder(w)
	defer codec.PutEncoder(enc)
	err = enc.Encode(&response)
}

func init() {
	notificationv1wrapper.init("notificationv1")
}

var notificationv1wrapper wrapper
