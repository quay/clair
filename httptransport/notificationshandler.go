package httptransport

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/google/uuid"
	je "github.com/quay/claircore/pkg/jsonerr"
	"github.com/rs/zerolog"

	"github.com/quay/clair/v4/internal/codec"
	"github.com/quay/clair/v4/notifier"
	"github.com/quay/clair/v4/notifier/service"
)

const (
	DefaultPageSize = 500
)

type Response struct {
	Page          notifier.Page           `json:"page"`
	Notifications []notifier.Notification `json:"notifications"`
}

type NotifHandler struct {
	serv service.Service
}

func NotificationHandler(serv service.Service) *NotifHandler {
	return &NotifHandler{
		serv: serv,
	}
}

func (h *NotifHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.Get(w, r)
	case http.MethodDelete:
		h.Delete(w, r)
	default:
		resp := &je.Response{
			Code:    "method-not-allowed",
			Message: "endpoint only allows POST",
		}
		je.Error(w, resp, http.StatusMethodNotAllowed)
	}
}

func (h *NotifHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := zerolog.Ctx(ctx)
	path := r.URL.Path
	id := filepath.Base(path)
	notificationID, err := uuid.Parse(id)
	if err != nil {
		resp := &je.Response{
			Code:    "bad-request",
			Message: fmt.Sprintf("could not parse notification id: %v", err),
		}
		log.Warn().Err(err).Msg("could not parse notification id")
		je.Error(w, resp, http.StatusBadRequest)
		return
	}

	err = h.serv.DeleteNotifications(ctx, notificationID)
	if err != nil {
		resp := &je.Response{
			Code:    "internal-server-error",
			Message: fmt.Sprintf("could not delete notification: %v", err),
		}
		log.Warn().Err(err).Msg("could not delete notification")
		je.Error(w, resp, http.StatusInternalServerError)
	}
}

// NotificaitonsHandler will return paginated notifications to the caller.
func (h *NotifHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := zerolog.Ctx(ctx)
	path := r.URL.Path
	id := filepath.Base(path)
	notificationID, err := uuid.Parse(id)
	if err != nil {
		resp := &je.Response{
			Code:    "bad-request",
			Message: fmt.Sprintf("could not parse notification id: %v", err),
		}
		log.Warn().Err(err).Msg("could not parse notification id")
		je.Error(w, resp, http.StatusBadRequest)
		return
	}

	// optional page_size parameter
	var pageSize uint64
	if param := r.URL.Query().Get("page_size"); param != "" {
		pageSize, err = strconv.ParseUint(param, 10, 64)
		if err != nil {
			resp := &je.Response{
				Code:    "bad-request",
				Message: "could not parse \"page_size\" query param into integer",
			}
			je.Error(w, resp, http.StatusBadRequest)
			return
		}
	}
	if pageSize == 0 {
		pageSize = DefaultPageSize
	}

	// optional page parameter
	var next *uuid.UUID
	if param := r.URL.Query().Get("next"); param != "" {
		n, err := uuid.Parse(param)
		if err != nil {
			resp := &je.Response{
				Code:    "bad-request",
				Message: "could not parse \"next\" query param into uuid",
			}
			je.Error(w, resp, http.StatusBadRequest)
			return
		}
		if n != uuid.Nil {
			next = &n
		}
	}

	inP := &notifier.Page{
		Size: pageSize,
		Next: next,
	}
	notifications, outP, err := h.serv.Notifications(ctx, notificationID, inP)
	if err != nil {
		resp := &je.Response{
			Code:    "internal-server-error",
			Message: "failed to retrieve notifications: " + err.Error(),
		}
		je.Error(w, resp, http.StatusInternalServerError)
		return
	}

	var response = Response{
		Page:          outP,
		Notifications: notifications,
	}

	defer writerError(w, &err)()
	enc := codec.GetEncoder(w)
	defer codec.PutEncoder(enc)
	err = enc.Encode(&response)
}
