package httptransport

import "net/http"

var gone = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	const msg = `{"code":"gone","message":"endpoint removed"}`
	http.Error(w, msg, http.StatusGone)
})
