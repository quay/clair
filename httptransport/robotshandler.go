package httptransport

import (
	"net/http"
	"strings"
	"time"

	"github.com/quay/clair/v4/cmd"
)

var startup = time.Now()

const robotstxt = "User-agent: *\nDisallow: /\n"

// RobotsHandler provides a "robots.txt" endpoint.
var robotsHandler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	d := cmd.CommitDate
	if d.IsZero() {
		d = startup
	}
	http.ServeContent(w, r, "robots.txt", d, strings.NewReader(robotstxt))
})
