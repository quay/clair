package httputil

import (
	"net"
	"net/http"
	"strings"
)

// GetClientAddr returns the first value in X-Forwarded-For if it exists
// otherwise fall back to use RemoteAddr
func GetClientAddr(r *http.Request) string {
	addr := r.RemoteAddr
	if s := r.Header.Get("X-Forwarded-For"); s != "" {
		ips := strings.Split(s, ",")
		// assume the first one is the client address
		if len(ips) != 0 {
			// validate the ip
			if realIP := net.ParseIP(ips[0]); realIP != nil {
				addr = strings.TrimSpace(ips[0])
			}
		}
	}
	return addr
}
