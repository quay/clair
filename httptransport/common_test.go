package httptransport

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestPickContentTypeMalformedAccept checks that an Accept header whose media
// type has no subtype does not panic. mime.ParseMediaType accepts bare tokens
// like "*", which split into a single element.
func TestPickContentTypeMalformedAccept(t *testing.T) {
	allow := []string{"application/json"}
	for _, hdr := range []string{"*", "text", "application;q=0.5", "*, application/json"} {
		t.Run(hdr, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Accept", hdr)
			w := httptest.NewRecorder()
			if err := pickContentType(w, r, allow); err != nil && err != ErrMediaType {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
