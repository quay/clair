package introspection

import (
	"net/http"

	"go.opentelemetry.io/otel/api/core"
	"go.opentelemetry.io/otel/api/key"
)

var methods = map[string]core.KeyValue{
	http.MethodConnect: key.New("http.method").String(http.MethodConnect),
	http.MethodDelete:  key.New("http.method").String(http.MethodDelete),
	http.MethodGet:     key.New("http.method").String(http.MethodGet),
	http.MethodHead:    key.New("http.method").String(http.MethodHead),
	http.MethodOptions: key.New("http.method").String(http.MethodOptions),
	http.MethodPatch:   key.New("http.method").String(http.MethodPatch),
	http.MethodPost:    key.New("http.method").String(http.MethodPost),
	http.MethodPut:     key.New("http.method").String(http.MethodPut),
	http.MethodTrace:   key.New("http.method").String(http.MethodTrace),
}

// methodKV provides an O(1) function for creating
// a core.KeyValue representing the http method.
//
// in best case no construction of a KeyValue will
// be necessary
func methodKV(r *http.Request) core.KeyValue {
	if kv, ok := methods[r.Method]; ok {
		return kv
	}
	return key.New("http.method").String(r.Method)
}
