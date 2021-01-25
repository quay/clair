package introspection

import (
	"net/http"

	"go.opentelemetry.io/otel/label"
)

// methodKey is the label accompanying pathKey and
// provides the http method of the requested path
var methodKey = label.Key("http.method")

var methods = map[string]label.KeyValue{
	http.MethodConnect: methodKey.String(http.MethodDelete),
	http.MethodDelete:  methodKey.String(http.MethodDelete),
	http.MethodGet:     methodKey.String(http.MethodGet),
	http.MethodHead:    methodKey.String(http.MethodHead),
	http.MethodOptions: methodKey.String(http.MethodOptions),
	http.MethodPatch:   methodKey.String(http.MethodPatch),
	http.MethodPost:    methodKey.String(http.MethodPost),
	http.MethodPut:     methodKey.String(http.MethodPut),
	http.MethodTrace:   methodKey.String(http.MethodTrace),
}

// methodKV provides an O(1) function for creating
// a core.KeyValue representing the http method.
//
// in best case no construction of a KeyValue will
// be necessary
func methodKV(r *http.Request) label.KeyValue {
	if kv, ok := methods[r.Method]; ok {
		return kv
	}
	return label.String("http.method", r.Method)
}
