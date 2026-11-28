// Package ui is a barebones HTML UI for clair.
package ui

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/quay/clair/v4/cmd"
)

type V1 struct {
	mux  *http.ServeMux
	tmpl *template.Template
	sys  fs.FS
	ctx  map[string]*PageContext
}

type PageContext struct {
	Title string
	Aux   map[string]interface{}
}

var (
	_ http.Handler = (*V1)(nil)

	//go:embed assets/v1
	v1assets embed.FS
)

func New() (*V1, error) {
	var err error
	h := V1{
		mux: http.NewServeMux(),
	}
	h.sys, err = fs.Sub(v1assets, "assets/v1")
	if err != nil {
		return nil, err
	}
	t := template.New("")
	t.Funcs(template.FuncMap(map[string]interface{}{
		"Version": func() string {
			return cmd.Version
		},
	}))
	h.tmpl, err = t.ParseFS(h.sys, "*.tmpl", "header", "footer")
	if err != nil {
		return nil, err
	}

	h.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimLeft(r.URL.Path, "/")
		try := []string{
			p + ".tmpl",
			path.Join(p, "index.tmpl"),
		}
		for _, n := range try {
			t := h.tmpl.Lookup(n)
			if t == nil {
				continue
			}
			w.Header().Set("content-type", "text/html")
			if err := t.Execute(w, h.ctx[n]); err != nil {
				srv := r.Context().Value(http.ServerContextKey).(*http.Server)
				srv.ErrorLog.Printf("error executing template %q: %v", n, err)
			}
			return
		}
		if f, err := h.sys.Open(p); err == nil {
			defer f.Close()
			io.Copy(w, f)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	h.ctx = map[string]*PageContext{
		"index.tmpl": {
			Title: "Clair",
		},
	}

	return &h, nil
}

func (h *V1) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost:
	default:
		http.Error(w, fmt.Sprintf("disallowed method: %q", r.Method), http.StatusMethodNotAllowed)
	}
	h.mux.ServeHTTP(w, r)
}
