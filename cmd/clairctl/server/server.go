package server

import (
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/cmd/clairctl/docker"
	"github.com/coreos/clair/cmd/clairctl/server/reverseProxy"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
)

type handler func(rw http.ResponseWriter, req *http.Request) error

var router *mux.Router

//Serve run a local server with the fileserver and the reverse proxy
func Serve(sURL string) error {

	go func() {
		restrictedFileServer := func(path string) http.Handler {
			if _, err := os.Stat(path); os.IsNotExist(err) {
				os.Mkdir(path, 0777)
			}

			fc := func(w http.ResponseWriter, r *http.Request) {
				http.FileServer(http.Dir(path)).ServeHTTP(w, r)
			}
			return http.HandlerFunc(fc)
		}

		router.PathPrefix("/v2/local").Handler(http.StripPrefix("/v2/local", restrictedFileServer(docker.TmpLocal()))).Methods("GET")
		listener, err := net.Listen("tcp", sURL)
		if err != nil {
			logrus.Fatalf("cannot instanciate listener: %v", err)
		}

		if viper.GetInt("hyperclair.port") == 0 {
			port := strings.Split(listener.Addr().String(), ":")[1]
			logrus.Debugf("Update local server port from %q to %q", "0", port)
			viper.Set("hyperclair.port", port)
		}
		logrus.Info("Starting Server on ", listener.Addr())

		if err := http.Serve(listener, nil); err != nil {
			logrus.Fatalf("local server error: %v", err)
		}
	}()
	//sleep needed to wait the server start. Maybe use a channel for that
	time.Sleep(5 * time.Millisecond)
	return nil
}

func reverseRegistryHandler() http.HandlerFunc {
	filters := []reverseProxy.FilterFunc{}
	proxy := reverseProxy.NewReverseProxy(filters)
	return proxy.ServeHTTP
}

func init() {

	router = mux.NewRouter()
	router.PathPrefix("/v2").Path("/{repository}/{name}/blobs/{digest}").HandlerFunc(reverseRegistryHandler())
	http.Handle("/", router)
}
