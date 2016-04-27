package server

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/cmd/clairclt/docker"
	"github.com/coreos/clair/cmd/clairclt/docker/httpclient"
	"github.com/spf13/viper"
)

//Serve run a local server with the fileserver and the reverse proxy
func Serve(sURL string) error {

	go func() {
		http.Handle("/v2/", newSingleHostReverseProxy())
		http.Handle("/local/", http.StripPrefix("/local", restrictedFileServer(docker.TmpLocal())))

		listener := tcpListener(sURL)
		logrus.Info("Starting Server on ", listener.Addr())

		if err := http.Serve(listener, nil); err != nil {
			logrus.Fatalf("local server error: %v", err)
		}
	}()
	//sleep needed to wait the server start. Maybe use a channel for that
	time.Sleep(5 * time.Millisecond)
	return nil
}

func tcpListener(sURL string) (listener net.Listener) {
	listener, err := net.Listen("tcp", sURL)
	if err != nil {
		logrus.Fatalf("cannot instanciate listener: %v", err)
	}

	if viper.GetInt("hyperclair.port") == 0 {
		port := strings.Split(listener.Addr().String(), ":")[1]
		logrus.Debugf("Update local server port from %q to %q", "0", port)
		viper.Set("hyperclair.port", port)
	}

	return
}

func restrictedFileServer(path string) http.Handler {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		os.Mkdir(path, 0777)
	}

	fc := func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir(path)).ServeHTTP(w, r)
	}
	return http.HandlerFunc(fc)
}

func newSingleHostReverseProxy() *httputil.ReverseProxy {
	director := func(request *http.Request) {

		var validID = regexp.MustCompile(`.*/blobs/(.*)$`)
		u := request.URL.Path
		logrus.Debugf("request url: %v", u)
		if !validID.MatchString(u) {
			logrus.Errorf("cannot parse url: %v", u)
		}

		host, _ := docker.GetRegistryMapping(validID.FindStringSubmatch(u)[1])
		out, _ := url.Parse(host)
		request.URL.Scheme = out.Scheme
		request.URL.Host = out.Host
		client := httpclient.Get()
		req, _ := http.NewRequest("HEAD", request.URL.String(), nil)
		resp, err := client.Do(req)
		if err != nil {
			logrus.Errorf("response error: %v", err)
			return
		}

		if resp.StatusCode == http.StatusUnauthorized {
			logrus.Info("pull from clair is unauthorized")
			docker.AuthenticateResponse(resp, request)
		}

		r, _ := http.NewRequest("GET", request.URL.String(), nil)
		r.Header.Set("Authorization", request.Header.Get("Authorization"))
		r.Header.Set("Accept-Encoding", request.Header.Get("Accept-Encoding"))
		*request = *r
	}
	return &httputil.ReverseProxy{
		Director: director,
	}
}
