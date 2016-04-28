package httpclient

import (
	"crypto/tls"
	"net/http"

	"github.com/spf13/viper"
)

var client *http.Client

//Get create a http.Client with Transport configuration
func Get() *http.Client {

	if client == nil {
		tr := &http.Transport{
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: viper.GetBool("auth.insecureSkipVerify")},
			DisableCompression: true,
		}
		client = &http.Client{Transport: tr}
	}

	return client
}
