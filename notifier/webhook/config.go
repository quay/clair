package webhook

import (
	"fmt"
	"net/http"
	"net/url"
)

// Config provides configuration for an Webhook deliverer.
type Config struct {
	// the URL where our webhook will be delivered
	Target string `yaml:"target"`
	target *url.URL
	// the callback url where notifications can be received
	// the notification will be appended to this url
	Callback string `yaml:"callback"`
	callback *url.URL
	// any htp headers necessary for the request to Target
	Headers http.Header `yaml:"headers"`
	// whether the webhook deliverer will sign out going.
	// if true webhooks will be sent with a jwt signed by
	// the notifier's private key.
	Signed bool
}

// Validate will return a copy of the Config on success.
// If any validation fails an error will be returned.
func (c *Config) Validate() (Config, error) {
	conf := *c
	target, err := url.Parse(c.Target)
	if err != nil {
		return conf, fmt.Errorf("failed to parse target url")
	}
	conf.target = target

	callback, err := url.Parse(c.Callback)
	if err != nil {
		return conf, fmt.Errorf("failed to parse callback url")
	}
	conf.callback = callback
	return conf, nil
}
