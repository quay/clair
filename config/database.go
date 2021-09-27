package config

import (
	"net/url"
	"os"
	"strings"
)

func checkDSN(s string) (w []Warning, err error) {
	switch {
	case s == "":
		// Nothing specified, make sure something's in the environment.
		envSet := false
		for _, k := range os.Environ() {
			if strings.HasPrefix(k, `PG`) {
				envSet = true
				break
			}
		}
		if !envSet {
			w = append(w, Warning{
				msg: "connection string is empty and no relevant environment variables found",
			})
		}
	case strings.HasPrefix(s, "postgresql://"):
		// Looks like a URL
		if _, err := url.Parse(s); err != nil {
			w = append(w, Warning{inner: err})
		}
	case strings.ContainsRune(s, '='):
		// Looks like a DSN
	case strings.Contains(s, `://`):
		w = append(w, Warning{
			msg: "connection string looks like a URL but scheme is unrecognized",
		})
	default:
		w = append(w, Warning{
			msg: "unable to make sense of connection string",
		})
	}
	return w, nil
}
