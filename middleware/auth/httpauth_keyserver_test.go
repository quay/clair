package auth

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	// KeyserverAPI indicates the root of a keyserver protocol server. For a
	// Project Quay instance, this is probably "http://server/keys/".
	keyserverAPI = flag.String("keyserver", "", "URI for a server implementing the jwtproxy keyserver protocol.")
)

// KeyserverConfig is the data cached for integration testing.
type keyserverConfig struct {
	JWK        jose.JSONWebKey
	URI        string
	Expiration time.Time
}

// Load loads the Config from the named file, creating it if it does not exist.
func (c *keyserverConfig) Load(t *testing.T, file string) {
	kf, err := os.OpenFile(file, os.O_CREATE|os.O_RDWR, 0640)
	if err != nil {
		t.Fatal(err)
	}
	defer kf.Close()
	fi, err := kf.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() == 0 {
		if *keyserverAPI == "" {
			t.Skip("'keyserver' flag not provided")
		}
		c.URI = *keyserverAPI
		c.JWK = newJWK(t)
		c.Expiration = time.Now().AddDate(1, 0, 0)
		if err := json.NewEncoder(kf).Encode(c); err != nil {
			t.Fatal(err)
		}
		kf.Sync()
		return
	}
	if err := json.NewDecoder(kf).Decode(c); err != nil {
		t.Fatal(err)
	}
}

// Regen creates a new key and writes it out to the specified file.
func (c *keyserverConfig) Regen(t *testing.T, file string) {
	kf, err := os.OpenFile(file, os.O_WRONLY, 0640)
	if err != nil {
		t.Fatal(err)
	}
	defer kf.Close()
	c.JWK = newJWK(t)
	c.Expiration = time.Now().AddDate(1, 0, 0)
	if err := json.NewEncoder(kf).Encode(c); err != nil {
		t.Fatal(err)
	}
	kf.Sync()
}

// Public returns the public key.
func (c *keyserverConfig) Public() jose.JSONWebKey {
	return c.JWK.Public()
}

// Signer returns a Signer using the key specified in the config.
func (c *keyserverConfig) Signer() (jose.Signer, error) {
	sk := jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(c.JWK.Algorithm),
		Key:       c.JWK.Key,
	}
	opts := jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey("kid"): c.JWK.KeyID,
		},
	}
	return jose.NewSigner(sk, &opts)
}

// TestKeyserver runs a test against a live Quay keyserver.
func TestKeyserver(t *testing.T) {
	t.Parallel()
	const (
		iss        = `clair_integration`
		configfile = `testdata/keyserver.config`
	)
	ctx, done := context.WithCancel(context.Background())
	defer done()

	// Stash our keyserver config and re-use it if present.
	var Config keyserverConfig
	Config.Load(t, configfile)
	root, err := url.Parse(Config.URI)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := Config.Signer()
	if err != nil {
		t.Fatal(err)
	}

	// Print what we're doing.
	t.Logf("using API rooted at: %v", root)
	t.Logf("using key id: %v", Config.JWK.KeyID)

	// Test server liveness, bail if not.
	tctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(tctx, http.MethodGet, root.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if res != nil {
		// Don't actually care about the response.
		res.Body.Close()
	}
	if err != nil {
		// TODO Decide if this should be hidden behind a tag like the claircore
		// integration tests, or just skipped if setup is missing.
		t.Skipf("skipping because of keyserver error: %v", err)
	}

	keyURL, err := root.Parse(path.Join("services", iss, "keys", Config.JWK.KeyID))
	if err != nil {
		t.Fatal(err)
	}
Install:
	// Keep asking for updates on this key. Once it's in place, we'll construct
	// an AuthCheck to use this key and server.
	for {
		res, err = http.DefaultClient.Get(keyURL.String())
		if res != nil {
			defer res.Body.Close()
		}
		if err != nil {
			t.Fatal(err)
		}
		switch res.StatusCode {
		// If OK, check the expiration on our key and optionally rotate it.
		case http.StatusOK:
			t.Log("key correctly installed")
			if Config.Expiration.Sub(time.Now()).Hours() > float64(7*24) {
				break Install
			}
			t.Log("key expiring within a week, rotating.")
			Config.Regen(t, configfile)
			// If we fall through here, the new key with be signed with the
			// previous one, meaning it should be chained properly and installed
			// without user interaction.
			fallthrough
		// If not found, upload the key as an initial upload.
		case http.StatusNotFound:
			t.Logf("uploading key %v", Config.JWK.KeyID)
			et := strconv.FormatInt(Config.Expiration.Unix(), 10)
			keyURL.RawQuery = url.Values{"expiration": {et}}.Encode()
			audURI, err := root.Parse("/")
			if err != nil {
				t.Fatal(err)
			}
			aud := strings.TrimRight(audURI.String(), "/")

			keyjson, err := json.Marshal(Config.Public())
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			cl := jwt.Claims{
				Issuer:    iss,
				Audience:  jwt.Audience{aud},
				IssuedAt:  jwt.NewNumericDate(now),
				Expiry:    jwt.NewNumericDate(now.Add(10 * time.Minute)),
				NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
			}

			auth, err := jwt.Signed(signer).Claims(cl).Claims(jti()).CompactSerialize()
			if err != nil {
				t.Fatal(err)
			}
			tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			pr, err := http.NewRequestWithContext(tctx, http.MethodPut, keyURL.String(), bytes.NewReader(keyjson))
			if err != nil {
				t.Fatal(err)
			}
			pr.Header.Set("content-type", "application/json")
			pr.Header.Set("authorization", "Bearer "+auth)

			res, err := http.DefaultClient.Do(pr)
			if res != nil {
				defer res.Body.Close()
			}
			if err != nil {
				t.Fatal(err)
			}

			if res.StatusCode != http.StatusAccepted {
				t.Fatalf("unexpected response: %d %s", res.StatusCode, res.Status)
			}
		// If conflicted, prompt the user to go approve the key.
		case http.StatusConflict:
			prompt, err := root.Parse("../superuser/?tab=servicekeys")
			if err != nil {
				t.Error(err)
			}
			// This is bad form, but we need to prompt for user interaction.
			fmt.Fprintf(os.Stderr, "key %q awaiting approval: %v\n", Config.JWK.KeyID, prompt)
			time.Sleep(10 * time.Second)
		// If forbidden, nuke the key and restart.
		case http.StatusForbidden:
			t.Logf("key %q expired, restarting test", Config.JWK.KeyID)
			if *keyserverAPI == "" {
				*keyserverAPI = Config.URI
			}
			os.Remove(configfile)
			TestKeyserver(t)
			return
		// If any other status, bail.
		default:
			t.Fatal(res.Status)
		}
	}

	now := time.Now()
	ks, err := NewQuayKeyserver(root.String())
	if err != nil {
		t.Fatal(err)
	}

	// Construct and sign a request using the live key.
	const checkAud = `http://example.com`
	req, err = http.NewRequest(http.MethodGet, checkAud+"/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	cl := jwt.Claims{
		Issuer:    iss,
		Audience:  jwt.Audience{checkAud},
		IssuedAt:  jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(+5 * time.Second)),
		NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
	}
	auth, err := jwt.Signed(signer).Claims(cl).CompactSerialize()
	if err != nil {
		t.Error(err)
	}
	req.Header.Set("authorization", "Bearer "+auth)

	// Finally, check that we can fetch and validate with the key.
	if !ks.Check(ctx, req) {
		t.Error("check failed")
	}
}

type JTI struct {
	JTI string `json:"jti"`
}

// Jti returns a claim containing a random JWT ID.
func jti() JTI {
	b := make([]byte, 16)
	if _, err := io.ReadFull(crand.Reader, b); err != nil {
		panic(err)
	}
	return JTI{JTI: hex.EncodeToString(b)}
}

// NewJWK generates and returns a new JWK.
func newJWK(t *testing.T) jose.JSONWebKey {
	const alg = jose.RS256
	// generate an ID
	b := make([]byte, 8)
	if _, err := io.ReadFull(crand.Reader, b); err != nil {
		t.Fatal(err)
	}
	kid := hex.EncodeToString(b)
	// generate a key
	key, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: string(alg), Use: "sig"}
	if !jwk.Valid() {
		t.Fatal("jwk not valid")
	}
	return jwk
}
