package config

import (
	"bytes"
	"crypto/tls"
	"net"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestTLS(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SSL_CERT_FILE", filepath.Join(dir, `cert.pem`))

	out, err := exec.Command(`go`, `env`, `GOROOT`).CombinedOutput()
	if err != nil {
		t.Logf("output:\n%s", string(out))
		t.Fatal(err)
	}
	goroot := string(bytes.TrimSpace(out))
	cmd := exec.Command(`go`, `run`,
		filepath.Join(goroot, "/src/crypto/tls/generate_cert.go"),
		"--rsa-bits=2048",
		"--host=127.0.0.1,::1,example.com",
		"--ca",
		"--start-date=Jan 1 00:00:00 1970",
		"--duration=1000000h",
	)
	cmd.Dir = dir
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		t.Logf("stderr:\n%s", errBuf.String())
		t.Fatal(err)
	}

	tlscfg := TLS{
		Cert: filepath.Join(dir, `cert.pem`),
		Key:  filepath.Join(dir, `key.pem`),
	}
	tlscfg.RootCA = tlscfg.Cert
	cfg, err := tlscfg.Config()
	if err != nil {
		t.Fatal(err)
	}

	checkTLSVersions(t, cfg)
}

func checkTLSVersions(t *testing.T, cfg *tls.Config) {
	t.Helper()
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	addr := l.Addr()
	l = tls.NewListener(l, cfg)
	done, gone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(gone)
		for {
			select {
			case <-done:
				return
			default:
			}
			c, err := l.Accept()
			if err != nil {
				t.Error(err)
				return
			}
			t.Log("connected")
			tc := c.(*tls.Conn)
			if err := tc.Handshake(); err != nil {
				t.Log(err)
				continue
			}
			st := tc.ConnectionState()
			t.Logf("version: %v", st.Version)
			c.Close()
		}
	}()

	for _, tc := range []struct {
		Version uint16
		FailOK  bool
	}{
		{tls.VersionTLS10, true},
		{tls.VersionTLS11, true},
		{tls.VersionTLS12, false},
		{tls.VersionTLS13, false},
	} {
		cfg := cfg.Clone()
		cfg.Certificates = nil
		cfg.MaxVersion = tc.Version
		_, err := tls.Dial(addr.Network(), addr.String(), cfg)
		if err != nil {
			t.Logf("%v: %v", tc.Version, err)
			if !tc.FailOK {
				t.Fail()
			}
		}
	}
	close(done)
	<-gone
}
