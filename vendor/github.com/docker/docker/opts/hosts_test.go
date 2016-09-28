package opts

import (
	"fmt"
	"testing"
)

func TestParseHost(t *testing.T) {
	invalid := []string{
		"anything",
		"something with spaces",
		"://",
		"unknown://",
		"tcp://:port",
		"tcp://invalid",
		"tcp://invalid:port",
	}

	valid := map[string]string{
		"":                         DefaultHost,
		" ":                        DefaultHost,
		"  ":                       DefaultHost,
		"fd://":                    "fd://",
		"fd://something":           "fd://something",
		"tcp://host:":              fmt.Sprintf("tcp://host:%d", DefaultHTTPPort),
		"tcp://":                   DefaultTCPHost,
		"tcp://:2375":              fmt.Sprintf("tcp://%s:2375", DefaultHTTPHost),
		"tcp://:2376":              fmt.Sprintf("tcp://%s:2376", DefaultHTTPHost),
		"tcp://0.0.0.0:8080":       "tcp://0.0.0.0:8080",
		"tcp://192.168.0.0:12000":  "tcp://192.168.0.0:12000",
		"tcp://192.168:8080":       "tcp://192.168:8080",
		"tcp://0.0.0.0:1234567890": "tcp://0.0.0.0:1234567890", // yeah it's valid :P
		" tcp://:7777/path ":       fmt.Sprintf("tcp://%s:7777/path", DefaultHTTPHost),
		"tcp://docker.com:2375":    "tcp://docker.com:2375",
		"unix://":                  "unix://" + DefaultUnixSocket,
		"unix://path/to/socket":    "unix://path/to/socket",
		"npipe://":                 "npipe://" + DefaultNamedPipe,
		"npipe:////./pipe/foo":     "npipe:////./pipe/foo",
	}

	for _, value := range invalid {
		if _, err := ParseHost(false, value); err == nil {
			t.Errorf("Expected an error for %v, got [nil]", value)
		}
	}

	for value, expected := range valid {
		if actual, err := ParseHost(false, value); err != nil || actual != expected {
			t.Errorf("Expected for %v [%v], got [%v, %v]", value, expected, actual, err)
		}
	}
}

func TestParseDockerDaemonHost(t *testing.T) {
	invalids := map[string]string{
		"0.0.0.0":                       "Invalid bind address format: 0.0.0.0",
		"tcp:a.b.c.d":                   "Invalid bind address format: tcp:a.b.c.d",
		"tcp:a.b.c.d/path":              "Invalid bind address format: tcp:a.b.c.d/path",
		"udp://127.0.0.1":               "Invalid bind address format: udp://127.0.0.1",
		"udp://127.0.0.1:2375":          "Invalid bind address format: udp://127.0.0.1:2375",
		"tcp://unix:///run/docker.sock": "Invalid bind address format: unix",
		" tcp://:7777/path ":            "Invalid bind address format:  tcp://:7777/path ",
		"tcp":                           "Invalid bind address format: tcp",
		"unix":                          "Invalid bind address format: unix",
		"fd":                            "Invalid bind address format: fd",
		"":                              "Invalid bind address format: ",
	}
	valids := map[string]string{
		"0.0.0.1:":                    "tcp://0.0.0.1:2375",
		"0.0.0.1:5555":                "tcp://0.0.0.1:5555",
		"0.0.0.1:5555/path":           "tcp://0.0.0.1:5555/path",
		"[::1]:":                      "tcp://[::1]:2375",
		"[::1]:5555/path":             "tcp://[::1]:5555/path",
		"[0:0:0:0:0:0:0:1]:":          "tcp://[0:0:0:0:0:0:0:1]:2375",
		"[0:0:0:0:0:0:0:1]:5555/path": "tcp://[0:0:0:0:0:0:0:1]:5555/path",
		":6666":                   fmt.Sprintf("tcp://%s:6666", DefaultHTTPHost),
		":6666/path":              fmt.Sprintf("tcp://%s:6666/path", DefaultHTTPHost),
		"tcp://":                  DefaultTCPHost,
		"tcp://:7777":             fmt.Sprintf("tcp://%s:7777", DefaultHTTPHost),
		"tcp://:7777/path":        fmt.Sprintf("tcp://%s:7777/path", DefaultHTTPHost),
		"unix:///run/docker.sock": "unix:///run/docker.sock",
		"unix://":                 "unix://" + DefaultUnixSocket,
		"fd://":                   "fd://",
		"fd://something":          "fd://something",
		"localhost:":              "tcp://localhost:2375",
		"localhost:5555":          "tcp://localhost:5555",
		"localhost:5555/path":     "tcp://localhost:5555/path",
	}
	for invalidAddr, expectedError := range invalids {
		if addr, err := parseDockerDaemonHost(invalidAddr); err == nil || err.Error() != expectedError {
			t.Errorf("tcp %v address expected error %v return, got %s and addr %v", invalidAddr, expectedError, err, addr)
		}
	}
	for validAddr, expectedAddr := range valids {
		if addr, err := parseDockerDaemonHost(validAddr); err != nil || addr != expectedAddr {
			t.Errorf("%v -> expected %v, got (%v) addr (%v)", validAddr, expectedAddr, err, addr)
		}
	}
}

func TestParseTCP(t *testing.T) {
	var (
		defaultHTTPHost = "tcp://127.0.0.1:2376"
	)
	invalids := map[string]string{
		"0.0.0.0":              "Invalid bind address format: 0.0.0.0",
		"tcp:a.b.c.d":          "Invalid bind address format: tcp:a.b.c.d",
		"tcp:a.b.c.d/path":     "Invalid bind address format: tcp:a.b.c.d/path",
		"udp://127.0.0.1":      "Invalid proto, expected tcp: udp://127.0.0.1",
		"udp://127.0.0.1:2375": "Invalid proto, expected tcp: udp://127.0.0.1:2375",
	}
	valids := map[string]string{
		"":                            defaultHTTPHost,
		"tcp://":                      defaultHTTPHost,
		"0.0.0.1:":                    "tcp://0.0.0.1:2376",
		"0.0.0.1:5555":                "tcp://0.0.0.1:5555",
		"0.0.0.1:5555/path":           "tcp://0.0.0.1:5555/path",
		":6666":                       "tcp://127.0.0.1:6666",
		":6666/path":                  "tcp://127.0.0.1:6666/path",
		"tcp://:7777":                 "tcp://127.0.0.1:7777",
		"tcp://:7777/path":            "tcp://127.0.0.1:7777/path",
		"[::1]:":                      "tcp://[::1]:2376",
		"[::1]:5555":                  "tcp://[::1]:5555",
		"[::1]:5555/path":             "tcp://[::1]:5555/path",
		"[0:0:0:0:0:0:0:1]:":          "tcp://[0:0:0:0:0:0:0:1]:2376",
		"[0:0:0:0:0:0:0:1]:5555":      "tcp://[0:0:0:0:0:0:0:1]:5555",
		"[0:0:0:0:0:0:0:1]:5555/path": "tcp://[0:0:0:0:0:0:0:1]:5555/path",
		"localhost:":                  "tcp://localhost:2376",
		"localhost:5555":              "tcp://localhost:5555",
		"localhost:5555/path":         "tcp://localhost:5555/path",
	}
	for invalidAddr, expectedError := range invalids {
		if addr, err := parseTCPAddr(invalidAddr, defaultHTTPHost); err == nil || err.Error() != expectedError {
			t.Errorf("tcp %v address expected error %v return, got %s and addr %v", invalidAddr, expectedError, err, addr)
		}
	}
	for validAddr, expectedAddr := range valids {
		if addr, err := parseTCPAddr(validAddr, defaultHTTPHost); err != nil || addr != expectedAddr {
			t.Errorf("%v -> expected %v, got %v and addr %v", validAddr, expectedAddr, err, addr)
		}
	}
}

func TestParseInvalidUnixAddrInvalid(t *testing.T) {
	if _, err := parseSimpleProtoAddr("unix", "tcp://127.0.0.1", "unix:///var/run/docker.sock"); err == nil || err.Error() != "Invalid proto, expected unix: tcp://127.0.0.1" {
		t.Fatalf("Expected an error, got %v", err)
	}
	if _, err := parseSimpleProtoAddr("unix", "unix://tcp://127.0.0.1", "/var/run/docker.sock"); err == nil || err.Error() != "Invalid proto, expected unix: tcp://127.0.0.1" {
		t.Fatalf("Expected an error, got %v", err)
	}
	if v, err := parseSimpleProtoAddr("unix", "", "/var/run/docker.sock"); err != nil || v != "unix:///var/run/docker.sock" {
		t.Fatalf("Expected an %v, got %v", v, "unix:///var/run/docker.sock")
	}
}
