package config

import (
	"encoding"
	"encoding/base64"
)

// Base64 is a byte slice that encodes to and from base64-encoded strings.
type Base64 []byte

var (
	_ encoding.TextMarshaler   = (*Base64)(nil)
	_ encoding.TextUnmarshaler = (*Base64)(nil)
)

// MarshalText implements encoding.TextMarshaler.
func (b *Base64) MarshalText() ([]byte, error) {
	sz := base64.StdEncoding.EncodedLen(len(*b))
	out := make([]byte, sz)
	base64.StdEncoding.Encode(out, *b)
	return out, nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (b *Base64) UnmarshalText(in []byte) error {
	sz := base64.StdEncoding.DecodedLen(len(in))
	s := make([]byte, sz)
	n, err := base64.StdEncoding.Decode(s, in)
	if err != nil {
		return err
	}
	*b = s[:n]
	return nil
}

// Auth holds the specific configs for different authentication methods.
//
// These should be pointers to structs, so that it's possible to distinguish
// between "absent" and "present and misconfigured."
type Auth struct {
	PSK       *AuthPSK       `yaml:"psk,omitempty" json:"psk,omitempty"`
	Keyserver *AuthKeyserver `yaml:"keyserver,omitempty" json:"keyserver,omitempty"`
}

// Any reports whether any sort of authentication is configured.
func (a Auth) Any() bool {
	return a.PSK != nil ||
		a.Keyserver != nil
}

// AuthKeyserver is the configuration for doing authentication with the Quay
// keyserver protocol.
//
// The "Intraservice" key is only needed when the overall config mode is not
// "combo".
type AuthKeyserver struct {
	API          string `yaml:"api" json:"api"`
	Intraservice Base64 `yaml:"intraservice" json:"intraservice"`
}

// AuthPSK is the configuration for doing pre-shared key based authentication.
//
// The "Issuer" key is what the service expects to verify as the "issuer" claim.
type AuthPSK struct {
	Key    Base64   `yaml:"key" json:"key"`
	Issuer []string `yaml:"iss" json:"iss"`
}
