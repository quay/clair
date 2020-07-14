package config

import "encoding/base64"

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
	Intraservice []byte `yaml:"intraservice" json:"intraservice"`
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (a *AuthKeyserver) UnmarshalYAML(f func(interface{}) error) error {
	var m struct {
		API          string `yaml:"api"`
		Intraservice string `yaml:"intraservice"`
	}
	if err := f(&m); err != nil {
		return nil
	}
	a.API = m.API
	s, err := base64.StdEncoding.DecodeString(m.Intraservice)
	if err != nil {
		return err
	}
	a.Intraservice = s
	return nil
}

// AuthPSK is the configuration for doing pre-shared key based authentication.
//
// The "Issuer" key is what the service expects to verify as the "issuer claim.
type AuthPSK struct {
	Key    []byte `yaml:"key" json:"key"`
	Issuer string `yaml:"iss" json:"issuer"`
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (a *AuthPSK) UnmarshalYAML(f func(interface{}) error) error {
	var m struct {
		Issuer string `yaml:"iss" json:"issuer"`
		Key    string `yaml:"key" json:"key"`
	}
	if err := f(&m); err != nil {
		return nil
	}
	a.Issuer = m.Issuer
	s, err := base64.StdEncoding.DecodeString(m.Key)
	if err != nil {
		return err
	}
	a.Key = s
	return nil
}
