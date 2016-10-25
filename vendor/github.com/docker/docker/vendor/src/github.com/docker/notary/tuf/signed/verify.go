package signed

import (
	"errors"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/docker/go/canonical/json"
	"github.com/docker/notary/tuf/data"
)

// Various basic signing errors
var (
	ErrMissingKey   = errors.New("tuf: missing key")
	ErrNoSignatures = errors.New("tuf: data has no signatures")
	ErrInvalid      = errors.New("tuf: signature verification failed")
	ErrWrongMethod  = errors.New("tuf: invalid signature type")
	ErrUnknownRole  = errors.New("tuf: unknown role")
	ErrWrongType    = errors.New("tuf: meta file has wrong type")
)

// VerifyRoot checks if a given root file is valid against a known set of keys.
// Threshold is always assumed to be 1
func VerifyRoot(s *data.Signed, minVersion int, keys map[string]data.PublicKey) error {
	if len(s.Signatures) == 0 {
		return ErrNoSignatures
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(s.Signed, &decoded); err != nil {
		return err
	}
	msg, err := json.MarshalCanonical(decoded)
	if err != nil {
		return err
	}

	for _, sig := range s.Signatures {
		// method lookup is consistent due to Unmarshal JSON doing lower case for us.
		method := sig.Method
		verifier, ok := Verifiers[method]
		if !ok {
			logrus.Debugf("continuing b/c signing method is not supported for verify root: %s\n", sig.Method)
			continue
		}

		key, ok := keys[sig.KeyID]
		if !ok {
			logrus.Debugf("continuing b/c signing key isn't present in keys: %s\n", sig.KeyID)
			continue
		}

		if err := verifier.Verify(key, sig.Signature, msg); err != nil {
			logrus.Debugf("continuing b/c signature was invalid\n")
			continue
		}
		// threshold of 1 so return on first success
		return verifyMeta(s, data.CanonicalRootRole, minVersion)
	}
	return ErrRoleThreshold{}
}

// Verify checks the signatures and metadata (expiry, version) for the signed role
// data
func Verify(s *data.Signed, role data.BaseRole, minVersion int) error {
	if err := verifyMeta(s, role.Name, minVersion); err != nil {
		return err
	}
	return VerifySignatures(s, role)
}

func verifyMeta(s *data.Signed, role string, minVersion int) error {
	sm := &data.SignedCommon{}
	if err := json.Unmarshal(s.Signed, sm); err != nil {
		return err
	}
	if !data.ValidTUFType(sm.Type, role) {
		return ErrWrongType
	}
	if IsExpired(sm.Expires) {
		logrus.Errorf("Metadata for %s expired", role)
		return ErrExpired{Role: role, Expired: sm.Expires.Format("Mon Jan 2 15:04:05 MST 2006")}
	}
	if sm.Version < minVersion {
		return ErrLowVersion{sm.Version, minVersion}
	}

	return nil
}

// IsExpired checks if the given time passed before the present time
func IsExpired(t time.Time) bool {
	return t.Before(time.Now())
}

// VerifySignatures checks the we have sufficient valid signatures for the given role
func VerifySignatures(s *data.Signed, roleData data.BaseRole) error {
	if len(s.Signatures) == 0 {
		return ErrNoSignatures
	}

	if roleData.Threshold < 1 {
		return ErrRoleThreshold{}
	}
	logrus.Debugf("%s role has key IDs: %s", roleData.Name, strings.Join(roleData.ListKeyIDs(), ","))

	// remarshal the signed part so we can verify the signature, since the signature has
	// to be of a canonically marshalled signed object
	var decoded map[string]interface{}
	if err := json.Unmarshal(s.Signed, &decoded); err != nil {
		return err
	}
	msg, err := json.MarshalCanonical(decoded)
	if err != nil {
		return err
	}

	valid := make(map[string]struct{})
	for _, sig := range s.Signatures {
		logrus.Debug("verifying signature for key ID: ", sig.KeyID)
		key, ok := roleData.Keys[sig.KeyID]
		if !ok {
			logrus.Debugf("continuing b/c keyid lookup was nil: %s\n", sig.KeyID)
			continue
		}
		// method lookup is consistent due to Unmarshal JSON doing lower case for us.
		method := sig.Method
		verifier, ok := Verifiers[method]
		if !ok {
			logrus.Debugf("continuing b/c signing method is not supported: %s\n", sig.Method)
			continue
		}

		if err := verifier.Verify(key, sig.Signature, msg); err != nil {
			logrus.Debugf("continuing b/c signature was invalid\n")
			continue
		}
		valid[sig.KeyID] = struct{}{}

	}
	if len(valid) < roleData.Threshold {
		return ErrRoleThreshold{}
	}

	return nil
}
