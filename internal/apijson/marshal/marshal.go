// Package marshal holds json/v2 Marshal machinery for v1 HTTP API types.
//
// All these functions look like long ways to do what the json package already
// does. That's true currently, but it allows us to change the claircore types
// and not have the serialization change.
package marshal

import (
	"encoding/base64"
	jsonv1 "encoding/json"
	"reflect"
	"time"
	"unicode/utf8"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"

	types "github.com/quay/clair/v4/httptransport/types/v1"
	"github.com/quay/clair/v4/internal/apijson/keys"
	"github.com/quay/clair/v4/internal/json"
	"github.com/quay/clair/v4/internal/json/jsontext"
)

// Manifest is used with [json.MarshalToFunc] to marshal a [claircore.Manifest].
func Manifest(enc *jsontext.Encoder, v *claircore.Manifest) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)

	if err := enc.WriteToken(jsontext.String(keys.Hash)); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(v.Hash.String())); err != nil {
		return err
	}

	if v.Layers != nil {
		if err := enc.WriteToken(jsontext.String(keys.Layers)); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.BeginArray); err != nil {
			return err
		}
		defer enc.WriteToken(jsontext.EndArray)

		for _, l := range v.Layers {
			if err := Layer(enc, l); err != nil {
				return err
			}
		}
	}

	return nil
}

// Layer is used with [json.MarshalToFunc] to marshal a [claircore.Layer].
func Layer(enc *jsontext.Encoder, v *claircore.Layer) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)

	if err := enc.WriteToken(jsontext.String(keys.Hash)); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(v.Hash.String())); err != nil {
		return err
	}

	if err := enc.WriteToken(jsontext.String(keys.URI)); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(v.URI)); err != nil {
		return err
	}

	if err := enc.WriteToken(jsontext.String(keys.Headers)); err != nil {
		return err
	}
	if err := json.MarshalEncode(enc, v.Headers); err != nil {
		return err
	}

	return nil
}

// IndexReport is used with [json.MarshalToFunc] to marshal a [claircore.IndexReport].
func IndexReport(enc *jsontext.Encoder, v *claircore.IndexReport) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)

	if err := enc.WriteToken(jsontext.String(keys.ReportHash)); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(v.Hash.String())); err != nil {
		return err
	}

	if err := enc.WriteToken(jsontext.String(keys.State)); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(v.State)); err != nil {
		return err
	}

	if err := enc.WriteToken(jsontext.String(keys.Success)); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Bool(v.Success)); err != nil {
		return err
	}

	if e := v.Err; e != "" {
		if err := enc.WriteToken(jsontext.String(keys.Err)); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(e)); err != nil {
			return err
		}
	}

	if err := doMap(enc, jsontext.String(keys.Packages), v.Packages, Package); err != nil {
		return err
	}
	if err := doMap(enc, jsontext.String(keys.Distributions), v.Distributions, Distribution); err != nil {
		return err
	}
	if err := doMap(enc, jsontext.String(keys.Repository), v.Repositories, Repository); err != nil {
		return err
	}
	if err := doMapArray(enc, jsontext.String(keys.Environments), v.Environments, Environment); err != nil {
		return err
	}

	return nil
}

// Package is used with [json.MarshalToFunc] to marshal a [claircore.Package].
func Package(enc *jsontext.Encoder, v *claircore.Package) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)

	fs := []struct {
		Key   jsontext.Token
		Value string
	}{
		{jsontext.String(keys.ID), v.ID},
		{jsontext.String(keys.Name), v.Name},
		{jsontext.String(keys.Version), v.Version},
		{jsontext.String(keys.Kind), v.Kind},
		{jsontext.String(keys.Module), v.Module},
		{jsontext.String(keys.Arch), v.Arch},
	}
	for _, f := range fs {
		if f.Value == "" {
			continue
		}
		if err := enc.WriteToken(f.Key); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(f.Value)); err != nil {
			return err
		}
	}

	if v.NormalizedVersion.Kind != "" {
		if err := enc.WriteToken(jsontext.String(keys.NormVersion)); err != nil {
			return err
		}
		v, err := v.NormalizedVersion.MarshalText()
		if err != nil {
			return err
		}
		b, err := jsontext.AppendQuote(enc.AvailableBuffer(), v)
		if err != nil {
			return err
		}
		if err := enc.WriteValue(b); err != nil {
			return err
		}
	}

	if v.CPE.Valid() == nil {
		if err := enc.WriteToken(jsontext.String(keys.CPE)); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(v.CPE.String())); err != nil {
			return err
		}
	}

	if src := v.Source; src != nil {
		if err := enc.WriteToken(jsontext.String(keys.Source)); err != nil {
			return err
		}
		if err := json.MarshalEncode(enc, src); err != nil {
			return err
		}
	}

	return nil
}

// Distribution is used with [json.MarshalToFunc] to marshal a [claircore.Distribution].
func Distribution(enc *jsontext.Encoder, v *claircore.Distribution) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)
	fs := []struct {
		Key   jsontext.Token
		Value string
	}{
		{jsontext.String(keys.ID), v.ID},
		{jsontext.String(keys.DID), v.DID},
		{jsontext.String(keys.Name), v.Name},
		{jsontext.String(keys.Version), v.Version},
		{jsontext.String(keys.VersionCodeName), v.VersionCodeName},
		{jsontext.String(keys.VersionID), v.VersionID},
		{jsontext.String(keys.Arch), v.Arch},
		{jsontext.String(keys.PrettyName), v.PrettyName},
	}
	for _, f := range fs {
		if f.Value == "" {
			continue
		}
		if err := enc.WriteToken(f.Key); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(f.Value)); err != nil {
			return err
		}
	}

	if v.CPE.Valid() == nil {
		if err := enc.WriteToken(jsontext.String(keys.CPE)); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(v.CPE.String())); err != nil {
			return err
		}
	}

	return nil
}

// Repository is used with [json.MarshalToFunc] to marshal a [claircore.Repository].
func Repository(enc *jsontext.Encoder, v *claircore.Repository) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)
	fs := []struct {
		Key   jsontext.Token
		Value string
	}{
		{jsontext.String(keys.ID), v.ID},
		{jsontext.String(keys.Name), v.Name},
		{jsontext.String(keys.Key), v.Key},
		{jsontext.String(keys.URI), v.URI},
	}
	for _, f := range fs {
		if f.Value == "" {
			continue
		}
		if err := enc.WriteToken(f.Key); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(f.Value)); err != nil {
			return err
		}
	}

	if v.CPE.Valid() == nil {
		if err := enc.WriteToken(jsontext.String(keys.CPE)); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(v.CPE.String())); err != nil {
			return err
		}
	}

	return nil
}

// Environment is used with [json.MarshalToFunc] to marshal a [claircore.Environment].
func Environment(enc *jsontext.Encoder, v *claircore.Environment) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)
	fs := []struct {
		Key   jsontext.Token
		Value string
	}{
		{jsontext.String(keys.PackageDB), v.PackageDB},
		{jsontext.String(keys.DistributionID), v.DistributionID},
	}
	for _, f := range fs {
		if f.Value == "" {
			continue
		}
		if err := enc.WriteToken(f.Key); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(f.Value)); err != nil {
			return err
		}
	}

	if v.IntroducedIn.Algorithm() != "" {
		if err := enc.WriteToken(jsontext.String(keys.Introduced)); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(v.IntroducedIn.String())); err != nil {
			return err
		}
	}

	if len(v.RepositoryIDs) != 0 {
		if err := enc.WriteToken(jsontext.String(keys.RepositoryIDs)); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.BeginArray); err != nil {
			return err
		}
		defer enc.WriteToken(jsontext.EndArray)
		for _, id := range v.RepositoryIDs {
			if err := enc.WriteToken(jsontext.String(id)); err != nil {
				return err
			}
		}
	}

	return nil
}

// VulnerabilityReport is used with [json.MarshalToFunc] to marshal a [claircore.VulnerabilityReport].
func VulnerabilityReport(enc *jsontext.Encoder, v *claircore.VulnerabilityReport) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)

	if err := enc.WriteToken(jsontext.String(keys.ReportHash)); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(v.Hash.String())); err != nil {
		return err
	}

	if err := doMap(enc, jsontext.String(keys.Packages), v.Packages, Package); err != nil {
		return err
	}
	if err := doMap(enc, jsontext.String(keys.Distributions), v.Distributions, Distribution); err != nil {
		return err
	}
	if err := doMap(enc, jsontext.String(keys.Repository), v.Repositories, Repository); err != nil {
		return err
	}
	if err := doMapArray(enc, jsontext.String(keys.Environments), v.Environments, Environment); err != nil {
		return err
	}
	if err := doMap(enc, jsontext.String(keys.Vulnerabilities), v.Vulnerabilities, Vulnerability); err != nil {
		return err
	}
	if err := doMapArray(enc, jsontext.String(keys.PackageVulnerabilities), v.PackageVulnerabilities, func(enc *jsontext.Encoder, v string) error {
		return enc.WriteToken(jsontext.String(v))
	}); err != nil {
		return err
	}
	if err := doMapArray(enc, jsontext.String(keys.Enrichments), v.Enrichments, func(enc *jsontext.Encoder, v jsonv1.RawMessage) error {
		return enc.WriteValue(jsontext.Value(v))
	}); err != nil {
		return err
	}

	return nil
}

// Vulnerability is used with [json.MarshalToFunc] to marshal a [claircore.Vulnerability].
func Vulnerability(enc *jsontext.Encoder, v *claircore.Vulnerability) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)

	fs := []struct {
		Key   jsontext.Token
		Value string
	}{
		{jsontext.String(keys.ID), v.ID},
		{jsontext.String(keys.Updater), v.Updater},
		{jsontext.String(keys.Name), v.Name},
		{jsontext.String(keys.Description), v.Description},
		{jsontext.String(keys.Links), v.Links},
		{jsontext.String(keys.Severity), v.Severity},
		{jsontext.String(keys.FixedIn), v.FixedInVersion},
	}
	for _, f := range fs {
		if f.Value == "" {
			continue
		}
		if err := enc.WriteToken(f.Key); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(f.Value)); err != nil {
			return err
		}
	}

	if err := enc.WriteToken(jsontext.String(keys.NormSeverity)); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(v.NormalizedSeverity.String())); err != nil {
		return err
	}

	if !v.Issued.IsZero() {
		if err := enc.WriteToken(jsontext.String(keys.Issued)); err != nil {
			return err
		}
		b := enc.AvailableBuffer()
		b = append(b, '"')
		b = v.Issued.AppendFormat(b, time.RFC3339)
		b = append(b, '"')
		if err := enc.WriteValue(b); err != nil {
			return err
		}
	}

	if v.Package != nil {
		if err := enc.WriteToken(jsontext.String(keys.Package)); err != nil {
			return err
		}
		if err := Package(enc, v.Package); err != nil {
			return err
		}
	}
	if v.Dist != nil {
		if err := enc.WriteToken(jsontext.String(keys.Distribution)); err != nil {
			return err
		}
		if err := Distribution(enc, v.Dist); err != nil {
			return err
		}
	}
	if v.Repo != nil {
		if err := enc.WriteToken(jsontext.String(keys.Repository)); err != nil {
			return err
		}
		if err := Repository(enc, v.Repo); err != nil {
			return err
		}
	}

	if v.Range != nil {
		if err := enc.WriteToken(jsontext.String(keys.Range)); err != nil {
			return err
		}
		if err := Range(enc, v.Range); err != nil {
			return err
		}
	}

	if v.ArchOperation != claircore.ArchOp(0) {
		if err := enc.WriteToken(jsontext.String(keys.ArchOp)); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(v.ArchOperation.String())); err != nil {
			return err
		}
	}

	return nil
}

// Range is used with [json.MarshalToFunc] to marshal a [claircore.Range].
func Range(enc *jsontext.Encoder, v *claircore.Range) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)

	f := func(k string, v *claircore.Version) error {
		if v.Kind == "" {
			return nil
		}
		r, err := v.MarshalText()
		if err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(k)); err != nil {
			return err
		}
		b := enc.AvailableBuffer()
		b = append(b, '"')
		b = append(b, r...)
		b = append(b, '"')
		return enc.WriteValue(b)
	}

	if err := f(keys.RangeLower, &v.Lower); err != nil {
		return err
	}
	if err := f(keys.RangeUpper, &v.Upper); err != nil {
		return err
	}
	return nil
}

// Error is used with [json.MarshalToFunc] to marshal a [types.Error].
func Error(enc *jsontext.Encoder, v *types.Error) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)
	code := jsontext.String("code")
	message := jsontext.String("code")

	if err := enc.WriteToken(code); err != nil {
		return err
	}
	var err error
	// Add the status codes numerically here to avoid pulling in the whole http
	// package.
	switch v.Code {
	case 400:
		err = enc.WriteToken(jsontext.String("bad-request"))
	case 404:
		err = enc.WriteToken(jsontext.String("not-found"))
	case 415:
		err = enc.WriteToken(jsontext.String("method-not-allowed"))
	case 429:
		err = enc.WriteToken(jsontext.String("too-many-requests"))
	default:
		err = enc.WriteToken(jsontext.String("internal-error"))
	}
	if err != nil {
		return err
	}

	if err := enc.WriteToken(message); err != nil {
		return err
	}
	b, err := jsontext.AppendQuote(enc.AvailableBuffer(), v.Error())
	if err != nil {
		return err
	}
	if err := enc.WriteValue(b); err != nil {
		return err
	}

	return nil
}

// UpdateOperation is used with [json.MarshalToFunc] to marshal a [driver.UpdateOperation].
func UpdateOperation(enc *jsontext.Encoder, v *driver.UpdateOperation) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)

	if err := enc.WriteToken(jsontext.String("ref")); err != nil {
		return err
	}
	b, err := v.Ref.MarshalText()
	if err != nil {
		return err
	}
	b, err = jsontext.AppendQuote(enc.AvailableBuffer(), b)
	if err != nil {
		return err
	}
	if err := enc.WriteValue(b); err != nil {
		return err
	}

	if err := enc.WriteToken(jsontext.String("updater")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(v.Updater)); err != nil {
		return err
	}

	if err := enc.WriteToken(jsontext.String("fingerprint")); err != nil {
		return err
	}

	if fp := []byte(v.Fingerprint); utf8.Valid(fp) {
		err = enc.WriteToken(jsontext.String(string(v.Fingerprint)))
	} else {
		b := enc.AvailableBuffer()
		b = append(b, '"')
		b = base64.StdEncoding.AppendEncode(b, fp)
		b = append(b, '"')
		err = enc.WriteValue(b)
	}
	if err != nil {
		return err
	}

	if err := enc.WriteToken(jsontext.String("date")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(v.Date.Format(time.RFC3339))); err != nil {
		return err
	}

	if err := enc.WriteToken(jsontext.String("kind")); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(string(v.Kind))); err != nil {
		return err
	}

	return nil
}

// UpdateDiff is used with [json.MarshalToFunc] to marshal a [driver.UpdateDiff].
func UpdateDiff(enc *jsontext.Encoder, v *driver.UpdateDiff) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)

	writeOp := func(k string, op *driver.UpdateOperation) error {
		if err := enc.WriteToken(jsontext.String(k)); err != nil {
			return err
		}
		if err := UpdateOperation(enc, op); err != nil {
			return err
		}
		return nil
	}
	writeSlice := func(k string, vs []claircore.Vulnerability) error {
		if len(vs) == 0 {
			return nil
		}
		if err := enc.WriteToken(jsontext.String(k)); err != nil {
			return err
		}

		if err := enc.WriteToken(jsontext.BeginArray); err != nil {
			return err
		}
		defer enc.WriteToken(jsontext.EndArray)

		for i := range vs {
			if err := Vulnerability(enc, &vs[i]); err != nil {
				return err
			}
		}

		return nil
	}

	if !reflect.ValueOf(v.Prev).IsZero() {
		if err := writeOp("prev", &v.Prev); err != nil {
			return err
		}
	}
	if err := writeOp("cur", &v.Cur); err != nil {
		return err
	}
	if err := writeSlice("added", v.Added); err != nil {
		return err
	}
	if err := writeSlice("removed", v.Removed); err != nil {
		return err
	}

	return nil
}
