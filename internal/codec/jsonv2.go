package codec

import (
	"encoding/base64"
	jsonv1 "encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"
	"unicode/utf8"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"

	types "github.com/quay/clair/v4/httptransport/types/v1"
	"github.com/quay/clair/v4/internal/json"
	"github.com/quay/clair/v4/internal/json/jsontext"
)

// The interface built on json/v2 does not use its own pool and instead relies
// on the json package's pooling.

var (
	v1Options = json.JoinOptions(
		json.DefaultOptionsV2(),
		jsontext.Multiline(false),
		jsontext.SpaceAfterColon(false),
		jsontext.SpaceAfterComma(false),
		json.OmitZeroStructFields(true),
		json.FormatNilMapAsNull(true),
		json.FormatNilSliceAsNull(true),
		json.WithMarshalers(v1Marshalers),
		json.WithUnmarshalers(v1Unmarshalers),
	)
	v1Marshalers = json.JoinMarshalers(
		// API-only types:
		json.MarshalToFunc(v1ErrorMarshal),
		// Indexer types:
		json.MarshalToFunc(v1ManifestMarshal),
		json.MarshalToFunc(v1LayerMarshal),
		json.MarshalToFunc(v1IndexReportMarshal),
		json.MarshalToFunc(v1PackageMarshal),
		json.MarshalToFunc(v1RepositoryMarshal),
		json.MarshalToFunc(v1DistributionMarshal),
		json.MarshalToFunc(v1EnvironmentMarshal),
		// Matcher types:
		json.MarshalToFunc(v1VulnerabilityReportMarshal),
		json.MarshalToFunc(v1VulnerabilityMarshal),
		json.MarshalToFunc(v1RangeMarshal),
		json.MarshalToFunc(v1UpdateOperationMarshal),
		json.MarshalToFunc(v1UpdateDiffMarshal),
	)
	v1Unmarshalers = json.JoinUnmarshalers(
		// Indexer types:
		json.UnmarshalFromFunc(v1ManifestUnmarshal),
		json.UnmarshalFromFunc(v1LayerUnmarshal),
		json.UnmarshalFromFunc(v1IndexReportUnmarshal),
		json.UnmarshalFromFunc(v1PackageUnmarshal),
		json.UnmarshalFromFunc(v1DistributionUnmarshal),
		json.UnmarshalFromFunc(v1RepositoryUnmarshal),
		json.UnmarshalFromFunc(v1EnvironmentUnmarshal),
		json.UnmarshalFromFunc(v1VulnerabilityReportUnmarshal),
		json.UnmarshalFromFunc(v1VulnerabilityUnmarshal),
		json.UnmarshalFromFunc(v1RangeUnmarshal),
	)
)

func v1Encoder(w io.Writer) Encoder {
	return &fwdWriter{w: w}
}

type fwdWriter struct {
	w io.Writer
}

func (w *fwdWriter) Encode(in any) error {
	return json.MarshalWrite(w.w, in, v1Options)
}

func v1Decoder(r io.Reader) Decoder {
	return &fwdReader{r}
}

type fwdReader struct {
	r io.Reader
}

func (r *fwdReader) Decode(out any) error {
	return json.UnmarshalRead(r.r, out, v1Options)
}

// All these functions look like long ways to do what the json package already
// does for us. That's true currently, but it allows us to change the claircore
// types and not have the serialization change!

func v1ManifestMarshal(enc *jsontext.Encoder, v *claircore.Manifest) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)

	if err := enc.WriteToken(hashKey); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(v.Hash.String())); err != nil {
		return err
	}

	if v.Layers != nil {
		if err := enc.WriteToken(layersKey); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.BeginArray); err != nil {
			return err
		}
		defer enc.WriteToken(jsontext.EndArray)

		for _, l := range v.Layers {
			if err := v1LayerMarshal(enc, l); err != nil {
				return err
			}
		}
	}

	return nil
}

func v1LayerMarshal(enc *jsontext.Encoder, v *claircore.Layer) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)

	if err := enc.WriteToken(hashKey); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(v.Hash.String())); err != nil {
		return err
	}

	if err := enc.WriteToken(uriKey); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(v.URI)); err != nil {
		return err
	}

	if err := enc.WriteToken(headersKey); err != nil {
		return err
	}
	if err := json.MarshalEncode(enc, v.Headers); err != nil {
		return err
	}

	return nil
}

func v1IndexReportMarshal(enc *jsontext.Encoder, v *claircore.IndexReport) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)

	if err := enc.WriteToken(reporthashKey); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(v.Hash.String())); err != nil {
		return err
	}

	if err := enc.WriteToken(stateKey); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(v.State)); err != nil {
		return err
	}

	if err := enc.WriteToken(successKey); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.Bool(v.Success)); err != nil {
		return err
	}

	if e := v.Err; e != "" {
		if err := enc.WriteToken(errKey); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(e)); err != nil {
			return err
		}
	}

	if err := v1DoMap(enc, packagesKey, v.Packages, v1PackageMarshal); err != nil {
		return err
	}
	if err := v1DoMap(enc, distributionsKey, v.Distributions, v1DistributionMarshal); err != nil {
		return err
	}
	if err := v1DoMap(enc, repositoryKey, v.Repositories, v1RepositoryMarshal); err != nil {
		return err
	}
	if err := v1DoMapArray(enc, environmentsKey, v.Environments, v1EnvironmentMarshal); err != nil {
		return err
	}

	return nil
}

func v1DoMap[T any](enc *jsontext.Encoder, t jsontext.Token, m map[string]*T, f func(*jsontext.Encoder, *T) error) error {
	if len(m) == 0 {
		return nil
	}
	if err := enc.WriteToken(t); err != nil {
		return err
	}

	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)
	for k, v := range m {
		if err := enc.WriteToken(jsontext.String(k)); err != nil {
			return err
		}
		if err := f(enc, v); err != nil {
			return err
		}
	}
	return nil
}

func v1DoMapArray[T any](enc *jsontext.Encoder, t jsontext.Token, m map[string][]T, f func(*jsontext.Encoder, T) error) error {
	if len(m) == 0 {
		return nil
	}
	if err := enc.WriteToken(t); err != nil {
		return err
	}

	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)

	writeArray := func(v []T) error {
		if err := enc.WriteToken(jsontext.BeginArray); err != nil {
			return err
		}
		defer enc.WriteToken(jsontext.EndArray)
		for _, v := range v {
			if err := f(enc, v); err != nil {
				return err
			}
		}
		return nil
	}
	for k, v := range m {
		if err := enc.WriteToken(jsontext.String(k)); err != nil {
			return err
		}
		if err := writeArray(v); err != nil {
			return err
		}
	}
	return nil
}

func v1PackageMarshal(enc *jsontext.Encoder, v *claircore.Package) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)

	fs := []struct {
		Key   jsontext.Token
		Value string
	}{
		{idKey, v.ID},
		{nameKey, v.Name},
		{versionKey, v.Version},
		{kindKey, v.Kind},
		{moduleKey, v.Module},
		{archKey, v.Arch},
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
		if err := enc.WriteToken(normVersionKey); err != nil {
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
		if err := enc.WriteToken(cpeKey); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(v.CPE.String())); err != nil {
			return err
		}
	}

	if src := v.Source; src != nil {
		if err := enc.WriteToken(sourceKey); err != nil {
			return err
		}
		if err := json.MarshalEncode(enc, src); err != nil {
			return err
		}
	}

	return nil
}

func v1DistributionMarshal(enc *jsontext.Encoder, v *claircore.Distribution) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)
	fs := []struct {
		Key   jsontext.Token
		Value string
	}{
		{idKey, v.ID},
		{didKey, v.DID},
		{nameKey, v.Name},
		{versionKey, v.Version},
		{versionCodeNameKey, v.VersionCodeName},
		{versionIDKey, v.VersionID},
		{archKey, v.Arch},
		{prettyNameKey, v.PrettyName},
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
		if err := enc.WriteToken(cpeKey); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(v.CPE.String())); err != nil {
			return err
		}
	}

	return nil
}

func v1RepositoryMarshal(enc *jsontext.Encoder, v *claircore.Repository) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)
	fs := []struct {
		Key   jsontext.Token
		Value string
	}{
		{idKey, v.ID},
		{nameKey, v.Name},
		{keyKey, v.Key},
		{uriKey, v.URI},
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
		if err := enc.WriteToken(cpeKey); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(v.CPE.String())); err != nil {
			return err
		}
	}

	return nil
}

func v1EnvironmentMarshal(enc *jsontext.Encoder, v *claircore.Environment) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)
	fs := []struct {
		Key   jsontext.Token
		Value string
	}{
		{packageDBKey, v.PackageDB},
		{distributionIDKey, v.DistributionID},
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
		if err := enc.WriteToken(introducedKey); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(v.IntroducedIn.String())); err != nil {
			return err
		}
	}

	if len(v.RepositoryIDs) != 0 {
		if err := enc.WriteToken(repositoryIDsKey); err != nil {
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

func v1VulnerabilityReportMarshal(enc *jsontext.Encoder, v *claircore.VulnerabilityReport) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)

	if err := enc.WriteToken(reporthashKey); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(v.Hash.String())); err != nil {
		return err
	}

	if err := v1DoMap(enc, packagesKey, v.Packages, v1PackageMarshal); err != nil {
		return err
	}
	if err := v1DoMap(enc, distributionsKey, v.Distributions, v1DistributionMarshal); err != nil {
		return err
	}
	if err := v1DoMap(enc, repositoryKey, v.Repositories, v1RepositoryMarshal); err != nil {
		return err
	}
	if err := v1DoMapArray(enc, environmentsKey, v.Environments, v1EnvironmentMarshal); err != nil {
		return err
	}
	if err := v1DoMap(enc, vulnerabilitiesKey, v.Vulnerabilities, v1VulnerabilityMarshal); err != nil {
		return err
	}
	if err := v1DoMapArray(enc, packageVulnerabilitiesKey, v.PackageVulnerabilities, func(enc *jsontext.Encoder, v string) error {
		return enc.WriteToken(jsontext.String(v))
	}); err != nil {
		return err
	}
	if err := v1DoMapArray(enc, enrichmentsKey, v.Enrichments, func(enc *jsontext.Encoder, v jsonv1.RawMessage) error {
		return enc.WriteValue(jsontext.Value(v))
	}); err != nil {
		return err
	}

	return nil
}

func v1VulnerabilityMarshal(enc *jsontext.Encoder, v *claircore.Vulnerability) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)

	fs := []struct {
		Key   jsontext.Token
		Value string
	}{
		{idKey, v.ID},
		{updaterKey, v.Updater},
		{nameKey, v.Name},
		{descriptionKey, v.Description},
		{linksKey, v.Links},
		{severityKey, v.Severity},
		{fixedInKey, v.FixedInVersion},
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

	if err := enc.WriteToken(normSeverityKey); err != nil {
		return err
	}
	if err := enc.WriteToken(jsontext.String(v.NormalizedSeverity.String())); err != nil {
		return err
	}

	if !v.Issued.IsZero() {
		if err := enc.WriteToken(issuedKey); err != nil {
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
		if err := enc.WriteToken(packageKey); err != nil {
			return err
		}
		if err := v1PackageMarshal(enc, v.Package); err != nil {
			return err
		}
	}
	if v.Dist != nil {
		if err := enc.WriteToken(distributionKey); err != nil {
			return err
		}
		if err := v1DistributionMarshal(enc, v.Dist); err != nil {
			return err
		}
	}
	if v.Repo != nil {
		if err := enc.WriteToken(repositoryKey); err != nil {
			return err
		}
		if err := v1RepositoryMarshal(enc, v.Repo); err != nil {
			return err
		}
	}

	if v.Range != nil {
		if err := enc.WriteToken(rangeKey); err != nil {
			return err
		}
		if err := v1RangeMarshal(enc, v.Range); err != nil {
			return err
		}
	}

	if v.ArchOperation != claircore.ArchOp(0) {
		if err := enc.WriteToken(archOpKey); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.String(v.ArchOperation.String())); err != nil {
			return err
		}
	}

	return nil
}

func v1RangeMarshal(enc *jsontext.Encoder, v *claircore.Range) error {
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

	if err := f(`[`, &v.Lower); err != nil {
		return err
	}
	if err := f(`)`, &v.Upper); err != nil {
		return err
	}
	return nil
}

func v1ErrorMarshal(enc *jsontext.Encoder, v *types.Error) error {
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
	b, err := jsontext.AppendQuote(enc.AvailableBuffer(), v.Message)
	if err != nil {
		return err
	}
	if err := enc.WriteValue(b); err != nil {
		return err
	}

	return nil
}

func v1UpdateOperationMarshal(enc *jsontext.Encoder, v *driver.UpdateOperation) error {
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

func v1UpdateDiffMarshal(enc *jsontext.Encoder, v *driver.UpdateDiff) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	defer enc.WriteToken(jsontext.EndObject)

	writeOp := func(k string, op *driver.UpdateOperation) error {
		if err := enc.WriteToken(jsontext.String(k)); err != nil {
			return err
		}
		if err := v1UpdateOperationMarshal(enc, op); err != nil {
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
			if err := v1VulnerabilityMarshal(enc, &vs[i]); err != nil {
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

// These Unmarshal functions are implemented as state machines using the
// return-a-function pattern. See jsonv2_unmarshal.go for the generic
// bits.

func v1ManifestUnmarshal(dec *jsontext.Decoder, v *claircore.Manifest) error {
	return runUnmarshalMachine(dec, v, unmarshalObjectBegin(uV1ManifestKeys))
}

func uV1ManifestKeys(m *unmarshalMachine[claircore.Manifest]) uStateFn[claircore.Manifest] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.error(err)
	}

	switch tok.Kind() {
	case '"':
		switch tok.String() {
		case "hash":
			return m.doText(&m.out.Hash, uV1ManifestKeys)
		case "layers":
			return unmarshalArray(m, &m.out.Layers, uV1ManifestKeys)
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.error(err)
			}
			return uV1ManifestKeys
		}
	case '}':
		return nil
	default:
		err := fmt.Errorf("unexpected token (at %s): %q", m.dec.StackPointer(), tok)
		return m.error(err)
	}
}

func v1LayerUnmarshal(dec *jsontext.Decoder, v *claircore.Layer) error {
	return runUnmarshalMachine(dec, v, unmarshalObjectBegin(uV1LayerKeys))
}

func uV1LayerKeys(m *unmarshalMachine[claircore.Layer]) uStateFn[claircore.Layer] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.error(err)
	}

	switch tok.Kind() {
	case '"':
		switch tok.String() {
		case "hash":
			return m.doText(&m.out.Hash, uV1LayerKeys)
		case "uri":
			return m.doString(&m.out.URI, uV1LayerKeys)
		case "headers":
			out := make(map[string][]string)
			if err := json.UnmarshalDecode(m.dec, &out); err != nil {
				return m.error(err)
			}
			m.out.Headers = out
			return uV1LayerKeys
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.error(err)
			}
			return uV1LayerKeys
		}
	case '}':
		return nil
	default:
		return m.invalidObjectKey()
	}
}

func v1IndexReportUnmarshal(dec *jsontext.Decoder, v *claircore.IndexReport) error {
	return runUnmarshalMachine(dec, v, unmarshalObjectBegin(uV1IndexReportKeys))
}

func uV1IndexReportKeys(m *unmarshalMachine[claircore.IndexReport]) uStateFn[claircore.IndexReport] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.error(err)
	}

	switch tok.Kind() {
	case '"':
		switch tok.String() {
		case "manifest_hash":
			return m.doText(&m.out.Hash, uV1IndexReportKeys)
		case "state":
			return m.doString(&m.out.State, uV1IndexReportKeys)
		case "err":
			return m.doString(&m.out.Err, uV1IndexReportKeys)
		case "success":
			return m.doBool(&m.out.Success, uV1IndexReportKeys)
		case "packages":
			m.out.Packages = make(map[string]*claircore.Package)
			return unmarshalMap(m, &m.out.Packages, uV1IndexReportKeys)
		case "distributions":
			m.out.Distributions = make(map[string]*claircore.Distribution)
			return unmarshalMap(m, &m.out.Distributions, uV1IndexReportKeys)
		case "repository":
			m.out.Repositories = make(map[string]*claircore.Repository)
			return unmarshalMap(m, &m.out.Repositories, uV1IndexReportKeys)
		case "environments":
			m.out.Environments = make(map[string][]*claircore.Environment)
			return unmarshalMap(m, &m.out.Environments, uV1IndexReportKeys)
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.error(err)
			}
			return uV1IndexReportKeys
		}
	case '}':
		return nil
	default:
		return m.invalidObjectKey()
	}
}

func v1PackageUnmarshal(dec *jsontext.Decoder, v *claircore.Package) error {
	return runUnmarshalMachine(dec, v, unmarshalObjectBegin(uV1PackageKeys))
}

func uV1PackageKeys(m *unmarshalMachine[claircore.Package]) uStateFn[claircore.Package] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.error(err)
	}

	switch tok.Kind() {
	case '"':
		switch tok.String() {
		case "id":
			return m.doString(&m.out.ID, uV1PackageKeys)
		case "name":
			return m.doString(&m.out.Name, uV1PackageKeys)
		case "version":
			return m.doString(&m.out.Version, uV1PackageKeys)
		case "kind":
			return m.doString(&m.out.Kind, uV1PackageKeys)
		case "module":
			return m.doString(&m.out.Module, uV1PackageKeys)
		case "arch":
			return m.doString(&m.out.Arch, uV1PackageKeys)
		case "normalized_version":
			return m.doText(&m.out.NormalizedVersion, uV1PackageKeys)
		case "cpe":
			return m.doText(&m.out.CPE, uV1PackageKeys)
		case "source":
			m.out.Source = new(claircore.Package)
			if err := json.UnmarshalDecode(m.dec, m.out.Source); err != nil {
				return m.error(err)
			}
			return uV1PackageKeys
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.error(err)
			}
			return uV1PackageKeys
		}
	case '}':
		return nil
	default:
		return m.invalidObjectKey()
	}
}

func v1DistributionUnmarshal(dec *jsontext.Decoder, v *claircore.Distribution) error {
	return runUnmarshalMachine(dec, v, unmarshalObjectBegin(uV1DistributionKeys))
}

func uV1DistributionKeys(m *unmarshalMachine[claircore.Distribution]) uStateFn[claircore.Distribution] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.error(err)
	}

	switch tok.Kind() {
	case '"':
		switch tok.String() {
		case "id":
			return m.doString(&m.out.ID, uV1DistributionKeys)
		case "did":
			return m.doString(&m.out.DID, uV1DistributionKeys)
		case "name":
			return m.doString(&m.out.Name, uV1DistributionKeys)
		case "version":
			return m.doString(&m.out.Version, uV1DistributionKeys)
		case "version_code_name":
			return m.doString(&m.out.VersionCodeName, uV1DistributionKeys)
		case "version_id":
			return m.doString(&m.out.VersionID, uV1DistributionKeys)
		case "arch":
			return m.doString(&m.out.Arch, uV1DistributionKeys)
		case "pretty_name":
			return m.doString(&m.out.PrettyName, uV1DistributionKeys)
		case "cpe":
			return m.doText(&m.out.CPE, uV1DistributionKeys)
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.error(err)
			}
			return uV1DistributionKeys
		}
	case '}':
		return nil
	default:
		return m.invalidObjectKey()
	}
}

func v1RepositoryUnmarshal(dec *jsontext.Decoder, v *claircore.Repository) error {
	return runUnmarshalMachine(dec, v, unmarshalObjectBegin(uV1RepositoryKeys))
}

func uV1RepositoryKeys(m *unmarshalMachine[claircore.Repository]) uStateFn[claircore.Repository] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.error(err)
	}

	switch tok.Kind() {
	case '"':
		switch tok.String() {
		case "id":
			return m.doString(&m.out.ID, uV1RepositoryKeys)
		case "name":
			return m.doString(&m.out.Name, uV1RepositoryKeys)
		case "key":
			return m.doString(&m.out.Key, uV1RepositoryKeys)
		case "uri":
			return m.doString(&m.out.URI, uV1RepositoryKeys)
		case "cpe":
			return m.doText(&m.out.CPE, uV1RepositoryKeys)
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.error(err)
			}
			return uV1RepositoryKeys
		}
	case '}':
		return nil
	default:
		return m.invalidObjectKey()
	}
}

func v1EnvironmentUnmarshal(dec *jsontext.Decoder, v *claircore.Environment) error {
	return runUnmarshalMachine(dec, v, unmarshalObjectBegin(uV1EnvironmentKeys))
}

func uV1EnvironmentKeys(m *unmarshalMachine[claircore.Environment]) uStateFn[claircore.Environment] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.error(err)
	}

	switch tok.Kind() {
	case '"':
		switch tok.String() {
		case "package_db":
			return m.doString(&m.out.PackageDB, uV1EnvironmentKeys)
		case "distribution_id":
			return m.doString(&m.out.DistributionID, uV1EnvironmentKeys)
		case "introduced_in":
			return m.doText(&m.out.IntroducedIn, uV1EnvironmentKeys)
		case "repository_ids":
			return unmarshalArray(m, &m.out.RepositoryIDs, uV1EnvironmentKeys)
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.error(err)
			}
			return uV1EnvironmentKeys
		}
	case '}':
		return nil
	default:
		return m.invalidObjectKey()
	}
}

func v1VulnerabilityUnmarshal(dec *jsontext.Decoder, v *claircore.Vulnerability) error {
	return runUnmarshalMachine(dec, v, unmarshalObjectBegin(uV1VulnerabilityKeys))
}

func uV1VulnerabilityKeys(m *unmarshalMachine[claircore.Vulnerability]) uStateFn[claircore.Vulnerability] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.error(err)
	}

	switch tok.Kind() {
	case '"':
		switch tok.String() {
		case "id":
			return m.doString(&m.out.ID, uV1VulnerabilityKeys)
		case "updater":
			return m.doString(&m.out.Updater, uV1VulnerabilityKeys)
		case "name":
			return m.doString(&m.out.Name, uV1VulnerabilityKeys)
		case "description":
			return m.doString(&m.out.Description, uV1VulnerabilityKeys)
		case "links":
			return m.doString(&m.out.Links, uV1VulnerabilityKeys)
		case "severity":
			return m.doString(&m.out.Severity, uV1VulnerabilityKeys)
		case "fixed_in_version":
			return m.doString(&m.out.FixedInVersion, uV1VulnerabilityKeys)
		case "issued":
			return m.doText(&m.out.Issued, uV1VulnerabilityKeys)
		case "normalized_severity":
			return m.doText(&m.out.NormalizedSeverity, uV1VulnerabilityKeys)
		case "arch_op":
			return m.doText(&m.out.ArchOperation, uV1VulnerabilityKeys)
		case "package":
			v := new(claircore.Package)
			if err := json.UnmarshalDecode(m.dec, v); err != nil {
				return m.error(err)
			}
			if !reflect.ValueOf(v).Elem().IsZero() {
				m.out.Package = v
			}
			return uV1VulnerabilityKeys
		case "distribution":
			v := new(claircore.Distribution)
			if err := json.UnmarshalDecode(m.dec, v); err != nil {
				return m.error(err)
			}
			if !reflect.ValueOf(v).Elem().IsZero() {
				m.out.Dist = v
			}
			return uV1VulnerabilityKeys
		case "repository":
			v := new(claircore.Repository)
			if err := json.UnmarshalDecode(m.dec, v); err != nil {
				return m.error(err)
			}
			if !reflect.ValueOf(v).Elem().IsZero() {
				m.out.Repo = v
			}
			return uV1VulnerabilityKeys
		case "range":
			v := new(claircore.Range)
			if err := json.UnmarshalDecode(m.dec, v); err != nil {
				return m.error(err)
			}
			if v.Lower.Kind != "" || v.Upper.Kind != "" {
				m.out.Range = v
			}
			return uV1VulnerabilityKeys
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.error(err)
			}
			return uV1VulnerabilityKeys
		}
	case '}':
		return nil
	default:
		return m.invalidObjectKey()
	}
}

func v1RangeUnmarshal(dec *jsontext.Decoder, v *claircore.Range) error {
	return runUnmarshalMachine(dec, v, unmarshalObjectBegin(uV1RangeKeys))
}

func uV1RangeKeys(m *unmarshalMachine[claircore.Range]) uStateFn[claircore.Range] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.error(err)
	}

	switch tok.Kind() {
	case '"':
		switch tok.String() {
		case "[":
			return m.doText(&m.out.Lower, uV1RangeKeys)
		case ")":
			return m.doText(&m.out.Upper, uV1RangeKeys)
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.error(err)
			}
			return uV1RangeKeys
		}
	case '}':
		return nil
	default:
		return m.invalidObjectKey()
	}
}

func v1VulnerabilityReportUnmarshal(dec *jsontext.Decoder, v *claircore.VulnerabilityReport) error {
	return runUnmarshalMachine(dec, v, unmarshalObjectBegin(uV1VulnerabilityReportKeys))
}

func uV1VulnerabilityReportKeys(m *unmarshalMachine[claircore.VulnerabilityReport]) uStateFn[claircore.VulnerabilityReport] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.error(err)
	}

	switch tok.Kind() {
	case '"':
		switch tok.String() {
		case "manifest_hash":
			return m.doText(&m.out.Hash, uV1VulnerabilityReportKeys)
		case "packages":
			m.out.Packages = make(map[string]*claircore.Package)
			return unmarshalMap(m, &m.out.Packages, uV1VulnerabilityReportKeys)
		case "distributions":
			m.out.Distributions = make(map[string]*claircore.Distribution)
			return unmarshalMap(m, &m.out.Distributions, uV1VulnerabilityReportKeys)
		case "repository":
			m.out.Repositories = make(map[string]*claircore.Repository)
			return unmarshalMap(m, &m.out.Repositories, uV1VulnerabilityReportKeys)
		case "environments":
			m.out.Environments = make(map[string][]*claircore.Environment)
			return unmarshalMap(m, &m.out.Environments, uV1VulnerabilityReportKeys)
		case "vulnerabilities":
			m.out.Vulnerabilities = make(map[string]*claircore.Vulnerability)
			return unmarshalMap(m, &m.out.Vulnerabilities, uV1VulnerabilityReportKeys)
		case "package_vulnerabilities":
			m.out.PackageVulnerabilities = make(map[string][]string)
			return unmarshalMap(m, &m.out.PackageVulnerabilities, uV1VulnerabilityReportKeys)
		case "enrichments":
			m.out.Enrichments = make(map[string][]jsonv1.RawMessage)
			return unmarshalMap(m, &m.out.Enrichments, uV1VulnerabilityReportKeys)
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.error(err)
			}
			return uV1VulnerabilityReportKeys
		}
	case '}':
		return nil
	default:
		return m.invalidObjectKey()
	}
}

var (
	archKey                   = jsontext.String(`arch`)
	cpeKey                    = jsontext.String(`cpe`)
	descriptionKey            = jsontext.String(`description`)
	didKey                    = jsontext.String(`did`)
	distributionIDKey         = jsontext.String(`distribution_id`)
	distributionsKey          = jsontext.String(`distributions`)
	distributionKey           = jsontext.String(`distribution`)
	enrichmentsKey            = jsontext.String(`enrichments`)
	environmentsKey           = jsontext.String(`environments`)
	errKey                    = jsontext.String(`err`)
	fixedInKey                = jsontext.String(`fixed_in_version`)
	hashKey                   = jsontext.String(`hash`)
	headersKey                = jsontext.String(`headers`)
	idKey                     = jsontext.String(`id`)
	introducedKey             = jsontext.String(`introduced_in`)
	issuedKey                 = jsontext.String(`issued`)
	keyKey                    = jsontext.String(`key`)
	kindKey                   = jsontext.String(`kind`)
	layersKey                 = jsontext.String(`layers`)
	linksKey                  = jsontext.String(`links`)
	moduleKey                 = jsontext.String(`module`)
	nameKey                   = jsontext.String(`name`)
	normVersionKey            = jsontext.String(`normalized_version`)
	normSeverityKey           = jsontext.String(`normalized_severity`)
	packageDBKey              = jsontext.String(`package_db`)
	packagesKey               = jsontext.String(`packages`)
	packageKey                = jsontext.String(`package`)
	packageVulnerabilitiesKey = jsontext.String(`package_vulnerabilities`)
	prettyNameKey             = jsontext.String(`pretty_name`)
	reporthashKey             = jsontext.String(`manifest_hash`)
	repositoryKey             = jsontext.String(`repository`)
	repositoryIDsKey          = jsontext.String(`repository_ids`)
	severityKey               = jsontext.String(`severity`)
	sourceKey                 = jsontext.String(`source`)
	stateKey                  = jsontext.String(`state`)
	successKey                = jsontext.String(`success`)
	updaterKey                = jsontext.String(`updater`)
	uriKey                    = jsontext.String(`uri`)
	versionCodeNameKey        = jsontext.String(`version_code_name`)
	versionIDKey              = jsontext.String(`version_id`)
	versionKey                = jsontext.String(`version`)
	vulnerabilitiesKey        = jsontext.String(`vulnerabilities`)
	rangeKey                  = jsontext.String(`range`)
	archOpKey                 = jsontext.String(`arch_op`)
)
