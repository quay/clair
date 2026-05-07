// Package unmarshal holds json/v2 Unmarshal machinery for v1 HTTP API types.
package unmarshal

import (
	jsonv1 "encoding/json"
	"fmt"
	"reflect"

	"github.com/quay/claircore"

	"github.com/quay/clair/v4/internal/apijson/keys"
	"github.com/quay/clair/v4/internal/json"
	"github.com/quay/clair/v4/internal/json/jsontext"
)

// The JSON token kinds used in this package.
const (
	kindString     = jsontext.Kind('"')
	kindTrue       = jsontext.Kind('t')
	kindFalse      = jsontext.Kind('f')
	kindNull       = jsontext.Kind('n')
	kindArrayBegin = jsontext.Kind('[')
	kindArrayEnd   = jsontext.Kind(']')
	kindObjBegin   = jsontext.Kind('{')
	kindObjEnd     = jsontext.Kind('}')
)

// Manifest is used with [json.UnmarshalFromFunc] to unmarshal a [claircore.Manifest].
func Manifest(dec *jsontext.Decoder, v *claircore.Manifest) error {
	return runMachine(dec, v, objectBegin(manifestKeys))
}

func manifestKeys(m *machine[claircore.Manifest]) stateFn[claircore.Manifest] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.Error(err)
	}

	switch tok.Kind() {
	case kindString:
		switch tok.String() {
		case keys.Hash:
			return m.Text(&m.out.Hash, manifestKeys)
		case keys.Layers:
			return doArray(m, &m.out.Layers, manifestKeys)
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.Error(err)
			}
			return manifestKeys
		}
	case kindObjEnd:
		return nil
	default:
		err := fmt.Errorf("unexpected token (at %s): %q", m.dec.StackPointer(), tok)
		return m.Error(err)
	}
}

// Layer is used with [json.UnmarshalFromFunc] to unmarshal a [claircore.Layer].
func Layer(dec *jsontext.Decoder, v *claircore.Layer) error {
	return runMachine(dec, v, objectBegin(layerKeys))
}

func layerKeys(m *machine[claircore.Layer]) stateFn[claircore.Layer] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.Error(err)
	}

	switch tok.Kind() {
	case kindString:
		switch tok.String() {
		case keys.Hash:
			return m.Text(&m.out.Hash, layerKeys)
		case keys.URI:
			return m.String(&m.out.URI, layerKeys)
		case keys.Headers:
			out := make(map[string][]string)
			if err := json.UnmarshalDecode(m.dec, &out); err != nil {
				return m.Error(err)
			}
			m.out.Headers = out
			return layerKeys
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.Error(err)
			}
			return layerKeys
		}
	case kindObjEnd:
		return nil
	default:
		return m.InvalidObjectKey()
	}
}

// IndexReport is used with [json.UnmarshalFromFunc] to unmarshal a [claircore.IndexReport].
func IndexReport(dec *jsontext.Decoder, v *claircore.IndexReport) error {
	return runMachine(dec, v, objectBegin(indexReportKeys))
}

func indexReportKeys(m *machine[claircore.IndexReport]) stateFn[claircore.IndexReport] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.Error(err)
	}

	switch tok.Kind() {
	case kindString:
		switch tok.String() {
		case keys.ReportHash:
			return m.Text(&m.out.Hash, indexReportKeys)
		case keys.State:
			return m.String(&m.out.State, indexReportKeys)
		case keys.Err:
			return m.String(&m.out.Err, indexReportKeys)
		case keys.Success:
			return m.Bool(&m.out.Success, indexReportKeys)
		case keys.Packages:
			m.out.Packages = make(map[string]*claircore.Package)
			return doMap(m, &m.out.Packages, indexReportKeys)
		case keys.Distributions:
			m.out.Distributions = make(map[string]*claircore.Distribution)
			return doMap(m, &m.out.Distributions, indexReportKeys)
		case keys.Repository:
			m.out.Repositories = make(map[string]*claircore.Repository)
			return doMap(m, &m.out.Repositories, indexReportKeys)
		case keys.Environments:
			m.out.Environments = make(map[string][]*claircore.Environment)
			return doMap(m, &m.out.Environments, indexReportKeys)
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.Error(err)
			}
			return indexReportKeys
		}
	case kindObjEnd:
		return nil
	default:
		return m.InvalidObjectKey()
	}
}

// Package is used with [json.UnmarshalFromFunc] to unmarshal a [claircore.Package].
func Package(dec *jsontext.Decoder, v *claircore.Package) error {
	return runMachine(dec, v, objectBegin(packageKeys))
}

func packageKeys(m *machine[claircore.Package]) stateFn[claircore.Package] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.Error(err)
	}

	switch tok.Kind() {
	case kindString:
		switch tok.String() {
		case keys.ID:
			return m.String(&m.out.ID, packageKeys)
		case keys.Name:
			return m.String(&m.out.Name, packageKeys)
		case keys.Version:
			return m.String(&m.out.Version, packageKeys)
		case keys.Kind:
			return m.String(&m.out.Kind, packageKeys)
		case keys.Module:
			return m.String(&m.out.Module, packageKeys)
		case keys.Arch:
			return m.String(&m.out.Arch, packageKeys)
		case keys.NormVersion:
			return m.Text(&m.out.NormalizedVersion, packageKeys)
		case keys.CPE:
			return m.Text(&m.out.CPE, packageKeys)
		case keys.Source:
			m.out.Source = new(claircore.Package)
			if err := json.UnmarshalDecode(m.dec, m.out.Source); err != nil {
				return m.Error(err)
			}
			return packageKeys
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.Error(err)
			}
			return packageKeys
		}
	case kindObjEnd:
		return nil
	default:
		return m.InvalidObjectKey()
	}
}

// Distribution is used with [json.UnmarshalFromFunc] to unmarshal a [claircore.Distribution].
func Distribution(dec *jsontext.Decoder, v *claircore.Distribution) error {
	return runMachine(dec, v, objectBegin(distributionKeys))
}

func distributionKeys(m *machine[claircore.Distribution]) stateFn[claircore.Distribution] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.Error(err)
	}

	switch tok.Kind() {
	case kindString:
		switch tok.String() {
		case keys.ID:
			return m.String(&m.out.ID, distributionKeys)
		case keys.DID:
			return m.String(&m.out.DID, distributionKeys)
		case keys.Name:
			return m.String(&m.out.Name, distributionKeys)
		case keys.Version:
			return m.String(&m.out.Version, distributionKeys)
		case keys.VersionCodeName:
			return m.String(&m.out.VersionCodeName, distributionKeys)
		case keys.VersionID:
			return m.String(&m.out.VersionID, distributionKeys)
		case keys.Arch:
			return m.String(&m.out.Arch, distributionKeys)
		case keys.PrettyName:
			return m.String(&m.out.PrettyName, distributionKeys)
		case keys.CPE:
			return m.Text(&m.out.CPE, distributionKeys)
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.Error(err)
			}
			return distributionKeys
		}
	case kindObjEnd:
		return nil
	default:
		return m.InvalidObjectKey()
	}
}

// Repository is used with [json.UnmarshalFromFunc] to unmarshal a [claircore.Repository].
func Repository(dec *jsontext.Decoder, v *claircore.Repository) error {
	return runMachine(dec, v, objectBegin(repositoryKeys))
}

func repositoryKeys(m *machine[claircore.Repository]) stateFn[claircore.Repository] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.Error(err)
	}

	switch tok.Kind() {
	case kindString:
		switch tok.String() {
		case keys.ID:
			return m.String(&m.out.ID, repositoryKeys)
		case keys.Name:
			return m.String(&m.out.Name, repositoryKeys)
		case keys.Key:
			return m.String(&m.out.Key, repositoryKeys)
		case keys.URI:
			return m.String(&m.out.URI, repositoryKeys)
		case keys.CPE:
			return m.Text(&m.out.CPE, repositoryKeys)
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.Error(err)
			}
			return repositoryKeys
		}
	case kindObjEnd:
		return nil
	default:
		return m.InvalidObjectKey()
	}
}

// Environment is used with [json.UnmarshalFromFunc] to unmarshal a [claircore.Environment].
func Environment(dec *jsontext.Decoder, v *claircore.Environment) error {
	return runMachine(dec, v, objectBegin(environmentKeys))
}

func environmentKeys(m *machine[claircore.Environment]) stateFn[claircore.Environment] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.Error(err)
	}

	switch tok.Kind() {
	case kindString:
		switch tok.String() {
		case keys.PackageDB:
			return m.String(&m.out.PackageDB, environmentKeys)
		case keys.DistributionID:
			return m.String(&m.out.DistributionID, environmentKeys)
		case keys.Introduced:
			return m.Text(&m.out.IntroducedIn, environmentKeys)
		case keys.RepositoryIDs:
			return doArray(m, &m.out.RepositoryIDs, environmentKeys)
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.Error(err)
			}
			return environmentKeys
		}
	case kindObjEnd:
		return nil
	default:
		return m.InvalidObjectKey()
	}
}

// Vulnerability is used with [json.UnmarshalFromFunc] to unmarshal a [claircore.Vulnerability].
func Vulnerability(dec *jsontext.Decoder, v *claircore.Vulnerability) error {
	return runMachine(dec, v, objectBegin(vulnerabilityKeys))
}

func vulnerabilityKeys(m *machine[claircore.Vulnerability]) stateFn[claircore.Vulnerability] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.Error(err)
	}

	switch tok.Kind() {
	case kindString:
		switch tok.String() {
		case keys.ID:
			return m.String(&m.out.ID, vulnerabilityKeys)
		case keys.Updater:
			return m.String(&m.out.Updater, vulnerabilityKeys)
		case keys.Name:
			return m.String(&m.out.Name, vulnerabilityKeys)
		case keys.Description:
			return m.String(&m.out.Description, vulnerabilityKeys)
		case keys.Links:
			return m.String(&m.out.Links, vulnerabilityKeys)
		case keys.Severity:
			return m.String(&m.out.Severity, vulnerabilityKeys)
		case keys.FixedIn:
			return m.String(&m.out.FixedInVersion, vulnerabilityKeys)
		case keys.Issued:
			return m.Text(&m.out.Issued, vulnerabilityKeys)
		case keys.NormSeverity:
			return m.Text(&m.out.NormalizedSeverity, vulnerabilityKeys)
		case keys.ArchOp:
			return m.Text(&m.out.ArchOperation, vulnerabilityKeys)
		case keys.Package:
			v := new(claircore.Package)
			if err := json.UnmarshalDecode(m.dec, v); err != nil {
				return m.Error(err)
			}
			if !reflect.ValueOf(v).Elem().IsZero() {
				m.out.Package = v
			}
			return vulnerabilityKeys
		case keys.Distribution:
			v := new(claircore.Distribution)
			if err := json.UnmarshalDecode(m.dec, v); err != nil {
				return m.Error(err)
			}
			if !reflect.ValueOf(v).Elem().IsZero() {
				m.out.Dist = v
			}
			return vulnerabilityKeys
		case keys.Repository:
			v := new(claircore.Repository)
			if err := json.UnmarshalDecode(m.dec, v); err != nil {
				return m.Error(err)
			}
			if !reflect.ValueOf(v).Elem().IsZero() {
				m.out.Repo = v
			}
			return vulnerabilityKeys
		case keys.Range:
			v := new(claircore.Range)
			if err := json.UnmarshalDecode(m.dec, v); err != nil {
				return m.Error(err)
			}
			if v.Lower.Kind != "" || v.Upper.Kind != "" {
				m.out.Range = v
			}
			return vulnerabilityKeys
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.Error(err)
			}
			return vulnerabilityKeys
		}
	case kindObjEnd:
		return nil
	default:
		return m.InvalidObjectKey()
	}
}

// Range is used with [json.UnmarshalFromFunc] to unmarshal a [claircore.Range].
func Range(dec *jsontext.Decoder, v *claircore.Range) error {
	return runMachine(dec, v, objectBegin(rangeKeys))
}

func rangeKeys(m *machine[claircore.Range]) stateFn[claircore.Range] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.Error(err)
	}

	switch tok.Kind() {
	case kindString:
		switch tok.String() {
		case keys.RangeLower:
			return m.Text(&m.out.Lower, rangeKeys)
		case keys.RangeUpper:
			return m.Text(&m.out.Upper, rangeKeys)
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.Error(err)
			}
			return rangeKeys
		}
	case kindObjEnd:
		return nil
	default:
		return m.InvalidObjectKey()
	}
}

// VulnerabilityReport is used with [json.UnmarshalFromFunc] to unmarshal a [claircore.VulnerabilityReport].
func VulnerabilityReport(dec *jsontext.Decoder, v *claircore.VulnerabilityReport) error {
	return runMachine(dec, v, objectBegin(vulnerabilityReportKeys))
}

func vulnerabilityReportKeys(m *machine[claircore.VulnerabilityReport]) stateFn[claircore.VulnerabilityReport] {
	tok, err := m.dec.ReadToken()
	if err != nil {
		return m.Error(err)
	}

	switch tok.Kind() {
	case kindString:
		switch tok.String() {
		case keys.ReportHash:
			return m.Text(&m.out.Hash, vulnerabilityReportKeys)
		case keys.Packages:
			m.out.Packages = make(map[string]*claircore.Package)
			return doMap(m, &m.out.Packages, vulnerabilityReportKeys)
		case keys.Distributions:
			m.out.Distributions = make(map[string]*claircore.Distribution)
			return doMap(m, &m.out.Distributions, vulnerabilityReportKeys)
		case keys.Repository:
			m.out.Repositories = make(map[string]*claircore.Repository)
			return doMap(m, &m.out.Repositories, vulnerabilityReportKeys)
		case keys.Environments:
			m.out.Environments = make(map[string][]*claircore.Environment)
			return doMap(m, &m.out.Environments, vulnerabilityReportKeys)
		case keys.Vulnerabilities:
			m.out.Vulnerabilities = make(map[string]*claircore.Vulnerability)
			return doMap(m, &m.out.Vulnerabilities, vulnerabilityReportKeys)
		case keys.PackageVulnerabilities:
			m.out.PackageVulnerabilities = make(map[string][]string)
			return doMap(m, &m.out.PackageVulnerabilities, vulnerabilityReportKeys)
		case keys.Enrichments:
			m.out.Enrichments = make(map[string][]jsonv1.RawMessage)
			return doMap(m, &m.out.Enrichments, vulnerabilityReportKeys)
		default: // Unexpected key, skip
			if err := m.dec.SkipValue(); err != nil {
				return m.Error(err)
			}
			return vulnerabilityReportKeys
		}
	case kindObjEnd:
		return nil
	default:
		return m.InvalidObjectKey()
	}
}
