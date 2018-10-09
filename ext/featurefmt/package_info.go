package featurefmt

import (
	"github.com/coreos/clair/database"
	"github.com/deckarep/golang-set"
)

// PackageInfo is the extracted raw information from the package managers that
// can be converted to a feature.
type PackageInfo struct {
	PackageName    string
	PackageVersion string
	SourceName     string
	SourceVersion  string
}

// Reset defaults the internal string fields to empty strings.
func (pkg *PackageInfo) Reset() {
	pkg.PackageName = ""
	pkg.PackageVersion = ""
	pkg.SourceName = ""
	pkg.SourceVersion = ""
}

func (pkg *PackageInfo) asFeature(versionFormat string) database.Feature {
	feature := database.Feature{
		Name:          pkg.PackageName,
		Version:       pkg.PackageVersion,
		VersionFormat: versionFormat,
	}

	if pkg.SourceName != "" {
		parent := database.Feature{
			Name:          pkg.SourceName,
			Version:       pkg.SourceVersion,
			VersionFormat: versionFormat,
		}

		if parent != feature {
			feature.Parent = &parent
		}
	}

	return feature
}

// PackageSetToFeatures converts a package set to feature slice
func PackageSetToFeatures(versionFormat string, pkgs mapset.Set) []database.Feature {
	features := make([]database.Feature, 0, pkgs.Cardinality())
	for pkg := range pkgs.Iter() {
		p := pkg.(PackageInfo)
		features = append(features, p.asFeature(versionFormat))
	}

	return features
}
