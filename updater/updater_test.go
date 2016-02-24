package updater

import (
	"fmt"
	"testing"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/utils/types"
	"github.com/stretchr/testify/assert"
)

func TestDoVulnerabilitiesNamespacing(t *testing.T) {
	fv1 := database.FeatureVersion{
		Feature: database.Feature{
			Namespace: database.Namespace{Name: "Namespace1"},
			Name:      "Feature1",
		},
		Version: types.NewVersionUnsafe("0.1"),
	}

	fv2 := database.FeatureVersion{
		Feature: database.Feature{
			Namespace: database.Namespace{Name: "Namespace2"},
			Name:      "Feature1",
		},
		Version: types.NewVersionUnsafe("0.2"),
	}

	fv3 := database.FeatureVersion{
		Feature: database.Feature{
			Namespace: database.Namespace{Name: "Namespace2"},
			Name:      "Feature2",
		},
		Version: types.NewVersionUnsafe("0.3"),
	}

	vulnerability := database.Vulnerability{
		Name:    "DoVulnerabilityNamespacing",
		FixedIn: []database.FeatureVersion{fv1, fv2, fv3},
	}

	vulnerabilities := doVulnerabilitiesNamespacing([]database.Vulnerability{vulnerability})
	for _, vulnerability := range vulnerabilities {
		switch vulnerability.Namespace.Name {
		case fv1.Feature.Namespace.Name:
			assert.Len(t, vulnerability.FixedIn, 1)
			assert.Contains(t, vulnerability.FixedIn, fv1)
		case fv2.Feature.Namespace.Name:
			assert.Len(t, vulnerability.FixedIn, 2)
			assert.Contains(t, vulnerability.FixedIn, fv2)
			assert.Contains(t, vulnerability.FixedIn, fv3)
		default:
			t.Errorf("Should not have a Vulnerability with '%s' as its Namespace.", vulnerability.Namespace.Name)
			fmt.Printf("%#v\n", vulnerability)
		}
	}
}
