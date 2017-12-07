package grafeas

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/grafeas/client-go/v1alpha1"
	log "github.com/sirupsen/logrus"
)

type Config struct {
	Enabled   bool
	Addr      string
	ProjectId string
}

type Grafeas struct {
	Config *Config
}

func NewGrafeas(config *Config) Grafeas {
	return Grafeas{config}
}

func (g *Grafeas) Export(datastore database.Datastore) error {
	if !g.Config.Enabled {
		return nil
	}

	log.Info("exporting vulnerabilities to Grafeas")

	tx, err := datastore.Begin()
	if err != nil {
		return err
	}

	defer tx.Rollback()
	vulnerabilities, err := tx.ListVulnerabilities()
	if err != nil {
		return err
	}

	pID := g.Config.ProjectId
	client := v1alpha1.NewGrafeasApiWithBasePath(g.Config.Addr)
	for _, vuln := range vulnerabilities {
		nID := vuln.Name
		score, nistVectors := extractMetadata(vuln.Metadata)
		note, _, err := client.GetNote(pID, nID)
		createNewNote := false
		if err != nil {
			n := noteWithoutDetails(pID, nID, vuln.Description, string(vuln.Severity), nistVectors, score)
			note = &n
			createNewNote = true
		}

		containsUpdatedDetail := false
		for _, affected := range vuln.Affected {
			cpeUri := createCpeUri(affected.Namespace.Name)
			detail := detail(cpeUri, affected.FeatureName, vuln.Description, string(vuln.Severity), affected.FixedInVersion)
			index := findDetail(note.VulnerabilityType.Details, detail)
			if index == -1 {
				note.VulnerabilityType.Details = append(note.VulnerabilityType.Details, detail)
				containsUpdatedDetail = true
			} else if !reflect.DeepEqual(note.VulnerabilityType.Details[index], detail) {
				note.VulnerabilityType.Details[index] = detail
				containsUpdatedDetail = true
			}
		}

		if createNewNote {
			_, _, err = client.CreateNote(pID, nID, *note)
		} else if containsUpdatedDetail {
			_, _, err = client.UpdateNote(pID, nID, *note)
		}

		if err != nil {
			log.Warn("Error creating note %v", err)
		}
	}

	log.Info("export done")

	return nil
}

func extractMetadata(metadata map[string]interface{}) (score float32, vectors string) {
	if nvd, ok := metadata["NVD"].(map[string]interface{}); ok {
		if cvss, ok := nvd["CVSSv2"].(map[string]interface{}); ok {
			score = float32(cvss["Score"].(float64))
			vectors = cvss["Vectors"].(string)
		}
	}

	return score, vectors
}

// Clair does not report cpe uri:s so we'll have to create one from the namespace.
func createCpeUri(namespaceName string) string {
	ss := strings.Split(namespaceName, ":")
	if len(ss) != 2 {
		return "CPE_UNSPECIFIED"
	}
	os := ss[0]
	ver := ss[1]

	switch os {
	case "alpine":
		return "cpe:/o:alpine:alpine_linux:" + ver
	case "debian":
		return "cpe:/o:debian:debian_linux:" + ver
	case "ubuntu":
		return "cpe:/o:canonical:ubuntu_linux:" + ver
	case "centos":
		return "cpe:/o:centos:centos:" + ver
	case "rhel":
		return "cpe:/o:redhat:enterprise_linux:" + ver
	case "fedora":
		return "cpe:/o:fedoraproject:fedora:" + ver
	}

	return "CPE_UNSPECIFIED"
}

func findDetail(details []v1alpha1.Detail, detail v1alpha1.Detail) int {
	for i, d := range details {
		if d.CpeUri == detail.CpeUri && d.Package_ == detail.Package_ {
			return i
		}
	}
	return -1
}

func fixedLocation(fixedBy, cpeUri, pkg string) v1alpha1.VulnerabilityLocation {
	var version v1alpha1.Version
	if fixedBy == "" {
		version = v1alpha1.Version{
			Kind: "MAXIMUM",
		}
	} else {
		// EVR: Epoch:Version.Revision
		evrRegexp := regexp.MustCompile(`(?:(\d*):)?([\w~]+[\w.~]*)-(~?\w+[\w.]*)`)
		matches := evrRegexp.FindStringSubmatch(fixedBy)
		if len(matches) != 0 {
			versionEpoch, _ := strconv.ParseInt(matches[1], 10, 32)
			versionName := matches[2]
			versionRev := matches[3]
			version = v1alpha1.Version{
				Epoch:    int32(versionEpoch),
				Name:     versionName,
				Revision: versionRev,
			}
		} else {
			version = v1alpha1.Version{
				Name: fixedBy,
			}
		}
	}
	return v1alpha1.VulnerabilityLocation{
		CpeUri:   cpeUri,
		Package_: pkg,
		Version:  version,
	}
}

func detail(cpeUri, packageName, description, severity, fixedBy string) v1alpha1.Detail {
	return v1alpha1.Detail{
		CpeUri:      cpeUri,
		Package_:    packageName,
		Description: description,
		MinAffectedVersion: v1alpha1.Version{
			Kind: "MINIMUM",
		},
		SeverityName:  severity,
		FixedLocation: fixedLocation(fixedBy, cpeUri, packageName),
	}
}

func noteWithoutDetails(pID, name, description, severity, nistVectors string, score float32) v1alpha1.Note {
	var longDescription string
	if nistVectors != "" {
		longDescription = fmt.Sprintf("NIST vectors: %v", nistVectors)
	}
	return v1alpha1.Note{
		Name:             fmt.Sprintf("projects/%v/notes/%v", pID, name),
		ShortDescription: name,
		LongDescription:  longDescription,
		Kind:             "PACKAGE_VULNERABILITY",
		VulnerabilityType: v1alpha1.VulnerabilityType{
			CvssScore: score,
			Severity:  severity,
			Details:   []v1alpha1.Detail{},
		},
	}
}
