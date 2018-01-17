package grafeas

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/coreos/clair/database"
	"github.com/grafeas/grafeas/samples/server/go-server/api/server/name"
	pb "github.com/grafeas/grafeas/v1alpha1/proto"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
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
	conn, err := grpc.Dial(g.Config.Addr, grpc.WithInsecure())
	defer conn.Close()
	context := context.Background()
	pClient := pb.NewGrafeasProjectsClient(conn)
	_, err = pClient.GetProject(context,
		&pb.GetProjectRequest{
			Name: fmt.Sprintf("projects/%s", pID),
		})
	if err != nil {
		// Project does not exist Create project
		log.Println("CreateProject")
		_, err = pClient.CreateProject(context,
			&pb.CreateProjectRequest{
				Name: fmt.Sprintf("projects/%s", pID),
			})
		if err != nil {
			// Failed to access API
			return err
		}
	}

	client := pb.NewGrafeasClient(conn)
	for _, vuln := range vulnerabilities {
		nID := vuln.Name
		score, nistVectors := extractMetadata(vuln.Metadata)
		note, err := client.GetNote(
			context,
			&pb.GetNoteRequest{
				Name: name.NoteName(pID, nID),
			})
		createNewNote := false
		if err != nil {
			note = noteWithoutDetails(pID, nID, vuln.Description, nistVectors, score, severity(vuln.Severity))
			createNewNote = true
		}

		containsUpdatedDetail := false
		for _, affected := range vuln.Affected {
			cpeUri := createCpeUri(affected.Namespace.Name)
			detail := detail(cpeUri, affected.FeatureName, vuln.Description, string(vuln.Severity), affected.FixedInVersion)
			index := findDetail(note.GetVulnerabilityType().Details, detail)
			if index == -1 {
				note.GetVulnerabilityType().Details = append(note.GetVulnerabilityType().Details, &detail)
				containsUpdatedDetail = true
			} else if !reflect.DeepEqual(note.GetVulnerabilityType().Details[index], detail) {
				note.GetVulnerabilityType().Details[index] = &detail
				containsUpdatedDetail = true
			}
		}

		if createNewNote {
			_, err = client.CreateNote(context,
				&pb.CreateNoteRequest{
					Parent: fmt.Sprintf("projects/%s", pID),
					NoteId: nID,
					Note:   note,
				})
		} else if containsUpdatedDetail {
			_, err = client.UpdateNote(context,
				&pb.UpdateNoteRequest{
					Name: name.NoteName(pID, nID),
					Note: note,
				})
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

func findDetail(details []*pb.VulnerabilityType_Detail, detail pb.VulnerabilityType_Detail) int {
	for i, d := range details {
		if d.CpeUri == detail.CpeUri && d.PackageType == detail.PackageType {
			return i
		}
	}
	return -1
}

func severity(severity database.Severity) pb.VulnerabilityType_Severity {
	switch severity {
	case database.Defcon1Severity:
		return pb.VulnerabilityType_CRITICAL
	case database.CriticalSeverity:
		return pb.VulnerabilityType_CRITICAL
	case database.HighSeverity:
		return pb.VulnerabilityType_HIGH
	case database.MediumSeverity:
		return pb.VulnerabilityType_MEDIUM
	case database.LowSeverity:
		return pb.VulnerabilityType_LOW
	case database.NegligibleSeverity:
		return pb.VulnerabilityType_LOW
	default:
		return pb.VulnerabilityType_SEVERITY_UNSPECIFIED
	}
}

func fixedLocation(fixedBy, cpeUri, pkg string) *pb.VulnerabilityType_VulnerabilityLocation {
	var version pb.VulnerabilityType_Version
	if fixedBy == "" {
		version = pb.VulnerabilityType_Version{
			Kind: pb.VulnerabilityType_Version_MAXIMUM,
		}
	} else {
		// EVR: Epoch:Version.Revision
		evrRegexp := regexp.MustCompile(`(?:(\d*):)?([\w~]+[\w.~]*)-(~?\w+[\w.]*)`)
		matches := evrRegexp.FindStringSubmatch(fixedBy)
		if len(matches) != 0 {
			versionEpoch, _ := strconv.ParseInt(matches[1], 10, 32)
			versionName := matches[2]
			versionRev := matches[3]
			version = pb.VulnerabilityType_Version{
				Epoch:    int32(versionEpoch),
				Name:     versionName,
				Revision: versionRev,
			}
		} else {
			version = pb.VulnerabilityType_Version{
				Name: fixedBy,
			}
		}
	}
	return &pb.VulnerabilityType_VulnerabilityLocation{
		CpeUri:  cpeUri,
		Package: pkg,
		Version: &version,
	}
}

func detail(cpeUri, packageName, description, severity, fixedBy string) pb.VulnerabilityType_Detail {
	return pb.VulnerabilityType_Detail{
		CpeUri:      cpeUri,
		Package:     packageName,
		Description: description,
		MinAffectedVersion: &pb.VulnerabilityType_Version{
			Kind: pb.VulnerabilityType_Version_MINIMUM,
		},
		SeverityName:  severity,
		FixedLocation: fixedLocation(fixedBy, cpeUri, packageName),
	}
}

func noteWithoutDetails(pID, name, description, nistVectors string, score float32, severity pb.VulnerabilityType_Severity) *pb.Note {
	var longDescription string
	if nistVectors != "" {
		longDescription = fmt.Sprintf("NIST vectors: %v", nistVectors)
	}
	return &pb.Note{
		Name:             fmt.Sprintf("projects/%v/notes/%v", pID, name),
		ShortDescription: name,
		LongDescription:  longDescription,
		Kind:             pb.Note_PACKAGE_VULNERABILITY,
		NoteType: &pb.Note_VulnerabilityType{
			&pb.VulnerabilityType{
				CvssScore: score,
				Severity:  severity,
				Details:   []*pb.VulnerabilityType_Detail{},
			},
		},
	}
}
