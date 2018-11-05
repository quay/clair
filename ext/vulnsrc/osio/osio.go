package osio

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/vulnsrc"
)

var (
	output    OsioApiResponse
	namespace = ""
)

const (
	osio_api    = "https://614101b9-6841-48ad-9daa-515bc7d5eacb.mock.pstmn.io/api/v1/cves/bydate/"
	updaterFlag = "osioUpdater"
	firstDate   = 20181030
)

type updater struct{}

func init() {
	vulnsrc.RegisterUpdater("osio", &updater{})
}

type AddCVE struct {
	CveId       string  `json:"cve_id"`
	CvssV2      float32 `json:"cvss_v2"`
	Description string  `json:"description"`
	Ecosystem   string  `json:"ecosystem"`
	FixedIn     string  `json:"fixed_in"`
	Name        string  `json:"name"`
	Status      string  `json:"status"`
	Version     string  `json:"version"`
	Link        string  `json:"link"`
}

type RemoveCVE struct {
	CveId     string `json:"cve-id"`
	Ecosystem string `json:"ecosystem"`
}
type OsioApiResponse struct {
	AddCVEList    []AddCVE    `json:"add"`
	Count         int         `json:"count"`
	RemoveCVEList []RemoveCVE `json:"remove"`
}

func (u *updater) Update(datastore database.Datastore) (resp vulnsrc.UpdateResponse, err error) {

	log.WithField("package", "OSIO").Info("Start fetching vulnerabilities")

	day := firstDate % 100
	month := (firstDate % 10000) / 100
	year := firstDate / 10000
	t := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)

	tx, err := datastore.Begin()
	if err != nil {
		return resp, err
	}

	flagValue, ok, err := tx.FindKeyValue(updaterFlag)
	if err != nil {
		return resp, err
	}

	if err := tx.Rollback(); err != nil {
		return resp, err
	}

	if !ok {
		flagValue = ""
	}

	firstOSIO, err := strconv.Atoi(flagValue)
	if firstOSIO == 0 || err != nil {
		firstOSIO = firstDate
	}

	fmt.Println("HIT the API of OSIO")

	for i := 0; i < 3; i++ {

		time_format := t.Format("2006-01-02")
		osio_api_url := osio_api + time_format[:4] + time_format[5:7] + time_format[8:]
		resp1, err1 := http.Get(osio_api_url)
		if err1 != nil {
			fmt.Println("cannot fetch URL %q: %v", osio_api_url, err)
		}

		defer resp1.Body.Close()

		if resp1.StatusCode != http.StatusOK {
			fmt.Println("unexpected http GET status: %s", resp1.Status)
		}
		body, err := ioutil.ReadAll(resp1.Body)
		fmt.Println(string(body))
		if err != nil {
			fmt.Println("Parsing not possible")
		}
		vs, rm, err := parseOSIO(body)
		if err != nil {
			return resp, err
		}
		for _, v := range vs {
			resp.Vulnerabilities = append(resp.Vulnerabilities, v)
		}

		for _, r := range rm {
			resp.ToRemove = append(resp.ToRemove, r)
		}
		resp.FlagName = updaterFlag
		resp.FlagValue = flagValue
		tomorrow := t.AddDate(0, 0, 1)
		t = tomorrow
	}
	fmt.Println("Sending Update Response")
	return resp, nil

}

func parseOSIO(body []byte) (vulnerabilities []database.VulnerabilityWithAffected, removeCve []database.VulnerabilityID, err error) {

	fmt.Println("inside parse OSIO")
	json.Unmarshal([]byte(body), &output)

	for _, i := range output.AddCVEList {

		vulnerability := database.VulnerabilityWithAffected{
			Vulnerability: database.Vulnerability{
				Name:        i.CveId,
				Link:        i.Link,
				Severity:    severity(i.CvssV2),
				Description: i.Description,
			},
		}

		if i.Ecosystem == "pypi" {
			namespace = "python"
		} else if i.Ecosystem == "npm" {
			namespace = "node"
		} else if i.Ecosystem == "maven" {
			namespace = "java"
		}
		pkg := database.AffectedFeature{
			FeatureName:     i.Name,
			AffectedVersion: i.Version,
			FixedInVersion:  i.FixedIn,
			Namespace: database.Namespace{
				Name:          namespace,
				VersionFormat: i.Ecosystem,
			},
		}
		vulnerability.Affected = append(vulnerability.Affected, pkg)
		vulnerabilities = append(vulnerabilities, vulnerability)

	}
	for _, i := range output.RemoveCVEList {

		if i.Ecosystem == "pypi" {
			namespace = "python"
		} else if i.Ecosystem == "npm" {
			namespace = "node"
		} else if i.Ecosystem == "maven" {
			namespace = "java"
		}
		remove_cve := database.VulnerabilityID{
			Name:      i.CveId,
			Namespace: namespace,
		}
		removeCve = append(removeCve, remove_cve)
	}
	return vulnerabilities, removeCve, nil
}

func (u *updater) Clean() {}

func severity(sev float32) database.Severity {
	switch {
	case sev <= 3.9:
		return database.LowSeverity
	case sev <= 6.9:
		return database.MediumSeverity
	case sev <= 10.0:
		return database.HighSeverity
	default:
		log.Warningf("could not determine vulnerability severity from: %f.", sev)
		return database.UnknownSeverity
	}
}
