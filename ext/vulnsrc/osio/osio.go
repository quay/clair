package osio

import (
	"encoding/json"
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
	firstDate = time.Now().AddDate(0, 0, -7)
	page_flag = true
	page      = 1
)

const (
	osio_api    = "http://bayesian-api-slenka-fabric8-analytics.devtools-dev.ext.devshift.net/api/v1/cves/bydate/"
	updaterFlag = "osioUpdater"
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

	firstDate_str := firstDate.Format("2006-01-02")
	firstOSIO := flagValue
	if firstOSIO == "" {
		firstOSIO = firstDate_str
	}
	y, err := strconv.Atoi(firstOSIO[:4])
	m, err := strconv.Atoi(firstOSIO[5:7])
	d, err := strconv.Atoi(firstOSIO[8:])
	firstOSIO_time := time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC)

	start_date := firstOSIO_time
	end_date := time.Now()

	for rd := rangeDate(start_date, end_date); ; {
		date := rd() // in time format
		if date.IsZero() {
			break
		}
		page_flag = true
		page = 1
		for page_flag && page < 100 {

			time_format := date.Format("2006-01-02")

			osio_api_url := osio_api + time_format[:4] + time_format[5:7] + time_format[8:] + "?page=" + strconv.Itoa(page)
			resp1, err1 := http.Get(osio_api_url)

			if err1 != nil {
				log.WithField("package", "OSIO").Info("cannot fetch URL %q: %v", osio_api_url, err)
			}

			defer resp1.Body.Close()

			if resp1.StatusCode != http.StatusOK {
				log.WithField("package", "OSIO").Info("unexpected http GET status: %s", resp1.Status)
			}

			body, err := ioutil.ReadAll(resp1.Body)
			if err != nil {
				log.WithField("package", "OSIO").Info("Parsing not possible")
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
			ok := resp1.Header.Get("page")
			page = page + 1
			if ok == "" {
				page_flag = false
			}
		}

	} //ranging over dates

	resp.FlagName = updaterFlag
	end_date_str := end_date.Format("2006-01-02")
	resp.FlagValue = end_date_str

	return resp, nil

}

func parseOSIO(body []byte) (vulnerabilities []database.VulnerabilityWithAffected, removeCve []database.VulnerabilityID, err error) {

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

		switch i.Ecosystem {
		case "pypi":
			namespace = "python"
			break
		case "npm":
			namespace = "node"
			break
		case "maven":
			namespace = "java"
			break
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
		switch i.Ecosystem {
		case "pypi":
			namespace = "python"
			break
		case "npm":
			namespace = "node"
			break
		case "maven":
			namespace = "java"
			break
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
func rangeDate(start, end time.Time) func() time.Time {
	y, m, d := start.Date()
	start = time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	y, m, d = end.Date()
	end = time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	return func() time.Time {
		if start.After(end) {
			return time.Time{}
		}
		date := start
		start = start.AddDate(0, 0, 1)
		return date
	}
}
