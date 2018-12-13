package redhat_npm

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
	output    RedhatApiResponse
	namespace = "node"
	firstDate = time.Now().AddDate(0, 0, -7)
	page_flag = true
	page      = 1
)

const (
	redhat_api  = "http://bayesian-api-slenka-fabric8-analytics.devtools-dev.ext.devshift.net/api/v1/cves/bydate/"
	updaterFlag = "redhatUpdater"
)

type updater struct{}

func init() {
	vulnsrc.RegisterUpdater("redhat_npm", &updater{})
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
type RedhatApiResponse struct {
	AddCVEList    []AddCVE    `json:"add"`
	Count         int         `json:"count"`
	RemoveCVEList []RemoveCVE `json:"remove"`
}

func (u *updater) Update(datastore database.Datastore) (resp vulnsrc.UpdateResponse, err error) {

	log.WithField("package", "RedHat").Info("Start fetching vulnerabilities")

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
	firstRedhat := flagValue
	if firstRedhat == "" {
		firstRedhat = firstDate_str
	}
	y, err := strconv.Atoi(firstRedhat[:4])
	m, err := strconv.Atoi(firstRedhat[5:7])
	d, err := strconv.Atoi(firstRedhat[8:])
	firstRedhat_time := time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC)

	start_date := firstRedhat_time
	end_date := time.Now()

	for rd := rangeDate(start_date, end_date); ; {
		date := rd() // ranging over dates in time format
		if date.IsZero() {
			break
		}
		page_flag = true
		page = 1
		for page_flag && page < 100 {

			time_format := date.Format("2006-01-02")

			redhat_api_url := redhat_api + time_format[:4] + time_format[5:7] + time_format[8:] + "?page=" + strconv.Itoa(page) + "&ecosystem=npm"
			resp1, err1 := http.Get(redhat_api_url)
			if err1 != nil {
				log.WithField("package", "RedHat").Info("cannot fetch URL %q: %v", redhat_api_url, err)
			}

			defer resp1.Body.Close()

			if resp1.StatusCode != http.StatusOK {
				log.WithField("package", "RedHat").Info("unexpected http GET status: %s", resp1.Status)
			}

			body, err := ioutil.ReadAll(resp1.Body)
			if err != nil {
				log.WithField("package", "RedHat").Info("Parsing not possible")
			}
			vs, rm, err := ParseRedhatJSON(body)
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

	}

	resp.FlagName = updaterFlag
	end_date_str := end_date.Format("2006-01-02")
	resp.FlagValue = end_date_str

	return resp, nil

}

func ParseRedhatJSON(body []byte) (vulnerabilities []database.VulnerabilityWithAffected, removeCve []database.VulnerabilityID, err error) {

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
