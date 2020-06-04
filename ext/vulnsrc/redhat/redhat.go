// Copyright 2019 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package redhat provides fetch/parsing/etc specific to version-2 oval
package redhat

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/quay/clair/v3/database"
	"github.com/quay/clair/v3/ext/versionfmt/modulerpm"
	"github.com/quay/clair/v3/ext/versionfmt/rpm"
	"github.com/quay/clair/v3/pkg/commonerr"
	"github.com/quay/clair/v3/pkg/httputil"
	"github.com/quay/clair/v3/ext/vulnsrc"
	log "github.com/sirupsen/logrus"
)

const (
	// PulpV2BaseURL - base url for pulp v2 content
	PulpV2BaseURL            = "https://www.redhat.com/security/data/oval/v2/"
	// PulpManifest - url suffix for pulp manifest file
	PulpManifest             = "PULP_MANIFEST"
	// DbManifestEntryKeyPrefix - key prefix used to create flag for manifest entry hash key/value
	DbManifestEntryKeyPrefix = "oval.v2.pulp.manifest.entry."
	// DbLastAdvisoryDateKey - key prefix used to create flag for last advisory date key/value
	DbLastAdvisoryDateKey    = "oval.v2.advisory.date.issued"
	// DefaultLastAdvisoryDate - literal date (in case no existing last advisory date is found)
	DefaultLastAdvisoryDate  = "1970-01-01"
	// AdvisoryDateFormat date format for advisory dates ('magical reference date' for datetime format)
	AdvisoryDateFormat       = "2006-01-02"
	// UpdaterFlag - key used for flag for updater
	UpdaterFlag              = "RedHatOvalV2Updater"
	// UpdaterFlagDateFormat - date format for updater flag dates ('magical reference date' for datetime format)
	UpdaterFlagDateFormat    = "2006-01-02 15:04:05"
	// AffectedType - affected type
	AffectedType             = database.BinaryPackage
	// CveURL - url for cve content
	CveURL                   = "https://access.redhat.com/security/cve/"
)

// SupportedArches - supported architectures
var SupportedArches = map[string]bool { "x86_64":true, "noarch":true }

// SupportedDefinitionTypes - supported definition classes
var SupportedDefinitionTypes = map[string]bool { "patch":true }

func init() {
	vulnsrc.RegisterUpdater("redhat", &updater{})
}

func (u *updater) Clean() {}

func (u *updater) Update(datastore database.Datastore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "RedHat").Info("Start fetching vulnerabilities")

	pulpManifestBody, err := FetchPulpManifest(PulpV2BaseURL + PulpManifest)
	if err != nil {
		log.Error("Unable to fetch pulp manifest file: " + PulpV2BaseURL + PulpManifest)
		return resp, err
	}
	log.Info("Found pulp manifest: " + pulpManifestBody)
	pulpManifestEntries := ParsePulpManifest(pulpManifestBody)

	log.Info(fmt.Sprintf("Processing %d pulp manifest entries",  len(pulpManifestEntries)))

	// initialize updater flags map
	resp.Flags = make(map[string]string)

	// walk the set of pulpManifestEntries
	for _, manifestEntry := range pulpManifestEntries {
		log.Info(fmt.Sprintf("Processing manifest entry (BzipPath: %s)",  manifestEntry.BzipPath))
		// check if this entry has already been processed (based on its sha256 hash)
		if IsNewOrUpdatedManifestEntry(manifestEntry, datastore) {
			unprocessedAdvisories := []ParsedAdvisory{}
			// this is new/updated, process it now
			log.Info("Found updated/new pulp manifest entry. Processing: " + manifestEntry.BzipPath)

			// unzip and read the bzip-compressed oval file into an xml string
			ovalXML, err := ReadBzipOvalFile(PulpV2BaseURL + manifestEntry.BzipPath)
			if err != nil {
				// log error and continue
				log.Error(err)
				continue
			}
			if (ovalXML == "") {
				log.Error("Cannot parse empty source oval doc")
				continue
			}
			//
			ovalDoc := OvalV2Document{}
			err = xml.Unmarshal([]byte(ovalXML), &ovalDoc)
			if err != nil {
				// log error and continue
				log.Error(err)
				continue
			}
			log.Info(fmt.Sprintf("Processing %d definitions...", len(ovalDoc.DefinitionSet.Definitions)))

			unprocessedAdvisories, err = GatherUnprocessedAdvisories(manifestEntry, ovalDoc, datastore)
			if err != nil {
				// log error and continue
				log.Error(err)
				continue
			}
			if len(unprocessedAdvisories) < 1 {
				log.Info("Successful update, no unprocessed advisories found.")
				continue
			} else {
				log.Info(fmt.Sprintf("Successful update, found %d unprocessed advisories.", len(unprocessedAdvisories)))
			}

			log.WithFields(log.Fields{
				"items":   len(unprocessedAdvisories),
				"updater": "RedHat",
			}).Info("Start processing advisories")

			resp.Vulnerabilities = append(resp.Vulnerabilities, CollectVulnerabilities(unprocessedAdvisories, ovalDoc)...)

			// remember the bzip hash for this entry, so we don't re-process it again next time (if unchanged)
			flagKey, flagVal := ConstructFlagForManifestEntrySignature(manifestEntry, datastore)
			resp.Flags[flagKey] = flagVal

		} else {
			// this pulp manifest entry has already been processed; log and skip it
			log.Info("Pulp manifest entry unchanged since last seen. Skipping: " + manifestEntry.BzipPath)
		}

	}

	// debug
	log.Info(fmt.Sprintf("Updating advisory-last-checked-on date in database to: %s", time.Now().Format(AdvisoryDateFormat)))
	// update the db ky/value entry for the advisory-last-checked-on date (current timestamp, as coarse YYYY-MM-dd format)
	resp.Flags[UpdaterFlag] = time.Now().Format(UpdaterFlagDateFormat)
	resp.Flags[DbLastAdvisoryDateKey] = time.Now().Format(UpdaterFlagDateFormat)

	// update the resp flag with summary of found
	if len(resp.Vulnerabilities) > 0 {
		log.WithField("package", "Red Hat").Debug(fmt.Sprintf("updating (found: %d vulnerabilities)...", len(resp.Vulnerabilities)))
	} else {
		log.WithField("package", "Red Hat").Debug("no update")
	}

	return resp, nil
}

// GatherUnprocessedAdvisories - gather any non-processed pulp manifest entry advisories
func GatherUnprocessedAdvisories(manifestEntry ManifestEntry, ovalDoc OvalV2Document, datastore database.Datastore) ([]ParsedAdvisory, error) {
	// get all unprocessed advisories from the oval file
	foundAdvisories, err := ProcessAdvisoriesSinceLastDbUpdate(ovalDoc, datastore)
	if err != nil {
		// log error and continue
		log.Error(err)
		return foundAdvisories, err
	}
	return foundAdvisories, nil
}

// CollectVulnerabilities - walk definitions and collect relevant/unprocessed vulnerability info
func CollectVulnerabilities(advisoryDefinitions []ParsedAdvisory, ovalDoc OvalV2Document) (vulnerabilities []database.VulnerabilityWithAffected) {
	// walk the provided set of advisory definitions
	for _, advisoryDefinition := range advisoryDefinitions {
		vulnerabilities = append(vulnerabilities, CollectVulnsForAdvisory(advisoryDefinition, ovalDoc)...)
	}
	return vulnerabilities
}

// CollectVulnsForAdvisory - get the set of vulns for the given advisory (full doc must also be passed, for the states/tests/objects references)
func CollectVulnsForAdvisory(advisoryDefinition ParsedAdvisory, ovalDoc OvalV2Document) (vulnerabilities []database.VulnerabilityWithAffected) {
	// first, check the advisory severity
	if (IsSignificantSeverity(advisoryDefinition.Metadata.Advisory.Severity)) {
		for _, cve := range advisoryDefinition.Metadata.Advisory.CveList {
			packageMap := make(map[string]bool)
			vulnerability := database.VulnerabilityWithAffected{
				Vulnerability: database.Vulnerability{
					Name:        cve.Value + " - " + ParseRhsaName(advisoryDefinition),
					Link:        CveURL + cve.Value,
					Severity:    GetSeverity(advisoryDefinition.Metadata.Advisory.Severity),
					Description: advisoryDefinition.Metadata.Description,
				},
			}
			for _, parsedRmpNvra := range advisoryDefinition.PackageList {
				if !IsArchSupported(parsedRmpNvra.Arch) {
					continue
				}
				key := parsedRmpNvra.Name + parsedRmpNvra.Evr
				ok := packageMap[key]
				if ok {
					// filter out duplicated features (arch specific)
					continue
				}
				packageMap[key] = true

				feature := database.AffectedFeature{
					FeatureName:     parsedRmpNvra.Name,
					AffectedVersion: parsedRmpNvra.Evr,
					FixedInVersion:  parsedRmpNvra.Evr,
					FeatureType:     AffectedType,
				}
				moduleNamespaces := ParseCriteriaForModuleNamespaces(advisoryDefinition.Criteria)
				if len(moduleNamespaces) > 0 {
					for _, moduleNamespace := range moduleNamespaces {
						// modular rpm has namespace made of module_name:stream
						feature.Namespace = database.Namespace{
							Name:          moduleNamespace,
							VersionFormat: modulerpm.ParserName,
						}
						vulnerability.Affected = append(vulnerability.Affected, feature)
					}
				} else {
					// normal rpm uses CPE namespaces
					cpeNames, err := ParseCpeNamesFromAffectedCpeList(advisoryDefinition.Metadata.Advisory.AffectedCpeList)
					if err != nil {
						// log error and continue
						log.Error(err)
						continue
					}
					if len(cpeNames) == 0 {
						log.Warning(fmt.Sprintf("No CPE for: %s %s %s",
							parsedRmpNvra.Name,
							parsedRmpNvra.Evr,
							advisoryDefinition.Metadata.Title))
					}
					for _, cpe := range cpeNames {
						feature.Namespace = database.Namespace{
							Name:          cpe,
							VersionFormat: rpm.ParserName,
						}
						vulnerability.Affected = append(vulnerability.Affected, feature)
					}
				}

			}
			if len(vulnerability.Affected) > 0 {
				vulnerabilities = append(vulnerabilities, vulnerability)
			}
		}
	} else {
		// advisories with severity "None" should be skipped
		log.Trace(fmt.Sprintf("Skipping unsupported severity '%s' for advisory: %s",
			advisoryDefinition.Metadata.Advisory.Severity,
			advisoryDefinition.Metadata.Title))
	}
	return
}

// ConstructVulnerabilityIDs - construct the []VulnerabilityID set from the given advisory definition
func ConstructVulnerabilityIDs(advisoryDefinition ParsedAdvisory) []database.VulnerabilityID {
	var vulnIDs []database.VulnerabilityID
	rhsaName := ParseRhsaName(advisoryDefinition)
	cveNames := ParseCveNames(advisoryDefinition)
	for _, cveName := range cveNames {
		vulnID := database.VulnerabilityID{Name: cveName + " - " + rhsaName, Namespace: ParseVulnerabilityNamespace(advisoryDefinition)}
		vulnIDs = append(vulnIDs, vulnID)
	}
	return vulnIDs
}

// ParseCveNames - parse the CVE name(s) (e.g.: "CVE-2019-11249") from the given advisory definition
func ParseCveNames(advisoryDefinition ParsedAdvisory) []string {
	var cveNames []string
	for _, cve := range advisoryDefinition.Metadata.Advisory.CveList {
		cveNames = append(cveNames, cve.Value)
	}
	return cveNames
}

// ParseRhsaName - parse the RHSA name (e.g.: "RHBA-2019:2794") from the given advisory definition
func ParseRhsaName(advisoryDefinition ParsedAdvisory) string {
	return strings.TrimSpace(advisoryDefinition.Metadata.Title[:strings.Index(advisoryDefinition.Metadata.Title, ": ")])
}

// ParseVulnerabilityNamespace - parse the namespace from the given advisory definition
func ParseVulnerabilityNamespace(advisoryDefinition ParsedAdvisory) string {
	// use criteria parse result
	moduleNamespaces := ParseCriteriaForModuleNamespaces(advisoryDefinition.Criteria)
	if len(moduleNamespaces) > 0 {
		// use MODULE namespace
		return moduleNamespaces[0]
	}
	// use CPE namespace
	cpeNames, err := ParseCpeNamesFromAffectedCpeList(advisoryDefinition.Metadata.Advisory.AffectedCpeList)
	if err != nil {
		// log error and continue
		log.Error(err)
		return ""
	}
	if len(cpeNames) == 0 {
		// no namespace found
		return ""
	}
	return cpeNames[0]
}

// GetSeverity - get the Severity value which corresponds to the given string
func GetSeverity(severity string) database.Severity {
	switch strings.Title(strings.ToLower(severity)) {
	case "None":
		return database.NegligibleSeverity
	case "Low":
		return database.LowSeverity
	case "Moderate":
		return database.MediumSeverity
	case "Important":
		return database.HighSeverity
	case "Critical":
		return database.CriticalSeverity
	case "Unknown":
		return database.UnknownSeverity
	default:
		log.Warningf("could not determine vulnerability severity from: %s.", severity)
		return database.UnknownSeverity
	}
}

// IsSignificantSeverity - checks whether the given severity is significant (used to determine whether vulns will be parsed and stored for it)
func IsSignificantSeverity(severity string) bool {
	switch strings.Title(strings.ToLower(severity)) {
		case "None":
			return false
	default:
		// anything else is considered significant
		return true
	}
}

func extractAllCriterions(criteria OvalV2Criteria) []OvalV2Criterion {
    var criterions []OvalV2Criterion
    for _, criterion := range criteria.Criteria {
        // recursively append criteria contents
        criterions = append(criterions, extractAllCriterions(criterion)...)
    }
    for _, criterion := range criteria.Criterion {
		if (IsRelevantCriterion(criterion)) {
			// append criterion
			criterions = append(criterions, criterion)
		}
    }
    return criterions
}

// IsRelevantCriterion - check whether the given criterion is relevant
func IsRelevantCriterion(criterion OvalV2Criterion) bool {
	// check comment for matching "is earlier than" substring
	if strings.Contains(criterion.Comment, "is earlier than") {
		return true
	}
	// nothing matched
	return false
}

// IsArchSupported - check whether the given architecture regex represents a supported arch
func IsArchSupported(archRegex string) bool {
	// treat empty arch package info as noarch
	if (archRegex == "") {
		return SupportedArches["noarch"]
	}
	// arch values may be simple strings (e.g.: "x86_64") or regex pattern-based (e.g.: "aarch64|ppc64le|s390x|x86_64")
	var archMatcher = regexp.MustCompile(archRegex)
	// walk the supported arches map, to see if there's a match to the regex
	for archName, isSupported := range SupportedArches {
		isMatch := archMatcher.MatchString(archName)
		if (isMatch && isSupported) {
			return true
		}
	}
	// nothing matched
	return false
}

// IsSupportedDefinitionType - check whether the given definition class corresponds to a supported def type
func IsSupportedDefinitionType(defClass string) bool {
	return SupportedDefinitionTypes[defClass]
}

// ParseCpeNamesFromAffectedCpeList - parse affected_cpe_list
func ParseCpeNamesFromAffectedCpeList(affectedCpeList OvalV2Cpe) ([]string, error) {
	var cpeNames []string
	if affectedCpeList.Cpe == nil || len(affectedCpeList.Cpe) < 2 {
		return cpeNames, errors.New("unparseable affected cpe list")
	}
	// return all cpe entries from the list
	for i := 0; i < len(affectedCpeList.Cpe); i++ {
		cpeNames = append(cpeNames, affectedCpeList.Cpe[i])
	}
	return cpeNames, nil
}

// ProcessAdvisoriesSinceLastDbUpdate - get advisories from the given oval document which were issued since the last update (based on db value)
func ProcessAdvisoriesSinceLastDbUpdate(ovalDoc OvalV2Document, datastore database.Datastore) ([]ParsedAdvisory, error) {
	sinceDate := DbLookupLastAdvisoryDate(datastore)
	var advisories []ParsedAdvisory
	for _, definition := range ovalDoc.DefinitionSet.Definitions {
		// check whether this is a supported definition type
		if (!IsSupportedDefinitionType(definition.Class)) {
			// not supported; skip it
			continue
		}
		// check if this entry has already been processed (based on its issued date)
		if IsAdvisorySinceDate(sinceDate, definition.Metadata.Advisory.Issued.Date) {
			// this advisory was issued since the last advisory date in the database; add it
			// debug
			log.Info(fmt.Sprintf("Found advisory issued since the last known advisory date (%s) in database: %s (%s)",
				sinceDate,
				definition.Metadata.Title, definition.Metadata.Advisory.Issued.Date))
			advisories = append(advisories, ParseAdvisory(definition, ovalDoc))
		} else if IsAdvisorySameDate(sinceDate, definition.Metadata.Advisory.Issued.Date) {
			parsedAdvisory := ParseAdvisory(definition, ovalDoc)
			// advisory date is coarse (YYYY-MM-dd format) date only,
			// so it's possible that we'll see an advisory multiple times within the same day;
			// check the db in this case to be sure
			if (!DbLookupIsAdvisoryProcessed(parsedAdvisory, datastore)) {
				// this advisory id/version hasn't been processed yet; add it
				// debug
				log.Info(fmt.Sprintf("Found unprocessed advisory issued on the last known advisory date (%s) in database: %s (%s)",
					sinceDate,
					definition.Metadata.Title, definition.Metadata.Advisory.Issued.Date))
				advisories = append(advisories, parsedAdvisory)
			}
		} else {
			// this advisory was issued before the last advisory date in the database, so already processed; skip it
			// debug
			log.Info(fmt.Sprintf("Skipping advisory issued before the last known advisory date (%s) in database: %s (%s)",
				sinceDate,
				definition.Metadata.Title, definition.Metadata.Advisory.Issued.Date))
		}
	}
	// debug-only info
	out, _ := xml.MarshalIndent(ovalDoc, " ", "  ")
	log.Debug(string(out))

	return advisories, nil
}

// ParseAdvisory - parse the given advisory definition
func ParseAdvisory(definition OvalV2AdvisoryDefinition, ovalDoc OvalV2Document) (ParsedAdvisory) {
	parsedAdvisory := ParsedAdvisory{
		Class: definition.Class,
		ID: definition.ID,
		Version: definition.Version,
		Metadata: definition.Metadata,
		Criteria: definition.Criteria,
		PackageList: GetPackageList(definition.Criteria, ovalDoc),
	}
	return parsedAdvisory
}

// GetPackageList - get the package list associated with the given criteria
func GetPackageList(criteria OvalV2Criteria, ovalDoc OvalV2Document) (parsedNvras []ParsedRmpNvra) {
	criterions := extractAllCriterions(criteria)
	for _, criterion := range criterions {
		// get package info
		parsedRpmNvra := FindPackageNvraInfo(criterion.TestRef, ovalDoc)
		// only include parsed nvra data if non-empty
		if (parsedRpmNvra.Evr != "") {
			parsedNvras = append(parsedNvras, parsedRpmNvra)
		}
	}
	return
}

// FindPackageNvraInfo - get nvra info for the given test ref
func FindPackageNvraInfo(testRefID string, ovalDoc OvalV2Document) ParsedRmpNvra {
	var parsedNvra ParsedRmpNvra
    for _, test := range ovalDoc.TestSet.Tests {
		if test.ID == testRefID {
			for _, obj := range ovalDoc.ObjectSet.Objects {
				if obj.ID == test.ObjectRef.Ref {
					parsedNvra.Name = obj.Name
				}
			}
			for _, state := range ovalDoc.StateSet.States {
				if (state.ID == test.StateRef.Ref) {
					parsedNvra.Evr = state.Evr.Value
					parsedNvra.Arch = state.Arch.Value
				}
			}
		}
	}
	return parsedNvra
}

// IsAdvisorySinceDate - determine whether the given advisory date string is since the last update
func IsAdvisorySinceDate(sinceDate string, advisoryDate string) bool {
	if sinceDate == "" {
		sinceDate = DefaultLastAdvisoryDate
	}
	sinceTime, err := time.Parse(AdvisoryDateFormat, sinceDate)
    if err != nil {
		log.Error("error parsing since date string: " + sinceDate)
		// if unable to parse date, treat as new advisory
		return true
	}
	advisoryTime, err := time.Parse(AdvisoryDateFormat, advisoryDate)
    if err != nil {
        log.Error("error parsing advisory date string: " + advisoryDate)
		// if unable to parse date, treat as new advisory
		return true
	}
	return advisoryTime.After(sinceTime)
}

// IsAdvisorySameDate - determine whether the given advisory date string is the same as the last update
func IsAdvisorySameDate(sinceDate string, advisoryDate string) bool {
	if sinceDate == "" {
		sinceDate = DefaultLastAdvisoryDate
	}
	sinceTime, err := time.Parse(AdvisoryDateFormat, sinceDate)
    if err != nil {
        log.Error("error parsing since date string: " + sinceDate)
		// if unable to parse date, treat as not same
		return false
	}
	advisoryTime, err := time.Parse(AdvisoryDateFormat, advisoryDate)
    if err != nil {
        log.Error("error parsing advisory date string: " + advisoryDate)
		// if unable to parse date, treat as not same
		return false
	}
	return advisoryTime.Equal(sinceTime)
}

// DbLookupLastAdvisoryDate - lookup the last advisory date from db key/value table
func DbLookupLastAdvisoryDate(datastore database.Datastore) string {
	dbLastAdvisoryDate, ok, err := database.FindKeyValueAndRollback(datastore, DbLastAdvisoryDateKey)
	if err != nil {
		log.Error("Unable to lookup last advisory date, caused by: " + err.Error())
		// error while fetching record, use default
		return DefaultLastAdvisoryDate
	}
	if (ok == false || dbLastAdvisoryDate == "") {
		// no record found, use default
		return DefaultLastAdvisoryDate
	}
	// return the current db value
	return dbLastAdvisoryDate
}

// DbLookupIsAdvisoryProcessed - check the db key/value table for the given advisory's id, compare the stored 'version' value to current
func DbLookupIsAdvisoryProcessed(definition ParsedAdvisory, datastore database.Datastore) bool {
	// check the db to see if the associated vulnerability name is already stored
	vulnIds := ConstructVulnerabilityIDs(definition)
	foundVulns, err := database.FindVulnerabilitiesAndRollback(datastore, vulnIds)
	if err != nil {
		log.Error(err)
		// error during db lookup, treat advisory as unprocessed
		return false
	}
	if len(foundVulns) > 0 {
		// found a record, so this has already been processed
		return true
	}
	// no record found, so it hasn't been processed yet
	return false
}

// ConstructFlagForManifestEntrySignature - construct the flag used to update the db key/value table with the given manifest entry's signature
func ConstructFlagForManifestEntrySignature(manifestEntry ManifestEntry, datastore database.Datastore) (string, string) {
	// use the latest sha256 hash for this entry
	return DbManifestEntryKeyPrefix + manifestEntry.BzipPath, manifestEntry.Signature
}

// IsNewOrUpdatedManifestEntry - check the db key/value table to determine whether the given entry is new/updated
//   since the last time the manifest was processed
func IsNewOrUpdatedManifestEntry(manifestEntry ManifestEntry, datastore database.Datastore) bool {
	currentDbSignature, ok, err := database.FindKeyValueAndRollback(datastore,
		DbManifestEntryKeyPrefix + manifestEntry.BzipPath)
	if err != nil {
		// log the error and err on the side of treat-as-new/updated
		log.Error("Unable to fetch advisory signature from db, caused by: " + err.Error())
		return true
	}
	if ok == false {
		// no record found, so consider this entry as updated (since it hasn't been previously processed)
		return true
	}
	// consider the entry updated if the ManifestEntry.Signature value doesn't match the database record
	return manifestEntry.Signature != currentDbSignature
}

// FetchPulpManifest - fetch the PULP_MANIFEST file, return body as a string
func FetchPulpManifest(pulpManifestURL string) (string, error) {
	resp, err := httputil.GetWithUserAgent(pulpManifestURL)
	if err != nil {
		log.Error("Unable to fetch pulp manifest, caused by: " + err.Error())
		return "", err
	}
	defer resp.Body.Close()
	if !httputil.Status2xx(resp) {
		log.WithField("StatusCode", resp.StatusCode).Error("Unable to fetch pulp manifest")
		return "", commonerr.ErrCouldNotDownload
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error("Unable to read fetched pulp manifest, caused by: " + err.Error())
		return "", err
	}
	return string(body), err
}

// ParsePulpManifest - parse the PULP_MANIFEST file body
func ParsePulpManifest(pulpManifestBody string) []ManifestEntry {
	var manifestEntries []ManifestEntry
	if pulpManifestBody != "" {
		scanner := bufio.NewScanner(strings.NewReader(pulpManifestBody))
		for scanner.Scan() {
			entry, err := ParsePulpManifestLine(scanner.Text())
			if err == nil {
				// append the parsed manifest entry to the slice
				manifestEntries = append(manifestEntries, entry)
			} else {
				// log the error and continue
				log.Warn(err)
			}
		}
	}
	return manifestEntries
}

// ParsePulpManifestLine - return a ManifestEntry from parsing a single line from PULP_MANIFEST
func ParsePulpManifestLine(srcManifestLine string) (ManifestEntry, error) {
	entry := ManifestEntry{}
	if srcManifestLine == "" {
		return entry, errors.New("Cannot parse empty source manifest line")
	}
	data := strings.Split(srcManifestLine, ",")
	if len(data) < 3 {
		return entry, fmt.Errorf(
			"Not enough elements (%d of 3) in source manifest line: %s",
			len(data), srcManifestLine)
	}
	entry.BzipPath = data[0]
	entry.Signature = data[1]
	size, err := strconv.Atoi(data[2])
	if err != nil {
		log.Error("Unable to parse pulp manifest line, caused by: " + err.Error())
		entry.Size = 0
		return entry, err
	}
	entry.Size = size
	return entry, err
}

// ReadBzipOvalFile - decompress and read a bzip2-compressed oval file, return the xml content as string
func ReadBzipOvalFile(bzipOvalFile string) (string, error) {
	resp, err := httputil.GetWithUserAgent(bzipOvalFile)
	if err != nil {
		log.Error(err)
		return "", err
	}
	defer resp.Body.Close()
	if !httputil.Status2xx(resp) {
		log.WithField("StatusCode", resp.StatusCode).Error("Unable to fetch bzip-compressed oval file")
		return "", commonerr.ErrCouldNotDownload
	}
	// read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error(err)
		return "", err
	}
	// create a bzip2 reader from the response body bytes
	bzipreader := bzip2.NewReader(bytes.NewReader(body))
	if err != nil {
		log.Error(err)
		return "", err
	}
	// proceed with read
	content, readErr := ioutil.ReadAll(bzipreader)
	if readErr != nil {
		log.Error(readErr)
		return "", err
	}
	return string(content), nil
}

// ParseCriteriaForModuleNamespaces - parse one definition
func ParseCriteriaForModuleNamespaces(criteria OvalV2Criteria) ([]string) {
    var moduleNamespaces []string
	criterions := extractAllCriterions(criteria)
	// walk the criteria and add them
	for _, criterion := range criterions {
		// Module idm:DL1 is enabled
		var regexComment = regexp.MustCompile(`(Module )(.*)( is enabled)`)
		matches := regexComment.FindStringSubmatch(criterion.Comment)
		if matches != nil && len(matches) > 2 && matches[2] != "" {
			moduleNamespaces = append(moduleNamespaces, matches[2])
		}
	}
    return moduleNamespaces
}

