// Copyright 2018 clair authors
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

package pgsql

import (
	"github.com/guregu/null/zero"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/database/dbtest"
)

// tVulnMap is for testing the vulnerabilities
type tVulnMap struct {
	// ID -> vulnerability
	vulns map[int]*database.VulnerabilityWithAffected
	// ID -> is vulnerability deleted
	deleted map[int]bool
}

func newTVulnMap() tVulnMap {
	return tVulnMap{make(map[int]*database.VulnerabilityWithAffected), make(map[int]bool)}
}

func (m *tVulnMap) addVuln(id int, vuln *database.VulnerabilityWithAffected, isDeleted bool) {
	m.vulns[id] = vuln
	m.deleted[id] = isDeleted
}

func (m *tVulnMap) addAffected(id int, feature database.AffectedFeature) {
	feature.Namespace = m.vulns[id].Namespace
	m.vulns[id].Affected = append(m.vulns[id].Affected, feature)
}

func (m *tVulnMap) getVulnsArray() (vulns []database.VulnerabilityWithAffected, deleted []bool) {
	for id, vuln := range m.vulns {
		vulns = append(vulns, *vuln)
		deleted = append(deleted, m.deleted[id])
	}

	return
}

func (tx *pgSession) tGetVulnMap() (tVulnMap, error) {
	query := `SELECT v.deleted_at, v.id, v.name, v.description, v.link, v.severity, v.metadata, n.version_format, n.name
				FROM vulnerability AS v, namespace AS n
				WHERE v.namespace_id = n.id`

	m := newTVulnMap()
	rows, err := tx.Query(query)
	if err != nil {
		return m, err
	}

	defer rows.Close()
	for rows.Next() {
		var (
			id      int
			deleted zero.Time
			v       database.Vulnerability
		)

		if err := rows.Scan(&deleted, &id, &v.Name, &v.Description, &v.Link, &v.Severity, &v.Metadata, &v.Namespace.VersionFormat, &v.Namespace.Name); err != nil {
			return m, err
		}

		m.addVuln(id, &database.VulnerabilityWithAffected{Vulnerability: v}, deleted.Valid)
	}

	return m, nil
}

func (tx *pgSession) tAddAffectedFeatures(m tVulnMap) error {
	selectAffected := `SELECT vulnerability.id, feature_name, affected_version, fixedin
						FROM vulnerability, vulnerability_affected_feature
						WHERE vulnerability.id = vulnerability_affected_feature.vulnerability_id`

	rows, err := tx.Query(selectAffected)
	if err != nil {
		return err
	}

	defer rows.Close()
	for rows.Next() {
		var (
			id int
			f  database.AffectedFeature
		)

		if err := rows.Scan(&id, &f.FeatureName, &f.AffectedVersion, &f.FixedInVersion); err != nil {
			return err
		}

		m.addAffected(id, f)
	}

	return nil
}

func (tx *pgSession) TGetAllVulnerabilitiesWithAffected() ([]database.VulnerabilityWithAffected, []bool, error) {
	m, err := tx.tGetVulnMap()
	if err != nil {
		return nil, nil, err
	}

	if err := tx.tAddAffectedFeatures(m); err != nil {
		return nil, nil, err
	}

	vulns, isVulnDeleted := m.getVulnsArray()
	return vulns, isVulnDeleted, nil
}

func (tx *pgSession) TGetAllNamespaces() ([]database.Namespace, error) {
	query := `SELECT name, version_format FROM namespace`
	rows, err := tx.Query(query)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	namespaces := []database.Namespace{}
	for rows.Next() {
		n := database.Namespace{}
		if err := rows.Scan(&n.Name, &n.VersionFormat); err != nil {
			return nil, err
		}

		namespaces = append(namespaces, n)
	}

	return namespaces, nil
}

func (tx *pgSession) TGetAllNamespacedFeatures() ([]database.NamespacedFeature, error) {
	query := `SELECT f.name, f.version, f.version_format, n.name, n.version_format FROM feature AS f, namespace AS n, namespaced_feature AS nf WHERE nf.namespace_id = n.id AND nf.feature_id = f.id`
	rows, err := tx.Query(query)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	features := []database.NamespacedFeature{}
	for rows.Next() {
		var f database.NamespacedFeature
		if err := rows.Scan(&f.Feature.Name, &f.Feature.Version, &f.Feature.VersionFormat, &f.Namespace.Name, &f.Namespace.VersionFormat); err != nil {
			return nil, err
		}

		features = append(features, f)
	}

	return features, err
}

func (tx *pgSession) TGetAllFeatures() ([]database.Feature, error) {
	query := `SELECT name, version, version_format FROM feature`
	rows, err := tx.Query(query)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	features := []database.Feature{}
	for rows.Next() {
		var f database.Feature
		if err := rows.Scan(&f.Name, &f.Version, &f.VersionFormat); err != nil {
			return nil, err
		}

		features = append(features, f)
	}

	return features, err
}

func (tx *pgSession) TGetAllDetectors() ([]database.Detector, error) {
	detectors, err := tx.findAllDetectors()
	if err != nil {
		return nil, err
	}

	ds := []database.Detector{}
	for _, d := range detectors.byID {
		ds = append(ds, d)
	}

	return ds, nil
}

func (tx *pgSession) TGetAllNotifications() ([]database.NotificationHook, error) {
	query := `SELECT name, created_at, notified_at, deleted_at FROM vulnerability_notification`
	rows, err := tx.Query(query)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	hooks := []database.NotificationHook{}
	for rows.Next() {
		var (
			hook     database.NotificationHook
			created  zero.Time
			notified zero.Time
			deleted  zero.Time
		)

		if err := rows.Scan(&hook.Name, &created, &notified, &deleted); err != nil {
			return nil, err
		}

		hook.Created = created.Time
		hook.Notified = notified.Time
		hook.Deleted = deleted.Time

		hooks = append(hooks, hook)
	}

	return hooks, nil
}

func (tx *pgSession) TGetAllLock() ([]dbtest.Lock, error) {
	query := `SELECT name, owner, until FROM lock`
	rows, err := tx.Query(query)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	results := []dbtest.Lock{}
	for rows.Next() {
		var result dbtest.Lock
		if err := rows.Scan(&result.Name, &result.Owner, &result.Until); err != nil {
			return nil, err
		}

		results = append(results, result)
	}

	return results, nil
}
