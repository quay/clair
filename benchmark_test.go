package main

import (
	"database/sql"
	"math"
	"strconv"
	"testing"

	"github.com/barakmich/glog"
	"github.com/coreos/quay-sec/database"
	"github.com/coreos/quay-sec/utils/types"
)

var vulnerabilities []*database.Vulnerability

var dbInfo = "host=192.168.99.100 port=5432 user=postgres sslmode=disable dbname=postgres"

func reset() {
	db, err := sql.Open("postgres", dbInfo)
	if err != nil {
		panic(err)
	}
	db.Exec("DROP TABLE quads;")
	db.Close()
}

func getVulnerabilities(id string) []*database.Vulnerability {
	layer, err := database.FindOneLayerByID(id, []string{database.FieldLayerParent}, []string{database.FieldLayerContentInstalledPackages, database.FieldLayerContentRemovedPackages})
	if err != nil {
		panic(err)
	}

	packagesNodes, err := layer.AllPackages()
	if err != nil {
		panic(err)
	}

	vulnerabilities, err := database.GetVulnerabilitiesFromLayerPackagesNodes(packagesNodes, types.Negligible, []string{database.FieldVulnerabilityID, database.FieldVulnerabilityLink, database.FieldVulnerabilityPriority, database.FieldVulnerabilityDescription})
	if err != nil {
		panic(err)
	}

	return vulnerabilities
}

func generateLayersData(sublayersCount, packagesCount, packagesPerBranchesCount int) string {
	var startPackages []string
	var allPackages []*database.Package
	for i := 0; i < packagesCount; i++ {
		for j := 0; j < packagesPerBranchesCount; j++ {
			p := &database.Package{
				OS:      "testOS",
				Name:    "p" + strconv.Itoa(i),
				Version: types.NewVersionUnsafe(strconv.Itoa(j)),
			}
			allPackages = append(allPackages, p)

			if j == 0 {
				startPackages = append(startPackages, p.GetNode())
			}
		}
	}
	err := database.InsertPackages(allPackages)
	if err != nil {
		panic(err)
	}

	var allLayers []*database.Layer
	var packagesCursor int
	for i := 0; i < sublayersCount; i++ {
		parentNode := ""
		if i > 0 {
			parentNode = allLayers[i-1].GetNode()
		}

		var installedPackagesNodes []string
		if i == sublayersCount-1 {
			if packagesCursor <= packagesCount-1 {
				installedPackagesNodes = startPackages[packagesCursor:packagesCount]
			}
		} else if (packagesCount / sublayersCount) > 0 {
			upperPackageCursor := int(math.Min(float64(packagesCursor+(packagesCount/sublayersCount)), float64(packagesCount)))
			installedPackagesNodes = startPackages[packagesCursor:upperPackageCursor]
			packagesCursor = upperPackageCursor
		}

		layer := &database.Layer{
			ID:         "l" + strconv.Itoa(i),
			ParentNode: parentNode,
			Content: database.LayerContent{
				TarSum: "lc" + strconv.Itoa(i),
				OS:     "testOS",
				InstalledPackagesNodes: installedPackagesNodes,
			},
		}
		err := database.InsertLayer(layer)
		if err != nil {
			panic(err)
		}
		allLayers = append(allLayers, layer)
	}

	return allLayers[sublayersCount-1].ID
}

func benchmarkVulnerabilities(b *testing.B, sublayersCount, packagesCount, packagesPerBranchesCount int) {
	glog.SetVerbosity(0)
	glog.SetAlsoToStderr(false)
	glog.SetStderrThreshold("FATAL")

	reset()
	err := database.Open("sql", dbInfo)
	if err != nil {
		panic(err)
	}
	defer database.Close()
	defer reset()

	layerID := generateLayersData(sublayersCount, packagesCount, packagesPerBranchesCount)

	var v []*database.Vulnerability
	for n := 0; n < b.N; n++ {
		// store result to prevent the compiler eliminating the function call.
		v = getVulnerabilities(layerID)
	}
	// store result to prevent the compiler eliminating the Benchmark itself.
	vulnerabilities = v
}

func BenchmarkVulnerabilitiesL1P1PPB1(b *testing.B) { benchmarkVulnerabilities(b, 1, 1, 1) }

func BenchmarkVulnerabilitiesL1P1PPB5(b *testing.B)  { benchmarkVulnerabilities(b, 1, 1, 5) }
func BenchmarkVulnerabilitiesL1P1PPB10(b *testing.B) { benchmarkVulnerabilities(b, 1, 1, 10) }
func BenchmarkVulnerabilitiesL1P1PPB20(b *testing.B) { benchmarkVulnerabilities(b, 1, 1, 20) }
func BenchmarkVulnerabilitiesL1P1PPB50(b *testing.B) { benchmarkVulnerabilities(b, 1, 1, 50) }

func BenchmarkVulnerabilitiesL1P5PPB1(b *testing.B)  { benchmarkVulnerabilities(b, 1, 5, 1) }
func BenchmarkVulnerabilitiesL1P10PPB1(b *testing.B) { benchmarkVulnerabilities(b, 1, 10, 1) }
func BenchmarkVulnerabilitiesL1P20PPB1(b *testing.B) { benchmarkVulnerabilities(b, 1, 20, 1) }
func BenchmarkVulnerabilitiesL1P50PPB1(b *testing.B) { benchmarkVulnerabilities(b, 1, 50, 1) }

func BenchmarkVulnerabilitiesL5P1PPB1(b *testing.B)  { benchmarkVulnerabilities(b, 5, 1, 1) }
func BenchmarkVulnerabilitiesL10P1PPB1(b *testing.B) { benchmarkVulnerabilities(b, 10, 1, 1) }
func BenchmarkVulnerabilitiesL20P1PPB1(b *testing.B) { benchmarkVulnerabilities(b, 20, 1, 1) }
func BenchmarkVulnerabilitiesL50P1PPB1(b *testing.B) { benchmarkVulnerabilities(b, 50, 1, 1) }

func BenchmarkVulnerabilitiesL5P5PPB5(b *testing.B)    { benchmarkVulnerabilities(b, 5, 5, 5) }
func BenchmarkVulnerabilitiesL10P10PPB10(b *testing.B) { benchmarkVulnerabilities(b, 10, 10, 10) }
func BenchmarkVulnerabilitiesL20P20PPB20(b *testing.B) { benchmarkVulnerabilities(b, 20, 20, 20) }
func BenchmarkVulnerabilitiesL50P50PPB50(b *testing.B) { benchmarkVulnerabilities(b, 50, 50, 50) }
