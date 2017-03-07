// Copyright 2015 clair authors
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

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/clair/api/v1"
	"github.com/coreos/clair/utils/types"
	"github.com/fatih/color"
	"github.com/kr/text"
)

const (
	postLayerURI        = "/v1/layers"
	getLayerFeaturesURI = "/v1/layers/%s?vulnerabilities"
	httpPort            = 9279
)

var (
	flagEndpoint        = flag.String("endpoint", "http://127.0.0.1:6060", "Address to Clair API")
	flagMyAddress       = flag.String("my-address", "127.0.0.1", "Address from the point of view of Clair")
	flagMinimumSeverity = flag.String("minimum-severity", "Negligible", "Minimum severity of vulnerabilities to show (Unknown, Negligible, Low, Medium, High, Critical, Defcon1)")
	flagColorMode       = flag.String("color", "auto", "Colorize the output (always, auto, never)")
)

type vulnerabilityInfo struct {
	vulnerability v1.Vulnerability
	feature       v1.Feature
	severity      types.Priority
}

type By func(v1, v2 vulnerabilityInfo) bool

func (by By) Sort(vulnerabilities []vulnerabilityInfo) {
	ps := &sorter{
		vulnerabilities: vulnerabilities,
		by:              by,
	}
	sort.Sort(ps)
}

type sorter struct {
	vulnerabilities []vulnerabilityInfo
	by              func(v1, v2 vulnerabilityInfo) bool
}

func (s *sorter) Len() int {
	return len(s.vulnerabilities)
}

func (s *sorter) Swap(i, j int) {
	s.vulnerabilities[i], s.vulnerabilities[j] = s.vulnerabilities[j], s.vulnerabilities[i]
}

func (s *sorter) Less(i, j int) bool {
	return s.by(s.vulnerabilities[i], s.vulnerabilities[j])
}

func main() {
	os.Exit(intMain())
}

func intMain() int {
	// Parse command-line arguments.
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] image-id\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if len(flag.Args()) != 1 {
		flag.Usage()
		return 1
	}
	imageName := flag.Args()[0]

	minSeverity := types.Priority(*flagMinimumSeverity)
	if !minSeverity.IsValid() {
		flag.Usage()
		return 1
	}

	if *flagColorMode == "never" {
		color.NoColor = true
	} else if *flagColorMode == "always" {
		color.NoColor = false
	}

	// Create a temporary folder.
	tmpPath, err := ioutil.TempDir("", "analyze-local-image-")
	if err != nil {
		log.Fatalf("Could not create temporary folder: %s", err)
	}
	defer os.RemoveAll(tmpPath)

	// Intercept SIGINT / SIGKILl signals.
	interrupt := make(chan os.Signal)
	signal.Notify(interrupt, os.Interrupt, os.Kill)

	// Analyze the image.
	analyzeCh := make(chan error, 1)
	go func() {
		analyzeCh <- AnalyzeLocalImage(imageName, minSeverity, *flagEndpoint, *flagMyAddress, tmpPath)
	}()

	select {
	case <-interrupt:
		return 130
	case err := <-analyzeCh:
		if err != nil {
			log.Print(err)
			return 1
		}
	}
	return 0
}

func AnalyzeLocalImage(imageName string, minSeverity types.Priority, endpoint, myAddress, tmpPath string) error {
	// Save image.
	log.Printf("Saving %s to local disk (this may take some time)", imageName)
	err := save(imageName, tmpPath)
	if err != nil {
		return fmt.Errorf("Could not save image: %s", err)
	}

	// Retrieve history.
	log.Println("Retrieving image history")
	layerIDs, err := historyFromManifest(tmpPath)
	if err != nil {
		layerIDs, err = historyFromCommand(imageName)
	}
	if err != nil || len(layerIDs) == 0 {
		return fmt.Errorf("Could not get image's history: %s", err)
	}

	// Setup a simple HTTP server if Clair is not local.
	if !strings.Contains(endpoint, "127.0.0.1") && !strings.Contains(endpoint, "localhost") {
		allowedHost := strings.TrimPrefix(endpoint, "http://")
		portIndex := strings.Index(allowedHost, ":")
		if portIndex >= 0 {
			allowedHost = allowedHost[:portIndex]
		}

		log.Printf("Setting up HTTP server (allowing: %s)\n", allowedHost)

		ch := make(chan error)
		go listenHTTP(tmpPath, allowedHost, ch)
		select {
		case err := <-ch:
			return fmt.Errorf("An error occured when starting HTTP server: %s", err)
		case <-time.After(100 * time.Millisecond):
			break
		}

		tmpPath = "http://" + myAddress + ":" + strconv.Itoa(httpPort)
	}

	// Analyze layers.
	log.Printf("Analyzing %d layers... \n", len(layerIDs))
	for i := 0; i < len(layerIDs); i++ {
		log.Printf("Analyzing %s\n", layerIDs[i])

		if i > 0 {
			err = analyzeLayer(endpoint, tmpPath+"/"+layerIDs[i]+"/layer.tar", layerIDs[i], layerIDs[i-1])
		} else {
			err = analyzeLayer(endpoint, tmpPath+"/"+layerIDs[i]+"/layer.tar", layerIDs[i], "")
		}
		if err != nil {
			return fmt.Errorf("Could not analyze layer: %s", err)
		}
	}

	// Get vulnerabilities.
	log.Println("Retrieving image's vulnerabilities")
	layer, err := getLayer(endpoint, layerIDs[len(layerIDs)-1])
	if err != nil {
		return fmt.Errorf("Could not get layer information: %s", err)
	}

	// Print report.
	fmt.Printf("Clair report for image %s (%s)\n", imageName, time.Now().UTC())

	if len(layer.Features) == 0 {
		fmt.Printf("%s No features have been detected in the image. This usually means that the image isn't supported by Clair.\n", color.YellowString("NOTE:"))
		return nil
	}

	isSafe := true
	hasVisibleVulnerabilities := false

	var vulnerabilities = make([]vulnerabilityInfo, 0)
	for _, feature := range layer.Features {
		if len(feature.Vulnerabilities) > 0 {
			for _, vulnerability := range feature.Vulnerabilities {
				severity := types.Priority(vulnerability.Severity)
				isSafe = false

				if minSeverity.Compare(severity) > 0 {
					continue
				}

				hasVisibleVulnerabilities = true
				vulnerabilities = append(vulnerabilities, vulnerabilityInfo{vulnerability, feature, severity})
			}
		}
	}

	// Sort vulnerabilitiy by severity.
	priority := func(v1, v2 vulnerabilityInfo) bool {
		return v1.severity.Compare(v2.severity) >= 0
	}

	By(priority).Sort(vulnerabilities)

	for _, vulnerabilityInfo := range vulnerabilities {
		vulnerability := vulnerabilityInfo.vulnerability
		feature := vulnerabilityInfo.feature
		severity := vulnerabilityInfo.severity

		fmt.Printf("%s (%s)\n", vulnerability.Name, coloredSeverity(severity))

		if vulnerability.Description != "" {
			fmt.Printf("%s\n\n", text.Indent(text.Wrap(vulnerability.Description, 80), "\t"))
		}

		fmt.Printf("\tPackage:       %s @ %s\n", feature.Name, feature.Version)

		if vulnerability.FixedBy != "" {
			fmt.Printf("\tFixed version: %s\n", vulnerability.FixedBy)
		}

		if vulnerability.Link != "" {
			fmt.Printf("\tLink:          %s\n", vulnerability.Link)
		}

		fmt.Printf("\tLayer:         %s\n", feature.AddedBy)
		fmt.Println("")
	}

	if isSafe {
		fmt.Printf("%s No vulnerabilities were detected in your image\n", color.GreenString("Success!"))
	} else if !hasVisibleVulnerabilities {
		fmt.Printf("%s No vulnerabilities matching the minimum severity level were detected in your image\n", color.YellowString("NOTE:"))
	} else {
		return fmt.Errorf("A total of %d vulnerabilities have been detected in your image", len(vulnerabilities))
        }

	return nil
}

func save(imageName, path string) error {
	var stderr bytes.Buffer
	save := exec.Command("docker", "save", imageName)
	save.Stderr = &stderr
	extract := exec.Command("tar", "xf", "-", "-C"+path)
	extract.Stderr = &stderr
	pipe, err := extract.StdinPipe()
	if err != nil {
		return err
	}
	save.Stdout = pipe

	err = extract.Start()
	if err != nil {
		return errors.New(stderr.String())
	}
	err = save.Run()
	if err != nil {
		return errors.New(stderr.String())
	}
	err = pipe.Close()
	if err != nil {
		return err
	}
	err = extract.Wait()
	if err != nil {
		return errors.New(stderr.String())
	}

	return nil
}

func historyFromManifest(path string) ([]string, error) {
	mf, err := os.Open(path + "/manifest.json")
	if err != nil {
		return nil, err
	}
	defer mf.Close()

	// https://github.com/docker/docker/blob/master/image/tarexport/tarexport.go#L17
	type manifestItem struct {
		Config   string
		RepoTags []string
		Layers   []string
	}

	var manifest []manifestItem
	if err = json.NewDecoder(mf).Decode(&manifest); err != nil {
		return nil, err
	} else if len(manifest) != 1 {
		return nil, err
	}
	var layers []string
	for _, layer := range manifest[0].Layers {
		layers = append(layers, strings.TrimSuffix(layer, "/layer.tar"))
	}
	return layers, nil
}

func historyFromCommand(imageName string) ([]string, error) {
	var stderr bytes.Buffer
	cmd := exec.Command("docker", "history", "-q", "--no-trunc", imageName)
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return []string{}, err
	}

	err = cmd.Start()
	if err != nil {
		return []string{}, errors.New(stderr.String())
	}

	var layers []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		layers = append(layers, scanner.Text())
	}

	for i := len(layers)/2 - 1; i >= 0; i-- {
		opp := len(layers) - 1 - i
		layers[i], layers[opp] = layers[opp], layers[i]
	}

	return layers, nil
}

func listenHTTP(path, allowedHost string, ch chan error) {
	restrictedFileServer := func(path, allowedHost string) http.Handler {
		fc := func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err == nil && strings.EqualFold(host, allowedHost) {
				http.FileServer(http.Dir(path)).ServeHTTP(w, r)
				return
			}
			w.WriteHeader(403)
		}
		return http.HandlerFunc(fc)
	}

	ch <- http.ListenAndServe(":"+strconv.Itoa(httpPort), restrictedFileServer(path, allowedHost))
}

func analyzeLayer(endpoint, path, layerName, parentLayerName string) error {
	payload := v1.LayerEnvelope{
		Layer: &v1.Layer{
			Name:       layerName,
			Path:       path,
			ParentName: parentLayerName,
			Format:     "Docker",
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	request, err := http.NewRequest("POST", endpoint+postLayerURI, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != 201 {
		body, _ := ioutil.ReadAll(response.Body)
		return fmt.Errorf("Got response %d with message %s", response.StatusCode, string(body))
	}

	return nil
}

func getLayer(endpoint, layerID string) (v1.Layer, error) {
	response, err := http.Get(endpoint + fmt.Sprintf(getLayerFeaturesURI, layerID))
	if err != nil {
		return v1.Layer{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		body, _ := ioutil.ReadAll(response.Body)
		err := fmt.Errorf("Got response %d with message %s", response.StatusCode, string(body))
		return v1.Layer{}, err
	}

	var apiResponse v1.LayerEnvelope
	if err = json.NewDecoder(response.Body).Decode(&apiResponse); err != nil {
		return v1.Layer{}, err
	} else if apiResponse.Error != nil {
		return v1.Layer{}, errors.New(apiResponse.Error.Message)
	}

	return *apiResponse.Layer, nil
}

func coloredSeverity(severity types.Priority) string {
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	white := color.New(color.FgWhite).SprintFunc()

	switch severity {
	case types.High, types.Critical:
		return red(severity)
	case types.Medium:
		return yellow(severity)
	default:
		return white(severity)
	}
}
