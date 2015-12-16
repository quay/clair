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
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	postLayerURI               = "/v1/layers"
	getLayerVulnerabilitiesURI = "/v1/layers/%s/vulnerabilities?minimumPriority=%s"
	httpPort                   = 9279
)

type APIVulnerabilitiesResponse struct {
	Vulnerabilities []APIVulnerability
}

type APIVulnerability struct {
	ID, Link, Priority, Description string
}

func main() {
	endpoint := flag.String("endpoint", "http://127.0.0.1:6060", "Address to Clair API")
	myAddress := flag.String("my-address", "127.0.0.1", "Address from the point of view of Clair")
	minimumPriority := flag.String("minimum-priority", "Low", "Minimum vulnerability vulnerability to show")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] image-id\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if len(flag.Args()) != 1 {
		flag.Usage()
		os.Exit(1)
	}
	imageName := flag.Args()[0]

	// Save image
	fmt.Printf("Saving %s\n", imageName)
	path, err := save(imageName)
	defer os.RemoveAll(path)
	if err != nil {
		log.Fatalf("- Could not save image: %s\n", err)
	}

	// Retrieve history
	fmt.Println("Getting image's history")
	layerIDs, err := history(imageName)
	if err != nil || len(layerIDs) == 0 {
		log.Fatalf("- Could not get image's history: %s\n", err)
	}

	// Setup a simple HTTP server if Clair is not local
	if !strings.Contains(*endpoint, "127.0.0.1") && !strings.Contains(*endpoint, "localhost") {
		go func(path string) {
			allowedHost := strings.TrimPrefix(*endpoint, "http://")
			portIndex := strings.Index(allowedHost, ":")
			if portIndex >= 0 {
				allowedHost = allowedHost[:portIndex]
			}

			fmt.Printf("Setting up HTTP server (allowing: %s)\n", allowedHost)

			err := http.ListenAndServe(":"+strconv.Itoa(httpPort), restrictedFileServer(path, allowedHost))
			if err != nil {
				log.Fatalf("- An error occurs with the HTTP Server: %s\n", err)
			}
		}(path)

		path = "http://" + *myAddress + ":" + strconv.Itoa(httpPort)
		time.Sleep(200 * time.Millisecond)
	}

	// Analyze layers
	fmt.Printf("Analyzing %d layers\n", len(layerIDs))
	for i := 0; i < len(layerIDs); i++ {
		fmt.Printf("- Analyzing %s\n", layerIDs[i])

		var err error
		if i > 0 {
			err = analyzeLayer(*endpoint, path+"/"+layerIDs[i]+"/layer.tar", layerIDs[i], layerIDs[i-1])
		} else {
			err = analyzeLayer(*endpoint, path+"/"+layerIDs[i]+"/layer.tar", layerIDs[i], "")
		}
		if err != nil {
			log.Fatalf("- Could not analyze layer: %s\n", err)
		}
	}

	// Get vulnerabilities
	fmt.Println("Getting image's vulnerabilities")
	vulnerabilities, err := getVulnerabilities(*endpoint, layerIDs[len(layerIDs)-1], *minimumPriority)
	if err != nil {
		log.Fatalf("- Could not get vulnerabilities: %s\n", err)
	}
	if len(vulnerabilities) == 0 {
		fmt.Println("Bravo, your image looks SAFE !")
	}
	for _, vulnerability := range vulnerabilities {
		fmt.Printf("- # %s\n", vulnerability.ID)
		fmt.Printf("  - Priority:    %s\n", vulnerability.Priority)
		fmt.Printf("  - Link:        %s\n", vulnerability.Link)
		fmt.Printf("  - Description: %s\n", vulnerability.Description)
	}
}

func save(imageName string) (string, error) {
	path, err := ioutil.TempDir("", "analyze-local-image-")
	if err != nil {
		return "", err
	}

	var stderr bytes.Buffer
	save := exec.Command("docker", "save", imageName)
	save.Stderr = &stderr
	extract := exec.Command("tar", "xf", "-", "-C"+path)
	extract.Stderr = &stderr
	pipe, err := extract.StdinPipe()
	if err != nil {
		return "", err
	}
	save.Stdout = pipe

	err = extract.Start()
	if err != nil {
		return "", errors.New(stderr.String())
	}
	err = save.Run()
	if err != nil {
		return "", errors.New(stderr.String())
	}
	err = pipe.Close()
	if err != nil {
		return "", err
	}
	err = extract.Wait()
	if err != nil {
		return "", errors.New(stderr.String())
	}

	return path, nil
}

func history(imageName string) ([]string, error) {
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

func analyzeLayer(endpoint, path, layerID, parentLayerID string) error {
	payload := struct{ ID, Path, ParentID, ImageFormat string }{ID: layerID, Path: path, ParentID: parentLayerID, ImageFormat: "Docker"}
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

func getVulnerabilities(endpoint, layerID, minimumPriority string) ([]APIVulnerability, error) {
	response, err := http.Get(endpoint + fmt.Sprintf(getLayerVulnerabilitiesURI, layerID, minimumPriority))
	if err != nil {
		return []APIVulnerability{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		body, _ := ioutil.ReadAll(response.Body)
		return []APIVulnerability{}, fmt.Errorf("Got response %d with message %s", response.StatusCode, string(body))
	}

	var apiResponse APIVulnerabilitiesResponse
	err = json.NewDecoder(response.Body).Decode(&apiResponse)
	if err != nil {
		return []APIVulnerability{}, err
	}

	return apiResponse.Vulnerabilities, nil
}

func restrictedFileServer(path, allowedHost string) http.Handler {
	fc := func(w http.ResponseWriter, r *http.Request) {
		if r.Host == allowedHost {
			http.FileServer(http.Dir(path)).ServeHTTP(w, r)
			return
		}
		w.WriteHeader(403)
	}
	return http.HandlerFunc(fc)
}
