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
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/clair/api/v1"
)

const (
	postLayerURI        = "/v1/layers"
	getLayerFeaturesURI = "/v1/layers/%s?vulnerabilities"
	httpPort            = 9279
)

func main() {
	// Parse command-line arguments.
	endpoint := flag.String("endpoint", "http://127.0.0.1:6060", "Address to Clair API")
	myAddress := flag.String("my-address", "127.0.0.1", "Address from the point of view of Clair")

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

	// Save image.
	fmt.Printf("Saving %s\n", imageName)
	path, err := save(imageName)
	defer os.RemoveAll(path)
	if err != nil {
		fmt.Printf("- Could not save image: %s\n", err)
		os.Exit(1)
	}

	// Retrieve history.
	fmt.Println("Getting image's history")
	layerIDs, err := historyFromManifest(path)
	if err != nil {
		layerIDs, err = historyFromCommand(imageName)
	}
	if err != nil || len(layerIDs) == 0 {
		fmt.Printf("- Could not get image's history: %s\n", err)
		os.Exit(1)
	}

	// Setup a simple HTTP server if Clair is not local.
	if !strings.Contains(*endpoint, "127.0.0.1") && !strings.Contains(*endpoint, "localhost") {
		allowedHost := strings.TrimPrefix(*endpoint, "http://")
		portIndex := strings.Index(allowedHost, ":")
		if portIndex >= 0 {
			allowedHost = allowedHost[:portIndex]
		}

		go listenHTTP(path, allowedHost)

		path = "http://" + *myAddress + ":" + strconv.Itoa(httpPort)
		time.Sleep(200 * time.Millisecond)
	}

	// Analyze layers.
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
			fmt.Printf("- Could not analyze layer: %s\n", err)
			os.Exit(1)
		}
	}

	// Get vulnerabilities.
	fmt.Println("Getting image's vulnerabilities")
	layer, err := getLayer(*endpoint, layerIDs[len(layerIDs)-1])
	if err != nil {
		fmt.Printf("- Could not get layer information: %s\n", err)
		os.Exit(1)
	}

	// Print report.
	fmt.Printf("\n# Clair report for image %s (%s)\n", imageName, time.Now().UTC())

	if len(layer.Features) == 0 {
		fmt.Println("No feature has been detected on the image.")
		fmt.Println("This usually means that the image isn't supported by Clair.")
		os.Exit(0)
	}

	isSafe := true
	for _, feature := range layer.Features {
		fmt.Printf("## Feature: %s %s (%s)\n", feature.Name, feature.Version, feature.Namespace)

		if len(feature.Vulnerabilities) > 0 {
			isSafe = false

			fmt.Printf("   - Added by: %s\n", feature.AddedBy)

			for _, vulnerability := range feature.Vulnerabilities {
				fmt.Printf("### (%s) %s\n", vulnerability.Severity, vulnerability.Name)

				if vulnerability.Description != "" {
					fmt.Printf("    - Link:          %s\n", vulnerability.Link)
				}

				if vulnerability.Link != "" {
					fmt.Printf("    - Description:   %s\n", vulnerability.Description)
				}

				if vulnerability.FixedBy != "" {
					fmt.Printf("    - Fixed version: %s\n", vulnerability.FixedBy)
				}

				if len(vulnerability.Metadata) > 0 {
					fmt.Printf("    - Metadata:      %+v\n", vulnerability.Metadata)
				}
			}
		}
	}

	if isSafe {
		fmt.Println("\nBravo, your image looks SAFE !")
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

func listenHTTP(path, allowedHost string) {
	fmt.Printf("Setting up HTTP server (allowing: %s)\n", allowedHost)

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

	err := http.ListenAndServe(":"+strconv.Itoa(httpPort), restrictedFileServer(path, allowedHost))
	if err != nil {
		fmt.Printf("- An error occurs with the HTTP server: %s\n", err)
		os.Exit(1)
	}
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
		return fmt.Errorf("- Got response %d with message %s", response.StatusCode, string(body))
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
		err := fmt.Errorf("- Got response %d with message %s", response.StatusCode, string(body))
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
