package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	// for cert auth
	"crypto/tls"
	"crypto/x509"
)

var (
	clair                     ClairAPI
	openvzMirror              string
	tlsClient                 *http.Client
	httpClient                = &http.Client{}
	certFile, keyFile, caFile string
)

type ClairAPI struct {
	Address         string `json:"adress"`
	Port            int    `json:"port"`
	HttpsEnable     bool   `json:"https_enable"`
	MinimumPriority string
}

type AddLayoutRequestAPI struct {
	ID       string `json:"ID"`
	Path     string `json:"Path"`
	ParantID string `json:"ParantID"`
}

type VulnerabilityItem struct {
	ID          string `json:"ID"`
	Link        string `json:"Link"`
	Priority    string `json:"Priority"`
	Description string `json:"Description"`
}

type GetLayersVulnResponseAPI struct {
	Vulnerabilities []VulnerabilityItem `json:"Vulnerabilities"`
}
type GetVersionsAnswer struct {
	ApiVersion    string `json:"APIVersion"`
	EngineVersion string `json:"EngineVersion"`
}

func init() {
	// Add logging
	log.SetOutput(os.Stdout)
	log.SetPrefix("main: ")
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// Flags
	openvzMirrorFlag := flag.String("m", "https://download.openvz.org/template/precreated/", "Adress to link(directory - not supported yet) with precreated templates")
	clairAddressFlag := flag.String("a", "127.0.0.1", "Adress to clair API")
	clairPortFlag := flag.Int("p", 6060, "Adress to clair API")
	clairMinPriorityFlag := flag.String("P", "High", "The minimum priority of the returned vulnerabilities")

	certFileFlag := flag.String("cert", "", "A PEM encoded certificate file.")
	keyFileFlag := flag.String("key", "", "A PEM encoded private key file.")
	caFileFlag := flag.String("CA", "", "A PEM eoncoded CA's certificate file.")

	flag.Parse()
	openvzMirror = *openvzMirrorFlag
	clair.Address = *clairAddressFlag
	clair.Port = *clairPortFlag
	var err error
	clair.MinimumPriority, err = CheckPriority(*clairMinPriorityFlag)
	if err != nil {
		log.Fatal("Incorrect priority or priority check failed with error - ", err)
	}

	// We have cert auth keys
	if len(*certFileFlag+*keyFileFlag+*caFileFlag) > 0 {
		certFile, keyFile, caFile = *certFileFlag, *keyFileFlag, *caFileFlag
		if len(*certFileFlag) > 0 && len(*keyFileFlag) > 0 && len(*caFileFlag) > 0 {
			// Generate tls client
			clair.HttpsEnable = true
			tlsClient, err = CreateTlsClient(*certFileFlag, *keyFileFlag, *caFileFlag)
			if err != nil {
				log.Fatal("Cannot create tls client, please check previous errors")
			}
		} else {
			fmt.Println("Please set cert,key and ca flags if you need client certificate auth for clair API")
			os.Exit(1)
		}
	}
}

func main() {
	fmt.Println("We use:")
	fmt.Println("Clair - ", clair.Address+":"+strconv.Itoa(clair.Port))
	versions, err := clair.GetVersions()
	if err != nil {
		log.Fatal("We cannot connet to clair ", err)
	}
	fmt.Println("We have clair with APIVersion:", versions.ApiVersion, "and EngineVersion:", versions.EngineVersion)
	fmt.Println("OpenVZ mirror - ", openvzMirror)
	isRemoteMirror, _ := regexp.MatchString(`(?i)^http(s)?\://`, openvzMirror)
	var templateList []string
	//var err error
	if isRemoteMirror {
		templateList, err = GetRemoteListing(openvzMirror)
	} else {
		templateList, err = GetLocalListing(openvzMirror)
	}
	if err != nil {
		log.Fatal("Cannot get template listing - exit")
	}

	templateList = CleanZeroValuesFromArray(templateList)
	fmt.Println("We have", len(templateList), "templates on mirror")
	fmt.Println()

	supportTemplates := regexp.MustCompile(`(?i)(ubuntu|debian|centos)`)

	for _, template := range templateList {

		if !supportTemplates.MatchString(template) {
			log.Println("\"" + template + "\" not supported OS - continue")
			continue
		}
		fmt.Println("Try to add ", template)
		err = clair.AddLayer(openvzMirror, template)
		if err != nil {
			log.Println("Error - cannot add template", template)
		} else {
			fmt.Println(template, "added success")
			fmt.Println("You can check it via:")
			getResultCurl := clair.Address + ":" + strconv.Itoa(clair.Port) + "/v1/layers/" + template + "/vulnerabilities?minimumPriority=" + clair.MinimumPriority
			if clair.HttpsEnable {
				getResultCurl = "curl -s https://" + getResultCurl + " --cert " + certFile + " --key " + keyFile + " --cacert " + caFile
			} else {
				getResultCurl = "curl -s http://" + getResultCurl
			}
			getResultCurl = getResultCurl + " | python -m json.tool"
			//fmt.Println("curl -s http://" + clair.Address + ":" + strconv.Itoa(clair.Port) + "/v1/layers/" + template + "/vulnerabilities?minimumPriority=" + clair.MinimumPriority + " | python -m json.tool")
			fmt.Println(getResultCurl)
			vulnList, err := clair.GetLayerVuln(template)
			if err != nil {
				fmt.Println("Cannot get vulnerabilities for this template - see errors and check it manual, please")
			} else {
				fmt.Println("Detect", len(vulnList), "vulnerabilities for this template")
			}
			fmt.Println()
		}
	}

}

func GetRemoteListing(adress string) (templateList []string, err error) {
	result, err := http.Get(adress + "/.listing")
	if err != nil {
		log.Println("Cannot get listing via web from ", adress)
		log.Println(err)
		return
	}
	listingAnswerByte, err := ioutil.ReadAll(result.Body)
	defer result.Body.Close()
	if err != nil {
		log.Println("Cannot get body from http responce with error ", err)
		return
	}

	templateList = strings.Split(string(listingAnswerByte), "\n")
	return
}

func GetLocalListing(directory string) (templateList []string, err error) {
	result, err := ioutil.ReadFile(directory + "/.listing")
	if err != nil {
		log.Println("Cannot get listing via local file from ", directory)
		log.Println(err)
		return
	}
	templateList = strings.Split(string(result), "\n")
	return
}

func CleanZeroValuesFromArray(array []string) []string {
	var cleanArray []string
	for _, value := range array {
		if len(value) > 0 {
			cleanArray = append(cleanArray, value)
		}
	}
	return cleanArray
}

// https://github.com/coreos/clair/blob/master/docs/API.md#insert-a-new-layer
func (clair ClairAPI) AddLayer(openvzMirror string, templateName string) error {
	var client *http.Client
	url := clair.Address + ":" + strconv.Itoa(clair.Port) + "/v1/layers"
	if clair.HttpsEnable {
		url = "https://" + url
		client = tlsClient
	} else {
		url = "http://" + url
		client = httpClient
	}

	jsonRequest, err := json.Marshal(AddLayoutRequestAPI{ID: templateName, Path: openvzMirror + "/" + templateName + ".tar.gz"})
	if err != nil {
		log.Println("Cannot convert to json request with error: ", err)
		return err
	}

	request, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonRequest))
	if err != nil {
		log.Println("Cannot generate request: ", err)
		return err
	}
	request.Header.Set("Content-Type", "application/json")

	//client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Println("Send request failed request: ", err)
		return err
	}

	// if OK  - returned "201 Created"
	if response.StatusCode != 201 {
		defer response.Body.Close()
		body, _ := ioutil.ReadAll(response.Body)
		log.Println("Error - response not ok - ", response.Status, " with message: ", string(body))
		return errors.New(string(body))
	}

	return nil
}

// https://github.com/coreos/clair/blob/master/docs/API.md#get-a-layers-vulnerabilities
func (clair ClairAPI) GetLayerVuln(templateName string) (vulnList []VulnerabilityItem, err error) {
	var client *http.Client
	url := clair.Address + ":" + strconv.Itoa(clair.Port) + "/v1/layers/" + templateName + "/vulnerabilities" + "?minimumPriority=" + clair.MinimumPriority
	if clair.HttpsEnable {
		url = "https://" + url
		client = tlsClient
	} else {
		url = "http://" + url
		client = httpClient
	}

	response, err := client.Get(url)
	if err != nil {
		log.Println("Send request failed request: ", err)
		return vulnList, err
	}
	defer response.Body.Close()
	body, _ := ioutil.ReadAll(response.Body)

	// if OK  - returned "200 OK"
	if response.StatusCode != 200 {
		log.Println("Error - response not ok - ", response.Status, " with message: ", string(body))
		return vulnList, errors.New(string(body))
	}

	var result GetLayersVulnResponseAPI
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Println("Cannot parse answer from clair to json: ", err)
		return vulnList, err
	}
	vulnList = result.Vulnerabilities
	return vulnList, nil
}

func (clair ClairAPI) GetVersions() (versions GetVersionsAnswer, err error) {
	var client *http.Client
	url := clair.Address + ":" + strconv.Itoa(clair.Port) + "/v1/versions"
	if clair.HttpsEnable {
		url = "https://" + url
		client = tlsClient
	} else {
		url = "http://" + url
		client = httpClient
	}

	response, err := client.Get(url)
	if err != nil {
		log.Println("Send request failed request: ", err)
		return
	}

	defer response.Body.Close()
	body, _ := ioutil.ReadAll(response.Body)

	// if OK  - returned "200 OK"
	if response.StatusCode != 200 {
		log.Println("Error - response not ok - ", response.Status, " with message: ", string(body))
		return versions, errors.New(string(body))
	}

	err = json.Unmarshal(body, &versions)
	if err != nil {
		log.Println("Cannot parse answer from clair to json: ", err)
		return
	}
	return
}

func CheckPriority(priority string) (result string, err error) {
	// Acutal list see in type Priority in
	// https://github.com/coreos/clair/blob/master/utils/types/priority.go
	match, err := regexp.MatchString(`(?i)^(Unknown|Negligible|Low|Medium|High|Critical|Critical|Defcon1)$`, priority)
	if err != nil {
		return "", err
	}
	if match {
		result = strings.ToUpper(string(priority[0])) + strings.ToLower(priority[1:len(priority)])
		return
	}
	return "", errors.New("Unknown priority " + priority)
}

func CreateTlsClient(certFile, keyFile, caFile string) (client *http.Client, err error) {
	// Load client cert
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Println("Cannot load client cert", err)
		return
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Println("Cannot get caFile:", err)
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client = &http.Client{Transport: transport}

	return
}
