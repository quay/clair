//go:build tools
// +build tools

// Openapigen is a script to take the OpenAPI YAML file, turn it into a JSON
// document, and write out files for use with the "embed" package.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func main() {
	inFile := flag.String("in", "../openapi.yaml", "input YAML file")
	outDir := flag.String("out", ".", "output directory")
	flag.Parse()

	inF, err := os.Open(*inFile)
	if inF != nil {
		defer inF.Close()
	}
	if err != nil {
		log.Fatal(err)
	}

	tmp := map[interface{}]interface{}{}
	if err := yaml.NewDecoder(inF).Decode(&tmp); err != nil {
		log.Fatal(err)
	}
	embed, err := json.Marshal(convert(tmp))
	if err != nil {
		log.Fatal(err)
	}
	ck := sha256.Sum256(embed)

	outF, err := os.OpenFile(filepath.Join(*outDir, `openapi.json`), os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer outF.Close()
	if _, err := io.Copy(outF, bytes.NewReader(embed)); err != nil {
		log.Fatal(err)
	}
	outF, err = os.OpenFile(filepath.Join(*outDir, `openapi.etag`), os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer outF.Close()
	if _, err := fmt.Fprintf(outF, `"%x"`, ck); err != nil {
		log.Fatal(err)
	}
}

// Convert yoinked from:
// https://stackoverflow.com/questions/40737122/convert-yaml-to-json-without-struct/40737676#40737676
func convert(i interface{}) interface{} {
	switch x := i.(type) {
	case map[interface{}]interface{}:
		m2 := map[string]interface{}{}
		for k, v := range x {
			m2[fmt.Sprint(k)] = convert(v)
		}
		return m2
	case []interface{}:
		for i, v := range x {
			x[i] = convert(v)
		}
	case map[string]interface{}:
		for k, v := range x {
			x[k] = convert(v)
		}
	}
	return i
}
