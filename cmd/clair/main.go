package main

import (
	"flag"
	"log"

	"github.com/quay/clair/v4/config"
	yaml "gopkg.in/yaml.v2"
)

func main() {
	var modev ModeValue
	var confv ConfValue

	flag.Var(&modev, "mode", "The mode Clair will run in. [ indexer | matcher ]")
	flag.Var(&confv, "conf", "The file system path to Clair's config file.")
	flag.Parse()

	if confv.String() == "" {
		log.Fatalf("must provide a -conf flag")
	}
	if modev.String() == "" {
		log.Fatalf("must provide a -mode flag")
	}

	var conf config.Config
	err := yaml.NewDecoder(confv.file).Decode(&conf)
	if err != nil {
		log.Fatalf("failed to decode yaml config: %w", err)
	}

}
