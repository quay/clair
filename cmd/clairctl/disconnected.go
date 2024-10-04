package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

// DisconnectedCmd is the "disconnected" subcommand.
var DisconnectedCmd = &cli.Command{
	Name:      "disconnected",
	Action:    disconnectedAction,
	Usage:     "add disconnected config drop-in",
	ArgsUsage: "",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "red-hat-repo-to-cpe-file-path",
			Usage:   "file path for the Red Hat repo-cpe-map data.",
			Value:   "",
			EnvVars: []string{"RED_HAT_REPO_TO_CPE_FILE_PATH"},
		},
		&cli.StringFlag{
			Name:    "red-hat-container-to-repos-file-path",
			Usage:   "file path for the Red Hat container-to-repos data.",
			Value:   "",
			EnvVars: []string{"RED_HAT_CONTAINER_TO_REPOS_FILE_PATH"},
		},
		&cli.BoolFlag{
			Name:    "dry-run",
			Aliases: []string{"d"},
			Usage:   "just print out drop-in.",
		},
	},
	Description: `Adds drop-in config for disconnected environments`,
}

type disconnectedCfgDropin struct {
	Indexer struct {
		Airgap  bool `json:"airgap" yaml:"airgap"`
		Scanner struct {
			Package struct {
				RHELContainerScanner map[string]string `json:"rhel_containerscanner" yaml:"rhel_containerscanner"`
			} `yaml:"package,omitempty" json:"package,omitempty"`
			Repo struct {
				RHELRepositoryScanner map[string]string `json:"rhel-repository-scanner" yaml:"rhel-repository-scanner"`
			} `yaml:"repo,omitempty" json:"repo,omitempty"`
		} `yaml:"scanner,omitempty" json:"scanner,omitempty"`
	} `yaml:"indexer,omitempty" json:"indexer,omitempty"`
	Matcher struct {
		DisableUpdaters bool `yaml:"disable_updaters,omitempty" json:"disable_updaters,omitempty"`
	}
}

func disconnectedAction(c *cli.Context) error {
	repoCPEMapFile := c.String("red-hat-repo-to-cpe-file-path")
	containerRepoMapFile := c.String("red-hat-container-to-repos-file-path")

	newConf := &disconnectedCfgDropin{}
	if repoCPEMapFile == "" {
		return errors.New("could not find repo to CPE file, either specify with --red-hat-repo-to-cpe-file-path or RED_HAT_REPO_TO_CPE_FILE_PATH")
	}
	if containerRepoMapFile == "" {
		return errors.New("could not find container to repos file, either specify with --red-hat-container-to-repos-file-path or RED_HAT_CONTAINER_TO_REPOS_FILE_PATH")

	}

	newConf.Indexer.Scanner.Repo.RHELRepositoryScanner = map[string]string{"repo2cpe_mapping_file": repoCPEMapFile}
	newConf.Indexer.Scanner.Package.RHELContainerScanner = map[string]string{"name2repos_mapping_file": containerRepoMapFile}
	newConf.Indexer.Airgap = true
	newConf.Matcher.DisableUpdaters = true

	cfgPath := c.Path("config")
	var (
		dropinPath string
		dropinData []byte
		err        error
	)
	switch {
	case strings.HasSuffix(cfgPath, ".json"):
		dropinPath = filepath.Join(cfgPath+".d", "disconnected.json")
		if dropinData, err = json.Marshal(newConf); err != nil {
			return err
		}
	case strings.HasSuffix(cfgPath, ".yaml"):
		dropinPath = filepath.Join(cfgPath+".d", "disconnected.yaml")
		if dropinData, err = yaml.Marshal(newConf); err != nil {
			return err
		}
	default:
		return errors.New("unknown config format, file is neither .yaml or .json")
	}
	if err := os.MkdirAll(filepath.Dir(dropinPath), 0o755); err != nil {
		return fmt.Errorf("unable to create needed directories: %v", err)
	}
	if c.Bool("dry-run") {
		os.Stdout.Write(dropinData)
		return nil
	} else {
		f, err := os.Create(dropinPath)
		if err != nil {
			return err
		}
		defer f.Close()

		if _, err = f.Write(dropinData); err != nil {
			return err
		}
	}

	return nil
}
