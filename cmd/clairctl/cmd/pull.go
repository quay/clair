package cmd

import (
	"fmt"
	"html/template"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/cmd/clairctl/config"
	"github.com/coreos/clair/cmd/clairctl/docker"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/docker/reference"
	"github.com/spf13/cobra"
)

const pullTplt = `
Image: {{.Named.FullName}}
 {{.V1Manifest.FSLayers | len}} layers found
 {{range .V1Manifest.FSLayers}} ➜ {{.BlobSum}}
 {{end}}
`

var pullCmd = &cobra.Command{
	Use:   "pull IMAGE",
	Short: "Pull Docker image to Clair",
	Long:  `Upload a Docker image to Clair for further analysis`,
	Run: func(cmd *cobra.Command, args []string) {

		if len(args) != 1 {
			fmt.Printf("clairctl: \"pull\" requires a minimum of 1 argument\n")
			os.Exit(1)
		}

		config.ImageName = args[0]
		image, manifest, err := docker.RetrieveManifest(config.ImageName, true)
		if err != nil {
			fmt.Println(errInternalError)
			logrus.Fatalf("retrieving manifest for %q: %v", config.ImageName, err)
		}

		data := struct {
			V1Manifest schema1.SignedManifest
			Named      reference.Named
		}{
			V1Manifest: manifest,
			Named:      image,
		}

		err = template.Must(template.New("pull").Parse(pullTplt)).Execute(os.Stdout, data)
		if err != nil {
			fmt.Println(errInternalError)
			logrus.Fatalf("rendering image: %v", err)
		}
	},
}

func init() {
	RootCmd.AddCommand(pullCmd)
	pullCmd.Flags().BoolVarP(&config.IsLocal, "local", "l", false, "Use local images")
}
