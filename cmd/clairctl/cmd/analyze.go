package cmd

import (
	"fmt"
	"os"
	"text/template"

	"github.com/jgsqware/clairctl/clair"
	"github.com/jgsqware/clairctl/config"
	"github.com/jgsqware/clairctl/docker"
	"github.com/spf13/cobra"
)

const analyzeTplt = `
Image: {{.String}}
 {{.Layers | len}} layers found
 {{$ia := .}}
 {{range .Layers}} ➜ {{with .Layer}}Analysis [{{.|$ia.ShortName}}] found {{.|$ia.CountVulnerabilities}} vulnerabilities.{{end}}
 {{end}}
`

var analyzeCmd = &cobra.Command{
	Use:   "analyze IMAGE",
	Short: "Analyze Docker image",
	Long:  `Analyze a Docker image with Clair, against Ubuntu, Red hat and Debian vulnerabilities databases`,
	Run: func(cmd *cobra.Command, args []string) {

		if len(args) != 1 {
			fmt.Printf("clairctl: \"analyze\" requires a minimum of 1 argument")
			os.Exit(1)
		}

		config.ImageName = args[0]
		image, manifest, err := docker.RetrieveManifest(config.ImageName, true)
		if err != nil {
			fmt.Println(errInternalError)
			log.Fatalf("retrieving manifest for %q: %v", config.ImageName, err)
		}

		startLocalServer()
		if err := clair.Push(image, manifest); err != nil {
			if err != nil {
				fmt.Println(errInternalError)
				log.Fatalf("pushing image %q: %v", image.String(), err)
			}
		}

		analysis := clair.Analyze(image, manifest)
		err = template.Must(template.New("analysis").Parse(analyzeTplt)).Execute(os.Stdout, analysis)
		if err != nil {
			fmt.Println(errInternalError)
			log.Fatalf("rendering analysis: %v", err)
		}
	},
}

func init() {
	RootCmd.AddCommand(analyzeCmd)
	analyzeCmd.Flags().BoolVarP(&config.IsLocal, "local", "l", false, "Use local images")
}
