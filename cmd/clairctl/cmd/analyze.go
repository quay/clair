package cmd

import (
	"fmt"
	"os"
	"text/template"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/cmd/clairctl/clair"
	"github.com/coreos/clair/cmd/clairctl/config"
	"github.com/coreos/clair/cmd/clairctl/docker"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

		ia := analyze(args[0])

		err := template.Must(template.New("analysis").Parse(analyzeTplt)).Execute(os.Stdout, ia)
		if err != nil {
			fmt.Println(errInternalError)
			logrus.Fatalf("rendering analysis: %v", err)
		}
	},
}

func analyze(imageName string) clair.ImageAnalysis {
	var err error
	var image docker.Image

	if !docker.IsLocal {
		image, err = docker.Pull(imageName)

		if err != nil {
			if err == config.ErrLoginNotFound {
				fmt.Println(err)
			} else {
				fmt.Println(errInternalError)
			}
			logrus.Fatalf("pulling image %q: %v", imageName, err)
		}

	} else {
		image, err = docker.Parse(imageName)
		if err != nil {
			fmt.Println(errInternalError)
			logrus.Fatalf("parsing local image %q: %v", imageName, err)
		}
		docker.FromHistory(&image)
		if err != nil {
			fmt.Println(errInternalError)
			logrus.Fatalf("getting local image %q from history: %v", imageName, err)
		}
	}

	return docker.Analyze(image)
}

func init() {
	RootCmd.AddCommand(analyzeCmd)
	analyzeCmd.Flags().BoolVarP(&docker.IsLocal, "local", "l", false, "Use local images")
	analyzeCmd.Flags().StringP("priority", "p", "Low", "Vulnerabilities priority [Low, Medium, High, Critical]")
	viper.BindPFlag("clair.priority", analyzeCmd.Flags().Lookup("priority"))
}
