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

const analyseTplt = `
Image: {{.String}}
 {{.Layers | len}} layers found
 {{$ia := .}}
 {{range .Layers}} ➜ {{with .Layer}}Analysis [{{.|$ia.ShortName}}] found {{.|$ia.CountVulnerabilities}} vulnerabilities.{{end}}
 {{end}}
`

var analyseCmd = &cobra.Command{
	Use:   "analyse IMAGE",
	Short: "Analyse Docker image",
	Long:  `Analyse a Docker image with Clair, against Ubuntu, Red hat and Debian vulnerabilities databases`,
	Run: func(cmd *cobra.Command, args []string) {

		if len(args) != 1 {
			fmt.Printf("hyperclair: \"analyse\" requires a minimum of 1 argument")
			os.Exit(1)
		}

		ia := analyse(args[0])

		err := template.Must(template.New("analysis").Parse(analyseTplt)).Execute(os.Stdout, ia)
		if err != nil {
			fmt.Println(errInternalError)
			logrus.Fatalf("rendering analysis: %v", err)
		}
	},
}

func analyse(imageName string) clair.ImageAnalysis {
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

	return docker.Analyse(image)
}

func init() {
	RootCmd.AddCommand(analyseCmd)
	analyseCmd.Flags().BoolVarP(&docker.IsLocal, "local", "l", false, "Use local images")
	analyseCmd.Flags().StringP("priority", "p", "Low", "Vulnerabilities priority [Low, Medium, High, Critical]")
	viper.BindPFlag("clair.priority", analyseCmd.Flags().Lookup("priority"))
}
