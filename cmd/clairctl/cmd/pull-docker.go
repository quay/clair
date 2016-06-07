package cmd

import (
	"fmt"
	"html/template"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/cmd/clairctl/docker"
	"github.com/coreos/clair/cmd/clairctl/dockerdist"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/docker/reference"
	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
	"github.com/spf13/cobra"
)

const pullDockerTplt = `
Image: {{.Named.FullName}}
 {{.V1Manifest.FSLayers | len}} layers found
 {{range .V1Manifest.FSLayers}} ➜ {{.BlobSum}}
 {{end}}
`

var pullDockerCmd = &cobra.Command{
	Use:   "pull-docker IMAGE",
	Short: "Pull Docker image to Clair",
	Long:  `Upload a Docker image to Clair for further analysis`,
	Run: func(cmd *cobra.Command, args []string) {

		if len(args) != 1 {
			fmt.Printf("clairctl: \"pull\" requires a minimum of 1 argument\n")
			os.Exit(1)
		}

		imageName := args[0]

		if !docker.IsLocal {
			n, manifest, err := dockerdist.DownloadManifest(imageName, true)

			if err != nil {
				fmt.Println(errInternalError)
				logrus.Fatalf("parsing image %q: %v", imageName, err)
			}
			// Ensure that the manifest type is supported.
			switch manifest.(type) {
			case *schema1.SignedManifest:
				break

			default:
				fmt.Println(errInternalError)
				logrus.Fatalf("only v1 manifests are currently supported")
			}
			data := struct {
				V1Manifest *schema1.SignedManifest
				Named      reference.Named
			}{
				V1Manifest: manifest.(*schema1.SignedManifest),
				Named:      n,
			}

			err = template.Must(template.New("pull").Parse(pullDockerTplt)).Execute(os.Stdout, data)
			if err != nil {
				fmt.Println(errInternalError)
				logrus.Fatalf("rendering image: %v", err)
			}
		} else {
			localManifest(imageName)
		}
	},
}

func localManifest(imageName string) {
	defaultHeaders := map[string]string{"User-Agent": "engine-api-cli-1.0"}
	cli, err := client.NewClient("unix:///var/run/docker.sock", "v1.22", nil, defaultHeaders)
	if err != nil {
		panic(err)
	}
	t := types.ImageListOptions{MatchName: imageName}
	cli.ImageList(t)
	// histories, err := cli.ImageHistory(context.Background(), imageName)

	if err != nil {
		panic(err)
	}

	// for _, history := range histories {
	// 	fmt.Println(history)
	// }
}
func init() {
	RootCmd.AddCommand(pullDockerCmd)
	pullDockerCmd.Flags().BoolVarP(&docker.IsLocal, "local", "l", false, "Use local images")
}
