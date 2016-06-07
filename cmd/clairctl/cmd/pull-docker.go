package cmd

import (
	"fmt"
	"html/template"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/cmd/clairctl/docker"
	"github.com/coreos/clair/cmd/clairctl/dockerdist"
	"github.com/docker/distribution/digest"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/docker/reference"
	"github.com/spf13/cobra"

	dockercli "github.com/fsouza/go-dockerclient"
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
		var manifest schema1.SignedManifest
		var named reference.Named

		if !docker.IsLocal {
			n, m, err := dockerdist.DownloadManifest(imageName, true)

			if err != nil {
				fmt.Println(errInternalError)
				logrus.Fatalf("parsing image %q: %v", imageName, err)
			}
			// Ensure that the manifest type is supported.
			switch m.(type) {
			case *schema1.SignedManifest:
				manifest = m.(schema1.SignedManifest)
				named = n
				break

			default:
				fmt.Println(errInternalError)
				logrus.Fatalf("only v1 manifests are currently supported")
			}

		} else {
			var err error
			named, manifest, err = LocalManifest(imageName)
			if err != nil {
				fmt.Println(errInternalError)
				logrus.Fatalf("parsing image %q: %v", imageName, err)
			}
		}

		data := struct {
			V1Manifest schema1.SignedManifest
			Named      reference.Named
		}{
			V1Manifest: manifest,
			Named:      named,
		}

		err := template.Must(template.New("pull").Parse(pullDockerTplt)).Execute(os.Stdout, data)
		if err != nil {
			fmt.Println(errInternalError)
			logrus.Fatalf("rendering image: %v", err)
		}
	},
}

func LocalManifest(imageName string) (reference.Named, schema1.SignedManifest, error) {
	manifest := schema1.SignedManifest{}
	// Parse the image name as a docker image reference.
	named, err := reference.ParseNamed(imageName)
	if err != nil {
		return nil, manifest, err
	}

	endpoint := "unix:///var/run/docker.sock"
	client, _ := dockercli.NewClient(endpoint)
	histories, _ := client.ImageHistory(imageName)
	for _, history := range histories {
		var d digest.Digest
		d, err := digest.ParseDigest(history.ID)
		if err != nil {
			return nil, manifest, err
		}
		manifest.FSLayers = append(manifest.FSLayers, schema1.FSLayer{BlobSum: d})
	}
	return named, manifest, nil
}

func init() {
	RootCmd.AddCommand(pullDockerCmd)
	pullDockerCmd.Flags().BoolVarP(&docker.IsLocal, "local", "l", false, "Use local images")
}
