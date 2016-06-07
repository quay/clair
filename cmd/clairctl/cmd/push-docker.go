package cmd

import (
	"fmt"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/cmd/clairctl/docker"
	"github.com/coreos/clair/cmd/clairctl/dockerdist"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/spf13/cobra"
)

var pushDockerCmd = &cobra.Command{
	Use:   "push-docker IMAGE",
	Short: "Push Docker image to Clair",
	Long:  `Upload a Docker image to Clair for further analysis`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			fmt.Printf("clairctl: \"push\" requires a minimum of 1 argument\n")
			os.Exit(1)
		}

		startLocalServer()

		imageName := args[0]
		var image docker.Image
		if !docker.IsLocal {

			image, manifest, err := dockerdist.DownloadManifest(imageName, true)

			if err != nil {
				fmt.Println(errInternalError)
				logrus.Fatalf("parsing local image %q: %v", imageName, err)
			}
			// Ensure that the manifest type is supported.
			switch manifest.(type) {
			case *schema1.SignedManifest:
				break

			default:
				fmt.Println(errInternalError)
				logrus.Fatalf("only v1 manifests are currently supported")
			}
			v1manifest := manifest.(*schema1.SignedManifest)

			if err := dockerdist.Push(image, *v1manifest); err != nil {
				if err != nil {
					fmt.Println(errInternalError)
					logrus.Fatalf("pushing image %q: %v", imageName, err)
				}
			}

		} else {
			var err error
			image, err = docker.Parse(imageName)
			if err != nil {
				fmt.Println(errInternalError)
				logrus.Fatalf("parsing local image %q: %v", imageName, err)
			}
			err = docker.Prepare(&image)
			logrus.Debugf("prepared image layers: %d", len(image.FsLayers))
			if err != nil {
				fmt.Println(errInternalError)
				logrus.Fatalf("preparing local image %q from history: %v", imageName, err)
			}
			logrus.Info("Pushing Image [OLD WAY] should be deprecated")
			if err := docker.Push(image); err != nil {
				if err != nil {
					fmt.Println(errInternalError)
					logrus.Fatalf("pushing image %q: %v", imageName, err)
				}
			}
		}

		fmt.Printf("%v has been pushed to Clair\n", imageName)
	},
}

func init() {
	RootCmd.AddCommand(pushDockerCmd)
	pushDockerCmd.Flags().BoolVarP(&docker.IsLocal, "local", "l", false, "Use local images")
}
