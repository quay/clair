package cmd

import (
	"fmt"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/cmd/clairctl/config"
	"github.com/coreos/clair/cmd/clairctl/docker"
	"github.com/coreos/clair/cmd/clairctl/dockercli"
	"github.com/coreos/clair/cmd/clairctl/dockerdist"
	"github.com/coreos/clair/cmd/clairctl/server"
	"github.com/docker/distribution/manifest/schema1"
	"github.com/docker/docker/reference"
	"github.com/spf13/cobra"
)

var pushCmd = &cobra.Command{
	Use:   "push IMAGE",
	Short: "Push Docker image to Clair",
	Long:  `Upload a Docker image to Clair for further analysis`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			fmt.Printf("clairctl: \"push\" requires a minimum of 1 argument\n")
			os.Exit(1)
		}

		startLocalServer()

		imageName := args[0]
		var image reference.Named
		var manifest *schema1.SignedManifest

		if !docker.IsLocal {
			n, m, err := dockerdist.DownloadManifest(imageName, true)

			if err != nil {
				fmt.Println(errInternalError)
				logrus.Fatalf("parsing local image %q: %v", imageName, err)
			}
			// Ensure that the manifest type is supported.
			switch m.(type) {
			case *schema1.SignedManifest:
				manifest = m.(*schema1.SignedManifest)
				image = n
				break

			default:
				fmt.Println(errInternalError)
				logrus.Fatalf("only v1 manifests are currently supported")
			}

		} else {
			n, err := reference.ParseNamed(imageName)
			if err != nil {
				fmt.Println(errInternalError)
				logrus.Fatalf("pushing image %q: %v", imageName, err)
			}
			m, err := dockercli.Save(n)
			if err != nil {
				fmt.Println(errInternalError)
				logrus.Fatalf("saving image %q: %v", imageName, err)
			}
			manifest = m
			image = n
		}

		if err := dockerdist.Push(image, *manifest); err != nil {
			if err != nil {
				fmt.Println(errInternalError)
				logrus.Fatalf("pushing image %q: %v", imageName, err)
			}
		}
		fmt.Printf("%v has been pushed to Clair\n", imageName)
	},
}

func startLocalServer() {
	sURL, err := config.LocalServerIP()
	if err != nil {
		fmt.Println(errInternalError)
		logrus.Fatalf("retrieving internal server IP: %v", err)
	}
	err = server.Serve(sURL)
	if err != nil {
		fmt.Println(errInternalError)
		logrus.Fatalf("starting local server: %v", err)
	}
}

func init() {
	RootCmd.AddCommand(pushCmd)
	pushCmd.Flags().BoolVarP(&docker.IsLocal, "local", "l", false, "Use local images")
}
