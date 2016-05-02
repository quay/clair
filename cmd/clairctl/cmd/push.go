package cmd

import (
	"fmt"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/cmd/clairctl/config"
	"github.com/coreos/clair/cmd/clairctl/docker"
	"github.com/coreos/clair/cmd/clairctl/server"
	"github.com/coreos/clair/cmd/clairctl/xerrors"
	"github.com/spf13/cobra"
)

var pushCmd = &cobra.Command{
	Use:   "push IMAGE",
	Short: "Push Docker image to Clair",
	Long:  `Upload a Docker image to Clair for further analysis`,
	Run: func(cmd *cobra.Command, args []string) {

		if len(args) != 1 {
			fmt.Printf("hyperclair: \"push\" requires a minimum of 1 argument\n")
			os.Exit(1)
		}

		startLocalServer()

		imageName := args[0]

		var image docker.Image
		if !docker.IsLocal {
			var err error
			image, err = docker.Pull(imageName)
			if err != nil {
				if err == xerrors.NotFound {
					fmt.Println(err)
				} else {
					fmt.Println(xerrors.InternalError)
				}
				logrus.Fatalf("pulling image %q: %v", imageName, err)
			}
		} else {
			var err error
			image, err = docker.Parse(imageName)
			if err != nil {
				fmt.Println(xerrors.InternalError)
				logrus.Fatalf("parsing local image %q: %v", imageName, err)
			}
			err = docker.Prepare(&image)
			logrus.Debugf("prepared image layers: %d", len(image.FsLayers))
			if err != nil {
				fmt.Println(xerrors.InternalError)
				logrus.Fatalf("preparing local image %q from history: %v", imageName, err)
			}
		}

		logrus.Info("Pushing Image")
		if err := docker.Push(image); err != nil {
			if err != nil {
				fmt.Println(xerrors.InternalError)
				logrus.Fatalf("pushing image %q: %v", imageName, err)
			}
		}

		fmt.Printf("%v has been pushed to Clair\n", imageName)

	},
}

func init() {
	RootCmd.AddCommand(pushCmd)
	pushCmd.Flags().BoolVarP(&docker.IsLocal, "local", "l", false, "Use local images")
}

//StartLocalServer start the hyperclair local server needed for reverse proxy and file server
func startLocalServer() {
	sURL, err := config.LocalServerIP()
	if err != nil {
		fmt.Println(xerrors.InternalError)
		logrus.Fatalf("retrieving internal server IP: %v", err)
	}
	err = server.Serve(sURL)
	if err != nil {
		fmt.Println(xerrors.InternalError)
		logrus.Fatalf("starting local server: %v", err)
	}
}
