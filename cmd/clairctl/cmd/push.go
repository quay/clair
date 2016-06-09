package cmd

import (
	"fmt"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/cmd/clairctl/clair"
	"github.com/coreos/clair/cmd/clairctl/config"
	"github.com/coreos/clair/cmd/clairctl/docker"
	"github.com/coreos/clair/cmd/clairctl/server"
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
		config.ImageName = args[0]
		image, manifest, err := docker.RetrieveManifest(config.ImageName, true)
		if err != nil {
			fmt.Println(errInternalError)
			logrus.Fatalf("retrieving manifest for %q: %v", config.ImageName, err)
		}

		if err := clair.Push(image, manifest); err != nil {
			if err != nil {
				fmt.Println(errInternalError)
				logrus.Fatalf("pushing image %q: %v", image.String(), err)
			}
		}
		fmt.Printf("%v has been pushed to Clair\n", image.String())
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
	pushCmd.Flags().BoolVarP(&config.IsLocal, "local", "l", false, "Use local images")
}
