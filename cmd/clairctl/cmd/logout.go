package cmd

import (
	"fmt"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/coreos/clair/cmd/clairctl/config"
	"github.com/coreos/clair/cmd/clairctl/docker"
	"github.com/coreos/clair/cmd/clairctl/xerrors"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out from a Docker registry",
	Long:  `Log out from a Docker registry`,
	Run: func(cmd *cobra.Command, args []string) {

		if len(args) > 1 {
			fmt.Println("Only one argument is allowed")
			os.Exit(1)
		}
		var reg string = docker.DockerHub

		if len(args) == 1 {
			reg = args[0]
		}

		if _, err := os.Stat(config.HyperclairConfig()); err == nil {
			var users userMapping

			if err := readConfigFile(&users, config.HyperclairConfig()); err != nil {
				fmt.Println(xerrors.InternalError)
				logrus.Fatalf("reading hyperclair file: %v", err)
			}
			if _, present := users[reg]; present {
				delete(users, reg)

				if err := writeConfigFile(users, config.HyperclairConfig()); err != nil {
					fmt.Println(xerrors.InternalError)
					logrus.Fatalf("indenting login: %v", err)
				}

				fmt.Println("Log out successful")
				return
			}
		}
		fmt.Println("You are not logged in")
	},
}

func init() {
	RootCmd.AddCommand(logoutCmd)
}
