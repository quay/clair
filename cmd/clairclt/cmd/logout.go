package cmd

import (
	"fmt"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/cmd/clairclt/config"
	"github.com/coreos/clair/cmd/clairclt/docker"
	"github.com/spf13/cobra"
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
		ok, err := config.RemoveLogin(reg)
		if err != nil {
			fmt.Println(errInternalError)
			logrus.Fatalf("log out: %v", err)
		}

		if ok {
			fmt.Println("Log out successful")
			return
		}
		fmt.Println("You are not logged in")
	},
}

func init() {
	RootCmd.AddCommand(logoutCmd)
}
