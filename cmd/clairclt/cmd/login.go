package cmd

import (
	"encoding/base64"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/Sirupsen/logrus"
	"github.com/coreos/clair/cmd/clairclt/config"
	"github.com/coreos/clair/cmd/clairclt/docker"
	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in to a Docker registry",
	Long:  `Log in to a Docker registry`,
	Run: func(cmd *cobra.Command, args []string) {

		if len(args) > 1 {
			fmt.Println("Only one argument is allowed")
			os.Exit(1)
		}

		var reg string = docker.DockerHub

		if len(args) == 1 {
			reg = args[0]
		}

		var login config.Login
		if err := askForLogin(&login); err != nil {
			fmt.Println(errInternalError)
			logrus.Fatalf("encrypting password: %v", err)
		}

		config.AddLogin(reg, login)

		logged, err := docker.Login(reg)

		if err != nil && err != docker.ErrUnauthorized {
			config.RemoveLogin(reg)
			fmt.Println(errInternalError)
			logrus.Fatalf("log in: %v", err)
		}

		if !logged {
			config.RemoveLogin(reg)
			fmt.Println("Unauthorized: Wrong login/password, please try again")
			os.Exit(1)
		}

		fmt.Println("Login Successful")
	},
}

func askForLogin(login *config.Login) error {
	fmt.Print("Username: ")
	fmt.Scan(&login.Username)
	fmt.Print("Password: ")
	pwd, err := terminal.ReadPassword(1)
	if err != nil {
		return err
	}
	fmt.Println(" ")

	encryptedPwd := base64.StdEncoding.EncodeToString(pwd)
	login.Password = string(encryptedPwd)
	return nil
}

func init() {
	RootCmd.AddCommand(loginCmd)
}
