package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/coreos/clair/cmd/clairctl/clair"
	"github.com/coreos/clair/cmd/clairctl/config"
	"github.com/spf13/cobra"
)

var errInternalError = errors.New("client quit unexpectedly")

var cfgFile string
var logLevel string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "clairctl",
	Short: "Analyze your docker image with Clair, directly from your registry or local images.",
	Long:  ``,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		err = config.Clean()
		fmt.Println(err)
		os.Exit(-1)
	}

	if err := config.Clean(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.clairctl.yml)")
	RootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "", "log level [Panic,Fatal,Error,Warn,Info,Debug]")
}

func initConfig() {
	config.Init(cfgFile, logLevel)
	clair.Config()
}
