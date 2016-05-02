package cmd

import (
	"fmt"
	"os"
	"text/template"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/coreos/clair/cmd/clairctl/xerrors"
)

const versionTplt = `
Hyperclair version {{.}}
`

var version string

var templ = template.Must(template.New("versions").Parse(versionTplt))

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Get Versions of Hyperclair and underlying services",
	Long:  `Get Versions of Hyperclair and underlying services`,
	Run: func(cmd *cobra.Command, args []string) {

		err := templ.Execute(os.Stdout, version)
		if err != nil {
			fmt.Println(xerrors.InternalError)
			logrus.Fatalf("rendering the version: %v", err)
		}
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
