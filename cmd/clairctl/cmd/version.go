package cmd

import (
	"fmt"
	"os"
	"text/template"

	"github.com/spf13/cobra"
)

const versionTplt = `
Clairctl version {{.}}
`

var version string

var templ = template.Must(template.New("versions").Parse(versionTplt))

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Get Versions of Clairctl and underlying services",
	Long:  `Get Versions of Clairctl and underlying services`,
	Run: func(cmd *cobra.Command, args []string) {

		err := templ.Execute(os.Stdout, version)
		if err != nil {
			fmt.Println(errInternalError)
			log.Fatalf("rendering the version: %v", err)
		}
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
