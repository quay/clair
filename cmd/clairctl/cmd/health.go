package cmd

import (
	"fmt"
	"os"
	"text/template"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/coreos/clair/cmd/clairctl/clair"
	"github.com/coreos/clair/cmd/clairctl/xerrors"
)

const healthTplt = `
Clair: {{if .}}✔{{else}}✘{{end}}
`

type health struct {
	Clair interface{} `json:"clair"`
}

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Get Health of Hyperclair and underlying services",
	Long:  `Get Health of Hyperclair and underlying services`,
	Run: func(cmd *cobra.Command, args []string) {
		ok := clair.IsHealthy()
		err := template.Must(template.New("health").Parse(healthTplt)).Execute(os.Stdout, ok)
		if err != nil {
			fmt.Println(xerrors.InternalError)
			logrus.Fatalf("rendering the health: %v", err)
		}

	},
}

func init() {
	RootCmd.AddCommand(healthCmd)
}
