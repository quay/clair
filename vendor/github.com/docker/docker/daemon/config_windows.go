package daemon

import (
	"os"

	flag "github.com/docker/docker/pkg/mflag"
)

var (
	defaultPidFile = os.Getenv("programdata") + string(os.PathSeparator) + "docker.pid"
	defaultGraph   = os.Getenv("programdata") + string(os.PathSeparator) + "docker"
	defaultExec    = "windows"
)

// bridgeConfig stores all the bridge driver specific
// configuration.
type bridgeConfig struct {
	VirtualSwitchName string `json:"bridge,omitempty"`
}

// Config defines the configuration of a docker daemon.
// These are the configuration settings that you pass
// to the docker daemon when you launch it with say: `docker daemon -e windows`
type Config struct {
	CommonConfig

	// Fields below here are platform specific. (There are none presently
	// for the Windows daemon.)
}

// InstallFlags adds command-line options to the top-level flag parser for
// the current process.
// Subsequent calls to `flag.Parse` will populate config with values parsed
// from the command-line.
func (config *Config) InstallFlags(cmd *flag.FlagSet, usageFn func(string) string) {
	// First handle install flags which are consistent cross-platform
	config.InstallCommonFlags(cmd, usageFn)

	// Then platform-specific install flags.
	cmd.StringVar(&config.bridgeConfig.VirtualSwitchName, []string{"b", "-bridge"}, "", "Attach containers to a virtual switch")
	cmd.StringVar(&config.SocketGroup, []string{"G", "-group"}, "", usageFn("Users or groups that can access the named pipe"))
}
