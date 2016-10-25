package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/go-check/check"
)

type testCondition func() bool

type testRequirement struct {
	Condition   testCondition
	SkipMessage string
}

// List test requirements
var (
	DaemonIsWindows = testRequirement{
		func() bool { return daemonPlatform == "windows" },
		"Test requires a Windows daemon",
	}
	DaemonIsLinux = testRequirement{
		func() bool { return daemonPlatform == "linux" },
		"Test requires a Linux daemon",
	}
	NotArm = testRequirement{
		func() bool { return os.Getenv("DOCKER_ENGINE_GOARCH") != "arm" },
		"Test requires a daemon not running on ARM",
	}
	NotPpc64le = testRequirement{
		func() bool { return os.Getenv("DOCKER_ENGINE_GOARCH") != "ppc64le" },
		"Test requires a daemon not running on ppc64le",
	}
	SameHostDaemon = testRequirement{
		func() bool { return isLocalDaemon },
		"Test requires docker daemon to run on the same machine as CLI",
	}
	UnixCli = testRequirement{
		func() bool { return isUnixCli },
		"Test requires posix utilities or functionality to run.",
	}
	ExecSupport = testRequirement{
		func() bool { return supportsExec },
		"Test requires 'docker exec' capabilities on the tested daemon.",
	}
	Network = testRequirement{
		func() bool {
			// Set a timeout on the GET at 15s
			var timeout = time.Duration(15 * time.Second)
			var url = "https://hub.docker.com"

			client := http.Client{
				Timeout: timeout,
			}

			resp, err := client.Get(url)
			if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
				panic(fmt.Sprintf("Timeout for GET request on %s", url))
			}
			if resp != nil {
				resp.Body.Close()
			}
			return err == nil
		},
		"Test requires network availability, environment variable set to none to run in a non-network enabled mode.",
	}
	Apparmor = testRequirement{
		func() bool {
			buf, err := ioutil.ReadFile("/sys/module/apparmor/parameters/enabled")
			return err == nil && len(buf) > 1 && buf[0] == 'Y'
		},
		"Test requires apparmor is enabled.",
	}
	RegistryHosting = testRequirement{
		func() bool {
			// for now registry binary is built only if we're running inside
			// container through `make test`. Figure that out by testing if
			// registry binary is in PATH.
			_, err := exec.LookPath(v2binary)
			return err == nil
		},
		fmt.Sprintf("Test requires an environment that can host %s in the same host", v2binary),
	}
	NotaryHosting = testRequirement{
		func() bool {
			// for now notary binary is built only if we're running inside
			// container through `make test`. Figure that out by testing if
			// notary-server binary is in PATH.
			_, err := exec.LookPath(notaryBinary)
			return err == nil
		},
		fmt.Sprintf("Test requires an environment that can host %s in the same host", notaryBinary),
	}
	NotOverlay = testRequirement{
		func() bool {
			cmd := exec.Command("grep", "^overlay / overlay", "/proc/mounts")
			if err := cmd.Run(); err != nil {
				return true
			}
			return false
		},
		"Test requires underlying root filesystem not be backed by overlay.",
	}

	Devicemapper = testRequirement{
		func() bool {
			cmd := exec.Command("grep", "^devicemapper / devicemapper", "/proc/mounts")
			if err := cmd.Run(); err != nil {
				return false
			}
			return true
		},
		"Test requires underlying root filesystem to be backed by devicemapper.",
	}

	IPv6 = testRequirement{
		func() bool {
			cmd := exec.Command("test", "-f", "/proc/net/if_inet6")

			if err := cmd.Run(); err != nil {
				return true
			}
			return false
		},
		"Test requires support for IPv6",
	}
	NotGCCGO = testRequirement{
		func() bool {
			out, err := exec.Command("go", "version").Output()
			if err == nil && strings.Contains(string(out), "gccgo") {
				return false
			}
			return true
		},
		"Test requires native Golang compiler instead of GCCGO",
	}
	NotUserNamespace = testRequirement{
		func() bool {
			root := os.Getenv("DOCKER_REMAP_ROOT")
			if root != "" {
				return false
			}
			return true
		},
		"Test cannot be run when remapping root",
	}
)

// testRequires checks if the environment satisfies the requirements
// for the test to run or skips the tests.
func testRequires(c *check.C, requirements ...testRequirement) {
	for _, r := range requirements {
		if !r.Condition() {
			c.Skip(r.SkipMessage)
		}
	}
}
