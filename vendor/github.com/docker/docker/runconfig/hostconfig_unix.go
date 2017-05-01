// +build !windows,!solaris

package runconfig

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/pkg/sysinfo"
)

// DefaultDaemonNetworkMode returns the default network stack the daemon should
// use.
func DefaultDaemonNetworkMode() container.NetworkMode {
	return container.NetworkMode("bridge")
}

// IsPreDefinedNetwork indicates if a network is predefined by the daemon
func IsPreDefinedNetwork(network string) bool {
	n := container.NetworkMode(network)
	return n.IsBridge() || n.IsHost() || n.IsNone() || n.IsDefault() || network == "ingress"
}

// ValidateNetMode ensures that the various combinations of requested
// network settings are valid.
func ValidateNetMode(c *container.Config, hc *container.HostConfig) error {
	// We may not be passed a host config, such as in the case of docker commit
	if hc == nil {
		return nil
	}
	parts := strings.Split(string(hc.NetworkMode), ":")
	if parts[0] == "container" {
		if len(parts) < 2 || parts[1] == "" {
			return fmt.Errorf("--net: invalid net mode: invalid container format container:<name|id>")
		}
	}

	if hc.NetworkMode.IsContainer() && c.Hostname != "" {
		return ErrConflictNetworkHostname
	}

	if hc.UTSMode.IsHost() && c.Hostname != "" {
		return ErrConflictUTSHostname
	}

	if hc.NetworkMode.IsHost() && len(hc.Links) > 0 {
		return ErrConflictHostNetworkAndLinks
	}

	if hc.NetworkMode.IsContainer() && len(hc.Links) > 0 {
		return ErrConflictContainerNetworkAndLinks
	}

	if hc.NetworkMode.IsContainer() && len(hc.DNS) > 0 {
		return ErrConflictNetworkAndDNS
	}

	if hc.NetworkMode.IsContainer() && len(hc.ExtraHosts) > 0 {
		return ErrConflictNetworkHosts
	}

	if (hc.NetworkMode.IsContainer() || hc.NetworkMode.IsHost()) && c.MacAddress != "" {
		return ErrConflictContainerNetworkAndMac
	}

	if hc.NetworkMode.IsContainer() && (len(hc.PortBindings) > 0 || hc.PublishAllPorts == true) {
		return ErrConflictNetworkPublishPorts
	}

	if hc.NetworkMode.IsContainer() && len(c.ExposedPorts) > 0 {
		return ErrConflictNetworkExposePorts
	}
	return nil
}

// ValidateIsolation performs platform specific validation of
// isolation in the hostconfig structure. Linux only supports "default"
// which is LXC container isolation
func ValidateIsolation(hc *container.HostConfig) error {
	// We may not be passed a host config, such as in the case of docker commit
	if hc == nil {
		return nil
	}
	if !hc.Isolation.IsValid() {
		return fmt.Errorf("invalid --isolation: %q - %s only supports 'default'", hc.Isolation, runtime.GOOS)
	}
	return nil
}

// ValidateQoS performs platform specific validation of the QoS settings
func ValidateQoS(hc *container.HostConfig) error {
	// We may not be passed a host config, such as in the case of docker commit
	if hc == nil {
		return nil
	}

	if hc.IOMaximumBandwidth != 0 {
		return fmt.Errorf("invalid QoS settings: %s does not support --io-maxbandwidth", runtime.GOOS)
	}

	if hc.IOMaximumIOps != 0 {
		return fmt.Errorf("invalid QoS settings: %s does not support --io-maxiops", runtime.GOOS)
	}
	return nil
}

// ValidateResources performs platform specific validation of the resource settings
// cpu-rt-runtime and cpu-rt-period can not be greater than their parent, cpu-rt-runtime requires sys_nice
func ValidateResources(hc *container.HostConfig, si *sysinfo.SysInfo) error {
	// We may not be passed a host config, such as in the case of docker commit
	if hc == nil {
		return nil
	}

	if hc.Resources.CPURealtimePeriod > 0 && !si.CPURealtimePeriod {
		return fmt.Errorf("invalid --cpu-rt-period: Your kernel does not support cgroup rt period")
	}

	if hc.Resources.CPURealtimeRuntime > 0 && !si.CPURealtimeRuntime {
		return fmt.Errorf("invalid --cpu-rt-runtime: Your kernel does not support cgroup rt runtime")
	}

	if hc.Resources.CPURealtimePeriod != 0 && hc.Resources.CPURealtimeRuntime != 0 && hc.Resources.CPURealtimeRuntime > hc.Resources.CPURealtimePeriod {
		return fmt.Errorf("invalid --cpu-rt-runtime: rt runtime cannot be higher than rt period")
	}
	return nil
}
