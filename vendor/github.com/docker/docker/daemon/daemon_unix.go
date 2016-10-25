// +build linux freebsd

package daemon

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/container"
	"github.com/docker/docker/image"
	"github.com/docker/docker/layer"
	"github.com/docker/docker/pkg/idtools"
	"github.com/docker/docker/pkg/parsers"
	"github.com/docker/docker/pkg/parsers/kernel"
	"github.com/docker/docker/pkg/sysinfo"
	"github.com/docker/docker/reference"
	"github.com/docker/docker/runconfig"
	runconfigopts "github.com/docker/docker/runconfig/opts"
	pblkiodev "github.com/docker/engine-api/types/blkiodev"
	containertypes "github.com/docker/engine-api/types/container"
	"github.com/docker/libnetwork"
	nwconfig "github.com/docker/libnetwork/config"
	"github.com/docker/libnetwork/drivers/bridge"
	"github.com/docker/libnetwork/ipamutils"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/options"
	"github.com/docker/libnetwork/types"
	blkiodev "github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/label"
	"github.com/opencontainers/runc/libcontainer/user"
)

const (
	// See https://git.kernel.org/cgit/linux/kernel/git/tip/tip.git/tree/kernel/sched/sched.h?id=8cd9234c64c584432f6992fe944ca9e46ca8ea76#n269
	linuxMinCPUShares = 2
	linuxMaxCPUShares = 262144
	platformSupported = true
	// It's not kernel limit, we want this 4M limit to supply a reasonable functional container
	linuxMinMemory = 4194304
	// constants for remapped root settings
	defaultIDSpecifier string = "default"
	defaultRemappedID  string = "dockremap"
)

func getBlkioWeightDevices(config *containertypes.HostConfig) ([]*blkiodev.WeightDevice, error) {
	var stat syscall.Stat_t
	var blkioWeightDevices []*blkiodev.WeightDevice

	for _, weightDevice := range config.BlkioWeightDevice {
		if err := syscall.Stat(weightDevice.Path, &stat); err != nil {
			return nil, err
		}
		weightDevice := blkiodev.NewWeightDevice(int64(stat.Rdev/256), int64(stat.Rdev%256), weightDevice.Weight, 0)
		blkioWeightDevices = append(blkioWeightDevices, weightDevice)
	}

	return blkioWeightDevices, nil
}

func parseSecurityOpt(container *container.Container, config *containertypes.HostConfig) error {
	var (
		labelOpts []string
		err       error
	)

	for _, opt := range config.SecurityOpt {
		con := strings.SplitN(opt, ":", 2)
		if len(con) == 1 {
			return fmt.Errorf("Invalid --security-opt: %q", opt)
		}
		switch con[0] {
		case "label":
			labelOpts = append(labelOpts, con[1])
		case "apparmor":
			container.AppArmorProfile = con[1]
		case "seccomp":
			container.SeccompProfile = con[1]
		default:
			return fmt.Errorf("Invalid --security-opt: %q", opt)
		}
	}

	container.ProcessLabel, container.MountLabel, err = label.InitLabels(labelOpts)
	return err
}

func getBlkioReadIOpsDevices(config *containertypes.HostConfig) ([]*blkiodev.ThrottleDevice, error) {
	var blkioReadIOpsDevice []*blkiodev.ThrottleDevice
	var stat syscall.Stat_t

	for _, iopsDevice := range config.BlkioDeviceReadIOps {
		if err := syscall.Stat(iopsDevice.Path, &stat); err != nil {
			return nil, err
		}
		readIOpsDevice := blkiodev.NewThrottleDevice(int64(stat.Rdev/256), int64(stat.Rdev%256), iopsDevice.Rate)
		blkioReadIOpsDevice = append(blkioReadIOpsDevice, readIOpsDevice)
	}

	return blkioReadIOpsDevice, nil
}

func getBlkioWriteIOpsDevices(config *containertypes.HostConfig) ([]*blkiodev.ThrottleDevice, error) {
	var blkioWriteIOpsDevice []*blkiodev.ThrottleDevice
	var stat syscall.Stat_t

	for _, iopsDevice := range config.BlkioDeviceWriteIOps {
		if err := syscall.Stat(iopsDevice.Path, &stat); err != nil {
			return nil, err
		}
		writeIOpsDevice := blkiodev.NewThrottleDevice(int64(stat.Rdev/256), int64(stat.Rdev%256), iopsDevice.Rate)
		blkioWriteIOpsDevice = append(blkioWriteIOpsDevice, writeIOpsDevice)
	}

	return blkioWriteIOpsDevice, nil
}

func getBlkioReadBpsDevices(config *containertypes.HostConfig) ([]*blkiodev.ThrottleDevice, error) {
	var blkioReadBpsDevice []*blkiodev.ThrottleDevice
	var stat syscall.Stat_t

	for _, bpsDevice := range config.BlkioDeviceReadBps {
		if err := syscall.Stat(bpsDevice.Path, &stat); err != nil {
			return nil, err
		}
		readBpsDevice := blkiodev.NewThrottleDevice(int64(stat.Rdev/256), int64(stat.Rdev%256), bpsDevice.Rate)
		blkioReadBpsDevice = append(blkioReadBpsDevice, readBpsDevice)
	}

	return blkioReadBpsDevice, nil
}

func getBlkioWriteBpsDevices(config *containertypes.HostConfig) ([]*blkiodev.ThrottleDevice, error) {
	var blkioWriteBpsDevice []*blkiodev.ThrottleDevice
	var stat syscall.Stat_t

	for _, bpsDevice := range config.BlkioDeviceWriteBps {
		if err := syscall.Stat(bpsDevice.Path, &stat); err != nil {
			return nil, err
		}
		writeBpsDevice := blkiodev.NewThrottleDevice(int64(stat.Rdev/256), int64(stat.Rdev%256), bpsDevice.Rate)
		blkioWriteBpsDevice = append(blkioWriteBpsDevice, writeBpsDevice)
	}

	return blkioWriteBpsDevice, nil
}

func checkKernelVersion(k, major, minor int) bool {
	if v, err := kernel.GetKernelVersion(); err != nil {
		logrus.Warnf("%s", err)
	} else {
		if kernel.CompareKernelVersion(*v, kernel.VersionInfo{Kernel: k, Major: major, Minor: minor}) < 0 {
			return false
		}
	}
	return true
}

func checkKernel() error {
	// Check for unsupported kernel versions
	// FIXME: it would be cleaner to not test for specific versions, but rather
	// test for specific functionalities.
	// Unfortunately we can't test for the feature "does not cause a kernel panic"
	// without actually causing a kernel panic, so we need this workaround until
	// the circumstances of pre-3.10 crashes are clearer.
	// For details see https://github.com/docker/docker/issues/407
	if !checkKernelVersion(3, 10, 0) {
		v, _ := kernel.GetKernelVersion()
		if os.Getenv("DOCKER_NOWARN_KERNEL_VERSION") == "" {
			logrus.Warnf("Your Linux kernel version %s can be unstable running docker. Please upgrade your kernel to 3.10.0.", v.String())
		}
	}
	return nil
}

// adaptContainerSettings is called during container creation to modify any
// settings necessary in the HostConfig structure.
func (daemon *Daemon) adaptContainerSettings(hostConfig *containertypes.HostConfig, adjustCPUShares bool) error {
	if adjustCPUShares && hostConfig.CPUShares > 0 {
		// Handle unsupported CPUShares
		if hostConfig.CPUShares < linuxMinCPUShares {
			logrus.Warnf("Changing requested CPUShares of %d to minimum allowed of %d", hostConfig.CPUShares, linuxMinCPUShares)
			hostConfig.CPUShares = linuxMinCPUShares
		} else if hostConfig.CPUShares > linuxMaxCPUShares {
			logrus.Warnf("Changing requested CPUShares of %d to maximum allowed of %d", hostConfig.CPUShares, linuxMaxCPUShares)
			hostConfig.CPUShares = linuxMaxCPUShares
		}
	}
	if hostConfig.Memory > 0 && hostConfig.MemorySwap == 0 {
		// By default, MemorySwap is set to twice the size of Memory.
		hostConfig.MemorySwap = hostConfig.Memory * 2
	}
	if hostConfig.ShmSize == 0 {
		hostConfig.ShmSize = container.DefaultSHMSize
	}
	var err error
	if hostConfig.SecurityOpt == nil {
		hostConfig.SecurityOpt, err = daemon.generateSecurityOpt(hostConfig.IpcMode, hostConfig.PidMode)
		if err != nil {
			return err
		}
	}
	if hostConfig.MemorySwappiness == nil {
		defaultSwappiness := int64(-1)
		hostConfig.MemorySwappiness = &defaultSwappiness
	}
	if hostConfig.OomKillDisable == nil {
		defaultOomKillDisable := false
		hostConfig.OomKillDisable = &defaultOomKillDisable
	}

	return nil
}

func verifyContainerResources(resources *containertypes.Resources, sysInfo *sysinfo.SysInfo, update bool) ([]string, error) {
	warnings := []string{}

	// memory subsystem checks and adjustments
	if resources.Memory != 0 && resources.Memory < linuxMinMemory {
		return warnings, fmt.Errorf("Minimum memory limit allowed is 4MB")
	}
	if resources.Memory > 0 && !sysInfo.MemoryLimit {
		warnings = append(warnings, "Your kernel does not support memory limit capabilities. Limitation discarded.")
		logrus.Warnf("Your kernel does not support memory limit capabilities. Limitation discarded.")
		resources.Memory = 0
		resources.MemorySwap = -1
	}
	if resources.Memory > 0 && resources.MemorySwap != -1 && !sysInfo.SwapLimit {
		warnings = append(warnings, "Your kernel does not support swap limit capabilities, memory limited without swap.")
		logrus.Warnf("Your kernel does not support swap limit capabilities, memory limited without swap.")
		resources.MemorySwap = -1
	}
	if resources.Memory > 0 && resources.MemorySwap > 0 && resources.MemorySwap < resources.Memory {
		return warnings, fmt.Errorf("Minimum memoryswap limit should be larger than memory limit, see usage.")
	}
	if resources.Memory == 0 && resources.MemorySwap > 0 && !update {
		return warnings, fmt.Errorf("You should always set the Memory limit when using Memoryswap limit, see usage.")
	}
	if resources.MemorySwappiness != nil && *resources.MemorySwappiness != -1 && !sysInfo.MemorySwappiness {
		warnings = append(warnings, "Your kernel does not support memory swappiness capabilities, memory swappiness discarded.")
		logrus.Warnf("Your kernel does not support memory swappiness capabilities, memory swappiness discarded.")
		resources.MemorySwappiness = nil
	}
	if resources.MemorySwappiness != nil {
		swappiness := *resources.MemorySwappiness
		if swappiness < -1 || swappiness > 100 {
			return warnings, fmt.Errorf("Invalid value: %v, valid memory swappiness range is 0-100.", swappiness)
		}
	}
	if resources.MemoryReservation > 0 && !sysInfo.MemoryReservation {
		warnings = append(warnings, "Your kernel does not support memory soft limit capabilities. Limitation discarded.")
		logrus.Warnf("Your kernel does not support memory soft limit capabilities. Limitation discarded.")
		resources.MemoryReservation = 0
	}
	if resources.Memory > 0 && resources.MemoryReservation > 0 && resources.Memory < resources.MemoryReservation {
		return warnings, fmt.Errorf("Minimum memory limit should be larger than memory reservation limit, see usage.")
	}
	if resources.KernelMemory > 0 && !sysInfo.KernelMemory {
		warnings = append(warnings, "Your kernel does not support kernel memory limit capabilities. Limitation discarded.")
		logrus.Warnf("Your kernel does not support kernel memory limit capabilities. Limitation discarded.")
		resources.KernelMemory = 0
	}
	if resources.KernelMemory > 0 && resources.KernelMemory < linuxMinMemory {
		return warnings, fmt.Errorf("Minimum kernel memory limit allowed is 4MB")
	}
	if resources.KernelMemory > 0 && !checkKernelVersion(4, 0, 0) {
		warnings = append(warnings, "You specified a kernel memory limit on a kernel older than 4.0. Kernel memory limits are experimental on older kernels, it won't work as expected and can cause your system to be unstable.")
		logrus.Warnf("You specified a kernel memory limit on a kernel older than 4.0. Kernel memory limits are experimental on older kernels, it won't work as expected and can cause your system to be unstable.")
	}
	if resources.OomKillDisable != nil && !sysInfo.OomKillDisable {
		// only produce warnings if the setting wasn't to *disable* the OOM Kill; no point
		// warning the caller if they already wanted the feature to be off
		if *resources.OomKillDisable {
			warnings = append(warnings, "Your kernel does not support OomKillDisable, OomKillDisable discarded.")
			logrus.Warnf("Your kernel does not support OomKillDisable, OomKillDisable discarded.")
		}
		resources.OomKillDisable = nil
	}

	// cpu subsystem checks and adjustments
	if resources.CPUShares > 0 && !sysInfo.CPUShares {
		warnings = append(warnings, "Your kernel does not support CPU shares. Shares discarded.")
		logrus.Warnf("Your kernel does not support CPU shares. Shares discarded.")
		resources.CPUShares = 0
	}
	if resources.CPUPeriod > 0 && !sysInfo.CPUCfsPeriod {
		warnings = append(warnings, "Your kernel does not support CPU cfs period. Period discarded.")
		logrus.Warnf("Your kernel does not support CPU cfs period. Period discarded.")
		resources.CPUPeriod = 0
	}
	if resources.CPUQuota > 0 && !sysInfo.CPUCfsQuota {
		warnings = append(warnings, "Your kernel does not support CPU cfs quota. Quota discarded.")
		logrus.Warnf("Your kernel does not support CPU cfs quota. Quota discarded.")
		resources.CPUQuota = 0
	}

	// cpuset subsystem checks and adjustments
	if (resources.CpusetCpus != "" || resources.CpusetMems != "") && !sysInfo.Cpuset {
		warnings = append(warnings, "Your kernel does not support cpuset. Cpuset discarded.")
		logrus.Warnf("Your kernel does not support cpuset. Cpuset discarded.")
		resources.CpusetCpus = ""
		resources.CpusetMems = ""
	}
	cpusAvailable, err := sysInfo.IsCpusetCpusAvailable(resources.CpusetCpus)
	if err != nil {
		return warnings, fmt.Errorf("Invalid value %s for cpuset cpus.", resources.CpusetCpus)
	}
	if !cpusAvailable {
		return warnings, fmt.Errorf("Requested CPUs are not available - requested %s, available: %s.", resources.CpusetCpus, sysInfo.Cpus)
	}
	memsAvailable, err := sysInfo.IsCpusetMemsAvailable(resources.CpusetMems)
	if err != nil {
		return warnings, fmt.Errorf("Invalid value %s for cpuset mems.", resources.CpusetMems)
	}
	if !memsAvailable {
		return warnings, fmt.Errorf("Requested memory nodes are not available - requested %s, available: %s.", resources.CpusetMems, sysInfo.Mems)
	}

	// blkio subsystem checks and adjustments
	if resources.BlkioWeight > 0 && !sysInfo.BlkioWeight {
		warnings = append(warnings, "Your kernel does not support Block I/O weight. Weight discarded.")
		logrus.Warnf("Your kernel does not support Block I/O weight. Weight discarded.")
		resources.BlkioWeight = 0
	}
	if resources.BlkioWeight > 0 && (resources.BlkioWeight < 10 || resources.BlkioWeight > 1000) {
		return warnings, fmt.Errorf("Range of blkio weight is from 10 to 1000.")
	}
	if len(resources.BlkioWeightDevice) > 0 && !sysInfo.BlkioWeightDevice {
		warnings = append(warnings, "Your kernel does not support Block I/O weight_device.")
		logrus.Warnf("Your kernel does not support Block I/O weight_device. Weight-device discarded.")
		resources.BlkioWeightDevice = []*pblkiodev.WeightDevice{}
	}
	if len(resources.BlkioDeviceReadBps) > 0 && !sysInfo.BlkioReadBpsDevice {
		warnings = append(warnings, "Your kernel does not support Block read limit in bytes per second.")
		logrus.Warnf("Your kernel does not support Block I/O read limit in bytes per second. --device-read-bps discarded.")
		resources.BlkioDeviceReadBps = []*pblkiodev.ThrottleDevice{}
	}
	if len(resources.BlkioDeviceWriteBps) > 0 && !sysInfo.BlkioWriteBpsDevice {
		warnings = append(warnings, "Your kernel does not support Block write limit in bytes per second.")
		logrus.Warnf("Your kernel does not support Block I/O write limit in bytes per second. --device-write-bps discarded.")
		resources.BlkioDeviceWriteBps = []*pblkiodev.ThrottleDevice{}
	}
	if len(resources.BlkioDeviceReadIOps) > 0 && !sysInfo.BlkioReadIOpsDevice {
		warnings = append(warnings, "Your kernel does not support Block read limit in IO per second.")
		logrus.Warnf("Your kernel does not support Block I/O read limit in IO per second. -device-read-iops discarded.")
		resources.BlkioDeviceReadIOps = []*pblkiodev.ThrottleDevice{}
	}
	if len(resources.BlkioDeviceWriteIOps) > 0 && !sysInfo.BlkioWriteIOpsDevice {
		warnings = append(warnings, "Your kernel does not support Block write limit in IO per second.")
		logrus.Warnf("Your kernel does not support Block I/O write limit in IO per second. --device-write-iops discarded.")
		resources.BlkioDeviceWriteIOps = []*pblkiodev.ThrottleDevice{}
	}

	return warnings, nil
}

func (daemon *Daemon) getCgroupDriver() string {
	cgroupDriver := "cgroupfs"
	if daemon.usingSystemd() {
		cgroupDriver = "systemd"
	}
	return cgroupDriver
}

func usingSystemd(config *Config) bool {
	for _, option := range config.ExecOptions {
		key, val, err := parsers.ParseKeyValueOpt(option)
		if err != nil || !strings.EqualFold(key, "native.cgroupdriver") {
			continue
		}
		if val == "systemd" {
			return true
		}
	}

	return false
}

func (daemon *Daemon) usingSystemd() bool {
	return usingSystemd(daemon.configStore)
}

// verifyPlatformContainerSettings performs platform-specific validation of the
// hostconfig and config structures.
func verifyPlatformContainerSettings(daemon *Daemon, hostConfig *containertypes.HostConfig, config *containertypes.Config, update bool) ([]string, error) {
	warnings := []string{}
	sysInfo := sysinfo.New(true)

	warnings, err := daemon.verifyExperimentalContainerSettings(hostConfig, config)
	if err != nil {
		return warnings, err
	}

	w, err := verifyContainerResources(&hostConfig.Resources, sysInfo, update)
	if err != nil {
		return warnings, err
	}
	warnings = append(warnings, w...)

	if hostConfig.ShmSize < 0 {
		return warnings, fmt.Errorf("SHM size must be greater then 0")
	}

	if hostConfig.OomScoreAdj < -1000 || hostConfig.OomScoreAdj > 1000 {
		return warnings, fmt.Errorf("Invalid value %d, range for oom score adj is [-1000, 1000].", hostConfig.OomScoreAdj)
	}
	if sysInfo.IPv4ForwardingDisabled {
		warnings = append(warnings, "IPv4 forwarding is disabled. Networking will not work.")
		logrus.Warnf("IPv4 forwarding is disabled. Networking will not work")
	}
	// check for various conflicting options with user namespaces
	if daemon.configStore.RemappedRoot != "" {
		if hostConfig.Privileged {
			return warnings, fmt.Errorf("Privileged mode is incompatible with user namespaces")
		}
		if hostConfig.NetworkMode.IsHost() || hostConfig.NetworkMode.IsContainer() {
			return warnings, fmt.Errorf("Cannot share the host or a container's network namespace when user namespaces are enabled")
		}
		if hostConfig.PidMode.IsHost() {
			return warnings, fmt.Errorf("Cannot share the host PID namespace when user namespaces are enabled")
		}
		if hostConfig.IpcMode.IsContainer() {
			return warnings, fmt.Errorf("Cannot share a container's IPC namespace when user namespaces are enabled")
		}
		if hostConfig.ReadonlyRootfs {
			return warnings, fmt.Errorf("Cannot use the --read-only option when user namespaces are enabled")
		}
	}
	if hostConfig.CgroupParent != "" && daemon.usingSystemd() {
		// CgroupParent for systemd cgroup should be named as "xxx.slice"
		if len(hostConfig.CgroupParent) <= 6 || !strings.HasSuffix(hostConfig.CgroupParent, ".slice") {
			return warnings, fmt.Errorf("cgroup-parent for systemd cgroup should be a valid slice named as \"xxx.slice\"")
		}
	}
	return warnings, nil
}

// verifyDaemonSettings performs validation of daemon config struct
func verifyDaemonSettings(config *Config) error {
	// Check for mutually incompatible config options
	if config.bridgeConfig.Iface != "" && config.bridgeConfig.IP != "" {
		return fmt.Errorf("You specified -b & --bip, mutually exclusive options. Please specify only one")
	}
	if !config.bridgeConfig.EnableIPTables && !config.bridgeConfig.InterContainerCommunication {
		return fmt.Errorf("You specified --iptables=false with --icc=false. ICC=false uses iptables to function. Please set --icc or --iptables to true")
	}
	if !config.bridgeConfig.EnableIPTables && config.bridgeConfig.EnableIPMasq {
		config.bridgeConfig.EnableIPMasq = false
	}
	if config.CgroupParent != "" && usingSystemd(config) {
		if len(config.CgroupParent) <= 6 || !strings.HasSuffix(config.CgroupParent, ".slice") {
			return fmt.Errorf("cgroup-parent for systemd cgroup should be a valid slice named as \"xxx.slice\"")
		}
	}
	return nil
}

// checkSystem validates platform-specific requirements
func checkSystem() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("The Docker daemon needs to be run as root")
	}
	return checkKernel()
}

// configureMaxThreads sets the Go runtime max threads threshold
// which is 90% of the kernel setting from /proc/sys/kernel/threads-max
func configureMaxThreads(config *Config) error {
	mt, err := ioutil.ReadFile("/proc/sys/kernel/threads-max")
	if err != nil {
		return err
	}
	mtint, err := strconv.Atoi(strings.TrimSpace(string(mt)))
	if err != nil {
		return err
	}
	maxThreads := (mtint / 100) * 90
	debug.SetMaxThreads(maxThreads)
	logrus.Debugf("Golang's threads limit set to %d", maxThreads)
	return nil
}

// configureKernelSecuritySupport configures and validate security support for the kernel
func configureKernelSecuritySupport(config *Config, driverName string) error {
	if config.EnableSelinuxSupport {
		if selinuxEnabled() {
			// As Docker on overlayFS and SELinux are incompatible at present, error on overlayfs being enabled
			if driverName == "overlay" {
				return fmt.Errorf("SELinux is not supported with the %s graph driver", driverName)
			}
			logrus.Debug("SELinux enabled successfully")
		} else {
			logrus.Warn("Docker could not enable SELinux on the host system")
		}
	} else {
		selinuxSetDisabled()
	}
	return nil
}

func isBridgeNetworkDisabled(config *Config) bool {
	return config.bridgeConfig.Iface == disableNetworkBridge
}

func (daemon *Daemon) networkOptions(dconfig *Config) ([]nwconfig.Option, error) {
	options := []nwconfig.Option{}
	if dconfig == nil {
		return options, nil
	}

	options = append(options, nwconfig.OptionDataDir(dconfig.Root))

	dd := runconfig.DefaultDaemonNetworkMode()
	dn := runconfig.DefaultDaemonNetworkMode().NetworkName()
	options = append(options, nwconfig.OptionDefaultDriver(string(dd)))
	options = append(options, nwconfig.OptionDefaultNetwork(dn))

	if strings.TrimSpace(dconfig.ClusterStore) != "" {
		kv := strings.Split(dconfig.ClusterStore, "://")
		if len(kv) != 2 {
			return nil, fmt.Errorf("kv store daemon config must be of the form KV-PROVIDER://KV-URL")
		}
		options = append(options, nwconfig.OptionKVProvider(kv[0]))
		options = append(options, nwconfig.OptionKVProviderURL(kv[1]))
	}
	if len(dconfig.ClusterOpts) > 0 {
		options = append(options, nwconfig.OptionKVOpts(dconfig.ClusterOpts))
	}

	if daemon.discoveryWatcher != nil {
		options = append(options, nwconfig.OptionDiscoveryWatcher(daemon.discoveryWatcher))
	}

	if dconfig.ClusterAdvertise != "" {
		options = append(options, nwconfig.OptionDiscoveryAddress(dconfig.ClusterAdvertise))
	}

	options = append(options, nwconfig.OptionLabels(dconfig.Labels))
	options = append(options, driverOptions(dconfig)...)
	return options, nil
}

func (daemon *Daemon) initNetworkController(config *Config) (libnetwork.NetworkController, error) {
	netOptions, err := daemon.networkOptions(config)
	if err != nil {
		return nil, err
	}

	controller, err := libnetwork.New(netOptions...)
	if err != nil {
		return nil, fmt.Errorf("error obtaining controller instance: %v", err)
	}

	// Initialize default network on "null"
	if _, err := controller.NewNetwork("null", "none", libnetwork.NetworkOptionPersist(false)); err != nil {
		return nil, fmt.Errorf("Error creating default \"null\" network: %v", err)
	}

	// Initialize default network on "host"
	if _, err := controller.NewNetwork("host", "host", libnetwork.NetworkOptionPersist(false)); err != nil {
		return nil, fmt.Errorf("Error creating default \"host\" network: %v", err)
	}

	if !config.DisableBridge {
		// Initialize default driver "bridge"
		if err := initBridgeDriver(controller, config); err != nil {
			return nil, err
		}
	}

	return controller, nil
}

func driverOptions(config *Config) []nwconfig.Option {
	bridgeConfig := options.Generic{
		"EnableIPForwarding":  config.bridgeConfig.EnableIPForward,
		"EnableIPTables":      config.bridgeConfig.EnableIPTables,
		"EnableUserlandProxy": config.bridgeConfig.EnableUserlandProxy}
	bridgeOption := options.Generic{netlabel.GenericData: bridgeConfig}

	dOptions := []nwconfig.Option{}
	dOptions = append(dOptions, nwconfig.OptionDriverConfig("bridge", bridgeOption))
	return dOptions
}

func initBridgeDriver(controller libnetwork.NetworkController, config *Config) error {
	if n, err := controller.NetworkByName("bridge"); err == nil {
		if err = n.Delete(); err != nil {
			return fmt.Errorf("could not delete the default bridge network: %v", err)
		}
	}

	bridgeName := bridge.DefaultBridgeName
	if config.bridgeConfig.Iface != "" {
		bridgeName = config.bridgeConfig.Iface
	}
	netOption := map[string]string{
		bridge.BridgeName:         bridgeName,
		bridge.DefaultBridge:      strconv.FormatBool(true),
		netlabel.DriverMTU:        strconv.Itoa(config.Mtu),
		bridge.EnableIPMasquerade: strconv.FormatBool(config.bridgeConfig.EnableIPMasq),
		bridge.EnableICC:          strconv.FormatBool(config.bridgeConfig.InterContainerCommunication),
	}

	// --ip processing
	if config.bridgeConfig.DefaultIP != nil {
		netOption[bridge.DefaultBindingIP] = config.bridgeConfig.DefaultIP.String()
	}

	var (
		ipamV4Conf *libnetwork.IpamConf
		ipamV6Conf *libnetwork.IpamConf
	)

	ipamV4Conf = &libnetwork.IpamConf{AuxAddresses: make(map[string]string)}

	nw, nw6List, err := ipamutils.ElectInterfaceAddresses(bridgeName)
	if err == nil {
		ipamV4Conf.PreferredPool = types.GetIPNetCanonical(nw).String()
		hip, _ := types.GetHostPartIP(nw.IP, nw.Mask)
		if hip.IsGlobalUnicast() {
			ipamV4Conf.Gateway = nw.IP.String()
		}
	}

	if config.bridgeConfig.IP != "" {
		ipamV4Conf.PreferredPool = config.bridgeConfig.IP
		ip, _, err := net.ParseCIDR(config.bridgeConfig.IP)
		if err != nil {
			return err
		}
		ipamV4Conf.Gateway = ip.String()
	} else if bridgeName == bridge.DefaultBridgeName && ipamV4Conf.PreferredPool != "" {
		logrus.Infof("Default bridge (%s) is assigned with an IP address %s. Daemon option --bip can be used to set a preferred IP address", bridgeName, ipamV4Conf.PreferredPool)
	}

	if config.bridgeConfig.FixedCIDR != "" {
		_, fCIDR, err := net.ParseCIDR(config.bridgeConfig.FixedCIDR)
		if err != nil {
			return err
		}

		ipamV4Conf.SubPool = fCIDR.String()
	}

	if config.bridgeConfig.DefaultGatewayIPv4 != nil {
		ipamV4Conf.AuxAddresses["DefaultGatewayIPv4"] = config.bridgeConfig.DefaultGatewayIPv4.String()
	}

	var deferIPv6Alloc bool
	if config.bridgeConfig.FixedCIDRv6 != "" {
		_, fCIDRv6, err := net.ParseCIDR(config.bridgeConfig.FixedCIDRv6)
		if err != nil {
			return err
		}

		// In case user has specified the daemon flag --fixed-cidr-v6 and the passed network has
		// at least 48 host bits, we need to guarantee the current behavior where the containers'
		// IPv6 addresses will be constructed based on the containers' interface MAC address.
		// We do so by telling libnetwork to defer the IPv6 address allocation for the endpoints
		// on this network until after the driver has created the endpoint and returned the
		// constructed address. Libnetwork will then reserve this address with the ipam driver.
		ones, _ := fCIDRv6.Mask.Size()
		deferIPv6Alloc = ones <= 80

		if ipamV6Conf == nil {
			ipamV6Conf = &libnetwork.IpamConf{AuxAddresses: make(map[string]string)}
		}
		ipamV6Conf.PreferredPool = fCIDRv6.String()

		// In case the --fixed-cidr-v6 is specified and the current docker0 bridge IPv6
		// address belongs to the same network, we need to inform libnetwork about it, so
		// that it can be reserved with IPAM and it will not be given away to somebody else
		for _, nw6 := range nw6List {
			if fCIDRv6.Contains(nw6.IP) {
				ipamV6Conf.Gateway = nw6.IP.String()
				break
			}
		}
	}

	if config.bridgeConfig.DefaultGatewayIPv6 != nil {
		if ipamV6Conf == nil {
			ipamV6Conf = &libnetwork.IpamConf{AuxAddresses: make(map[string]string)}
		}
		ipamV6Conf.AuxAddresses["DefaultGatewayIPv6"] = config.bridgeConfig.DefaultGatewayIPv6.String()
	}

	v4Conf := []*libnetwork.IpamConf{ipamV4Conf}
	v6Conf := []*libnetwork.IpamConf{}
	if ipamV6Conf != nil {
		v6Conf = append(v6Conf, ipamV6Conf)
	}
	// Initialize default network on "bridge" with the same name
	_, err = controller.NewNetwork("bridge", "bridge",
		libnetwork.NetworkOptionEnableIPv6(config.bridgeConfig.EnableIPv6),
		libnetwork.NetworkOptionDriverOpts(netOption),
		libnetwork.NetworkOptionIpam("default", "", v4Conf, v6Conf, nil),
		libnetwork.NetworkOptionDeferIPv6Alloc(deferIPv6Alloc))
	if err != nil {
		return fmt.Errorf("Error creating default \"bridge\" network: %v", err)
	}
	return nil
}

// setupInitLayer populates a directory with mountpoints suitable
// for bind-mounting things into the container.
//
// This extra layer is used by all containers as the top-most ro layer. It protects
// the container from unwanted side-effects on the rw layer.
func setupInitLayer(initLayer string, rootUID, rootGID int) error {
	for pth, typ := range map[string]string{
		"/dev/pts":         "dir",
		"/dev/shm":         "dir",
		"/proc":            "dir",
		"/sys":             "dir",
		"/.dockerenv":      "file",
		"/etc/resolv.conf": "file",
		"/etc/hosts":       "file",
		"/etc/hostname":    "file",
		"/dev/console":     "file",
		"/etc/mtab":        "/proc/mounts",
	} {
		parts := strings.Split(pth, "/")
		prev := "/"
		for _, p := range parts[1:] {
			prev = filepath.Join(prev, p)
			syscall.Unlink(filepath.Join(initLayer, prev))
		}

		if _, err := os.Stat(filepath.Join(initLayer, pth)); err != nil {
			if os.IsNotExist(err) {
				if err := idtools.MkdirAllNewAs(filepath.Join(initLayer, filepath.Dir(pth)), 0755, rootUID, rootGID); err != nil {
					return err
				}
				switch typ {
				case "dir":
					if err := idtools.MkdirAllNewAs(filepath.Join(initLayer, pth), 0755, rootUID, rootGID); err != nil {
						return err
					}
				case "file":
					f, err := os.OpenFile(filepath.Join(initLayer, pth), os.O_CREATE, 0755)
					if err != nil {
						return err
					}
					f.Chown(rootUID, rootGID)
					f.Close()
				default:
					if err := os.Symlink(typ, filepath.Join(initLayer, pth)); err != nil {
						return err
					}
				}
			} else {
				return err
			}
		}
	}

	// Layer is ready to use, if it wasn't before.
	return nil
}

// Parse the remapped root (user namespace) option, which can be one of:
//   username            - valid username from /etc/passwd
//   username:groupname  - valid username; valid groupname from /etc/group
//   uid                 - 32-bit unsigned int valid Linux UID value
//   uid:gid             - uid value; 32-bit unsigned int Linux GID value
//
//  If no groupname is specified, and a username is specified, an attempt
//  will be made to lookup a gid for that username as a groupname
//
//  If names are used, they are verified to exist in passwd/group
func parseRemappedRoot(usergrp string) (string, string, error) {

	var (
		userID, groupID     int
		username, groupname string
	)

	idparts := strings.Split(usergrp, ":")
	if len(idparts) > 2 {
		return "", "", fmt.Errorf("Invalid user/group specification in --userns-remap: %q", usergrp)
	}

	if uid, err := strconv.ParseInt(idparts[0], 10, 32); err == nil {
		// must be a uid; take it as valid
		userID = int(uid)
		luser, err := user.LookupUid(userID)
		if err != nil {
			return "", "", fmt.Errorf("Uid %d has no entry in /etc/passwd: %v", userID, err)
		}
		username = luser.Name
		if len(idparts) == 1 {
			// if the uid was numeric and no gid was specified, take the uid as the gid
			groupID = userID
			lgrp, err := user.LookupGid(groupID)
			if err != nil {
				return "", "", fmt.Errorf("Gid %d has no entry in /etc/group: %v", groupID, err)
			}
			groupname = lgrp.Name
		}
	} else {
		lookupName := idparts[0]
		// special case: if the user specified "default", they want Docker to create or
		// use (after creation) the "dockremap" user/group for root remapping
		if lookupName == defaultIDSpecifier {
			lookupName = defaultRemappedID
		}
		luser, err := user.LookupUser(lookupName)
		if err != nil && idparts[0] != defaultIDSpecifier {
			// error if the name requested isn't the special "dockremap" ID
			return "", "", fmt.Errorf("Error during uid lookup for %q: %v", lookupName, err)
		} else if err != nil {
			// special case-- if the username == "default", then we have been asked
			// to create a new entry pair in /etc/{passwd,group} for which the /etc/sub{uid,gid}
			// ranges will be used for the user and group mappings in user namespaced containers
			_, _, err := idtools.AddNamespaceRangesUser(defaultRemappedID)
			if err == nil {
				return defaultRemappedID, defaultRemappedID, nil
			}
			return "", "", fmt.Errorf("Error during %q user creation: %v", defaultRemappedID, err)
		}
		userID = luser.Uid
		username = luser.Name
		if len(idparts) == 1 {
			// we only have a string username, and no group specified; look up gid from username as group
			group, err := user.LookupGroup(lookupName)
			if err != nil {
				return "", "", fmt.Errorf("Error during gid lookup for %q: %v", lookupName, err)
			}
			groupID = group.Gid
			groupname = group.Name
		}
	}

	if len(idparts) == 2 {
		// groupname or gid is separately specified and must be resolved
		// to a unsigned 32-bit gid
		if gid, err := strconv.ParseInt(idparts[1], 10, 32); err == nil {
			// must be a gid, take it as valid
			groupID = int(gid)
			lgrp, err := user.LookupGid(groupID)
			if err != nil {
				return "", "", fmt.Errorf("Gid %d has no entry in /etc/passwd: %v", groupID, err)
			}
			groupname = lgrp.Name
		} else {
			// not a number; attempt a lookup
			group, err := user.LookupGroup(idparts[1])
			if err != nil {
				return "", "", fmt.Errorf("Error during gid lookup for %q: %v", idparts[1], err)
			}
			groupID = group.Gid
			groupname = idparts[1]
		}
	}
	return username, groupname, nil
}

func setupRemappedRoot(config *Config) ([]idtools.IDMap, []idtools.IDMap, error) {
	if runtime.GOOS != "linux" && config.RemappedRoot != "" {
		return nil, nil, fmt.Errorf("User namespaces are only supported on Linux")
	}

	// if the daemon was started with remapped root option, parse
	// the config option to the int uid,gid values
	var (
		uidMaps, gidMaps []idtools.IDMap
	)
	if config.RemappedRoot != "" {
		username, groupname, err := parseRemappedRoot(config.RemappedRoot)
		if err != nil {
			return nil, nil, err
		}
		if username == "root" {
			// Cannot setup user namespaces with a 1-to-1 mapping; "--root=0:0" is a no-op
			// effectively
			logrus.Warnf("User namespaces: root cannot be remapped with itself; user namespaces are OFF")
			return uidMaps, gidMaps, nil
		}
		logrus.Infof("User namespaces: ID ranges will be mapped to subuid/subgid ranges of: %s:%s", username, groupname)
		// update remapped root setting now that we have resolved them to actual names
		config.RemappedRoot = fmt.Sprintf("%s:%s", username, groupname)

		uidMaps, gidMaps, err = idtools.CreateIDMappings(username, groupname)
		if err != nil {
			return nil, nil, fmt.Errorf("Can't create ID mappings: %v", err)
		}
	}
	return uidMaps, gidMaps, nil
}

func setupDaemonRoot(config *Config, rootDir string, rootUID, rootGID int) error {
	config.Root = rootDir
	// the docker root metadata directory needs to have execute permissions for all users (o+x)
	// so that syscalls executing as non-root, operating on subdirectories of the graph root
	// (e.g. mounted layers of a container) can traverse this path.
	// The user namespace support will create subdirectories for the remapped root host uid:gid
	// pair owned by that same uid:gid pair for proper write access to those needed metadata and
	// layer content subtrees.
	if _, err := os.Stat(rootDir); err == nil {
		// root current exists; verify the access bits are correct by setting them
		if err = os.Chmod(rootDir, 0701); err != nil {
			return err
		}
	} else if os.IsNotExist(err) {
		// no root exists yet, create it 0701 with root:root ownership
		if err := os.MkdirAll(rootDir, 0701); err != nil {
			return err
		}
	}

	// if user namespaces are enabled we will create a subtree underneath the specified root
	// with any/all specified remapped root uid/gid options on the daemon creating
	// a new subdirectory with ownership set to the remapped uid/gid (so as to allow
	// `chdir()` to work for containers namespaced to that uid/gid)
	if config.RemappedRoot != "" {
		config.Root = filepath.Join(rootDir, fmt.Sprintf("%d.%d", rootUID, rootGID))
		logrus.Debugf("Creating user namespaced daemon root: %s", config.Root)
		// Create the root directory if it doesn't exists
		if err := idtools.MkdirAllAs(config.Root, 0700, rootUID, rootGID); err != nil {
			return fmt.Errorf("Cannot create daemon root: %s: %v", config.Root, err)
		}
	}
	return nil
}

// registerLinks writes the links to a file.
func (daemon *Daemon) registerLinks(container *container.Container, hostConfig *containertypes.HostConfig) error {
	if hostConfig == nil || hostConfig.NetworkMode.IsUserDefined() {
		return nil
	}

	for _, l := range hostConfig.Links {
		name, alias, err := runconfigopts.ParseLink(l)
		if err != nil {
			return err
		}
		child, err := daemon.GetContainer(name)
		if err != nil {
			//An error from daemon.GetContainer() means this name could not be found
			return fmt.Errorf("Could not get container for %s", name)
		}
		for child.HostConfig.NetworkMode.IsContainer() {
			parts := strings.SplitN(string(child.HostConfig.NetworkMode), ":", 2)
			child, err = daemon.GetContainer(parts[1])
			if err != nil {
				return fmt.Errorf("Could not get container for %s", parts[1])
			}
		}
		if child.HostConfig.NetworkMode.IsHost() {
			return runconfig.ErrConflictHostNetworkAndLinks
		}
		if err := daemon.registerLink(container, child, alias); err != nil {
			return err
		}
	}

	// After we load all the links into the daemon
	// set them to nil on the hostconfig
	return container.WriteHostConfig()
}

// conditionalMountOnStart is a platform specific helper function during the
// container start to call mount.
func (daemon *Daemon) conditionalMountOnStart(container *container.Container) error {
	return daemon.Mount(container)
}

// conditionalUnmountOnCleanup is a platform specific helper function called
// during the cleanup of a container to unmount.
func (daemon *Daemon) conditionalUnmountOnCleanup(container *container.Container) {
	daemon.Unmount(container)
}

func restoreCustomImage(is image.Store, ls layer.Store, rs reference.Store) error {
	// Unix has no custom images to register
	return nil
}
