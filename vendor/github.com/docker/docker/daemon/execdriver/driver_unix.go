// +build !windows

package execdriver

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/daemon/execdriver/native/template"
	"github.com/docker/docker/pkg/idtools"
	"github.com/docker/docker/pkg/mount"
	"github.com/docker/go-units"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/cgroups/fs"
	"github.com/opencontainers/runc/libcontainer/configs"
	blkiodev "github.com/opencontainers/runc/libcontainer/configs"
)

// Mount contains information for a mount operation.
type Mount struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Writable    bool   `json:"writable"`
	Data        string `json:"data"`
	Propagation string `json:"mountpropagation"`
}

// Resources contains all resource configs for a driver.
// Currently these are all for cgroup configs.
type Resources struct {
	CommonResources

	// Fields below here are platform specific

	BlkioWeightDevice            []*blkiodev.WeightDevice   `json:"blkio_weight_device"`
	BlkioThrottleReadBpsDevice   []*blkiodev.ThrottleDevice `json:"blkio_throttle_read_bps_device"`
	BlkioThrottleWriteBpsDevice  []*blkiodev.ThrottleDevice `json:"blkio_throttle_write_bps_device"`
	BlkioThrottleReadIOpsDevice  []*blkiodev.ThrottleDevice `json:"blkio_throttle_read_iops_device"`
	BlkioThrottleWriteIOpsDevice []*blkiodev.ThrottleDevice `json:"blkio_throttle_write_iops_device"`
	MemorySwap                   int64                      `json:"memory_swap"`
	KernelMemory                 int64                      `json:"kernel_memory"`
	CPUQuota                     int64                      `json:"cpu_quota"`
	CpusetCpus                   string                     `json:"cpuset_cpus"`
	CpusetMems                   string                     `json:"cpuset_mems"`
	CPUPeriod                    int64                      `json:"cpu_period"`
	Rlimits                      []*units.Rlimit            `json:"rlimits"`
	OomKillDisable               bool                       `json:"oom_kill_disable"`
	MemorySwappiness             int64                      `json:"memory_swappiness"`
}

// ProcessConfig is the platform specific structure that describes a process
// that will be run inside a container.
type ProcessConfig struct {
	CommonProcessConfig

	// Fields below here are platform specific
	Privileged bool   `json:"privileged"`
	User       string `json:"user"`
	Console    string `json:"-"` // dev/console path
}

// Ipc settings of the container
// It is for IPC namespace setting. Usually different containers
// have their own IPC namespace, however this specifies to use
// an existing IPC namespace.
// You can join the host's or a container's IPC namespace.
type Ipc struct {
	ContainerID string `json:"container_id"` // id of the container to join ipc.
	HostIpc     bool   `json:"host_ipc"`
}

// Pid settings of the container
// It is for PID namespace setting. Usually different containers
// have their own PID namespace, however this specifies to use
// an existing PID namespace.
// Joining the host's PID namespace is currently the only supported
// option.
type Pid struct {
	HostPid bool `json:"host_pid"`
}

// UTS settings of the container
// It is for UTS namespace setting. Usually different containers
// have their own UTS namespace, however this specifies to use
// an existing UTS namespace.
// Joining the host's UTS namespace is currently the only supported
// option.
type UTS struct {
	HostUTS bool `json:"host_uts"`
}

// Network settings of the container
type Network struct {
	Mtu            int    `json:"mtu"`
	ContainerID    string `json:"container_id"` // id of the container to join network.
	NamespacePath  string `json:"namespace_path"`
	HostNetworking bool   `json:"host_networking"`
}

// Command wraps an os/exec.Cmd to add more metadata
type Command struct {
	CommonCommand

	// Fields below here are platform specific

	AllowedDevices     []*configs.Device `json:"allowed_devices"`
	AppArmorProfile    string            `json:"apparmor_profile"`
	AutoCreatedDevices []*configs.Device `json:"autocreated_devices"`
	CapAdd             []string          `json:"cap_add"`
	CapDrop            []string          `json:"cap_drop"`
	CgroupParent       string            `json:"cgroup_parent"` // The parent cgroup for this command.
	GIDMapping         []idtools.IDMap   `json:"gidmapping"`
	GroupAdd           []string          `json:"group_add"`
	Ipc                *Ipc              `json:"ipc"`
	OomScoreAdj        int               `json:"oom_score_adj"`
	Pid                *Pid              `json:"pid"`
	ReadonlyRootfs     bool              `json:"readonly_rootfs"`
	RemappedRoot       *User             `json:"remap_root"`
	SeccompProfile     string            `json:"seccomp_profile"`
	UIDMapping         []idtools.IDMap   `json:"uidmapping"`
	UTS                *UTS              `json:"uts"`
}

// SetRootPropagation sets the root mount propagation mode.
func SetRootPropagation(config *configs.Config, propagation int) {
	config.RootPropagation = propagation
}

// InitContainer is the initialization of a container config.
// It returns the initial configs for a container. It's mostly
// defined by the default template.
func InitContainer(c *Command) *configs.Config {
	container := template.New()

	container.Hostname = getEnv("HOSTNAME", c.ProcessConfig.Env)
	container.Cgroups.Name = c.ID
	container.Cgroups.Resources.AllowedDevices = c.AllowedDevices
	container.Devices = filterDevices(c.AutoCreatedDevices, (c.RemappedRoot.UID != 0))
	container.Rootfs = c.Rootfs
	container.Readonlyfs = c.ReadonlyRootfs
	// This can be overridden later by driver during mount setup based
	// on volume options
	SetRootPropagation(container, mount.RPRIVATE)
	container.Cgroups.Parent = c.CgroupParent

	// check to see if we are running in ramdisk to disable pivot root
	container.NoPivotRoot = os.Getenv("DOCKER_RAMDISK") != ""

	return container
}

func filterDevices(devices []*configs.Device, userNamespacesEnabled bool) []*configs.Device {
	if !userNamespacesEnabled {
		return devices
	}

	filtered := []*configs.Device{}
	// if we have user namespaces enabled, these devices will not be created
	// because of the mknod limitation in the kernel for an unprivileged process.
	// Rather, they will be bind-mounted, which will only work if they exist;
	// check for existence and remove non-existent entries from the list
	for _, device := range devices {
		if _, err := os.Stat(device.Path); err == nil {
			filtered = append(filtered, device)
		}
	}
	return filtered
}

func getEnv(key string, env []string) string {
	for _, pair := range env {
		parts := strings.SplitN(pair, "=", 2)
		if parts[0] == key {
			return parts[1]
		}
	}
	return ""
}

// SetupCgroups setups cgroup resources for a container.
func SetupCgroups(container *configs.Config, c *Command) error {
	if c.Resources != nil {
		container.Cgroups.Resources.CpuShares = c.Resources.CPUShares
		container.Cgroups.Resources.Memory = c.Resources.Memory
		container.Cgroups.Resources.MemoryReservation = c.Resources.MemoryReservation
		container.Cgroups.Resources.MemorySwap = c.Resources.MemorySwap
		container.Cgroups.Resources.KernelMemory = c.Resources.KernelMemory
		container.Cgroups.Resources.CpusetCpus = c.Resources.CpusetCpus
		container.Cgroups.Resources.CpusetMems = c.Resources.CpusetMems
		container.Cgroups.Resources.CpuPeriod = c.Resources.CPUPeriod
		container.Cgroups.Resources.CpuQuota = c.Resources.CPUQuota
		container.Cgroups.Resources.BlkioWeight = c.Resources.BlkioWeight
		container.Cgroups.Resources.BlkioWeightDevice = c.Resources.BlkioWeightDevice
		container.Cgroups.Resources.BlkioThrottleReadBpsDevice = c.Resources.BlkioThrottleReadBpsDevice
		container.Cgroups.Resources.BlkioThrottleWriteBpsDevice = c.Resources.BlkioThrottleWriteBpsDevice
		container.Cgroups.Resources.BlkioThrottleReadIOPSDevice = c.Resources.BlkioThrottleReadIOpsDevice
		container.Cgroups.Resources.BlkioThrottleWriteIOPSDevice = c.Resources.BlkioThrottleWriteIOpsDevice
		container.Cgroups.Resources.OomKillDisable = c.Resources.OomKillDisable
		container.Cgroups.Resources.MemorySwappiness = c.Resources.MemorySwappiness
	}

	return nil
}

// Returns the network statistics for the network interfaces represented by the NetworkRuntimeInfo.
func getNetworkInterfaceStats(interfaceName string) (*libcontainer.NetworkInterface, error) {
	out := &libcontainer.NetworkInterface{Name: interfaceName}
	// This can happen if the network runtime information is missing - possible if the
	// container was created by an old version of libcontainer.
	if interfaceName == "" {
		return out, nil
	}
	type netStatsPair struct {
		// Where to write the output.
		Out *uint64
		// The network stats file to read.
		File string
	}
	// Ingress for host veth is from the container. Hence tx_bytes stat on the host veth is actually number of bytes received by the container.
	netStats := []netStatsPair{
		{Out: &out.RxBytes, File: "tx_bytes"},
		{Out: &out.RxPackets, File: "tx_packets"},
		{Out: &out.RxErrors, File: "tx_errors"},
		{Out: &out.RxDropped, File: "tx_dropped"},

		{Out: &out.TxBytes, File: "rx_bytes"},
		{Out: &out.TxPackets, File: "rx_packets"},
		{Out: &out.TxErrors, File: "rx_errors"},
		{Out: &out.TxDropped, File: "rx_dropped"},
	}
	for _, netStat := range netStats {
		data, err := readSysfsNetworkStats(interfaceName, netStat.File)
		if err != nil {
			return nil, err
		}
		*(netStat.Out) = data
	}
	return out, nil
}

// Reads the specified statistics available under /sys/class/net/<EthInterface>/statistics
func readSysfsNetworkStats(ethInterface, statsFile string) (uint64, error) {
	data, err := ioutil.ReadFile(filepath.Join("/sys/class/net", ethInterface, "statistics", statsFile))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

// Stats collects all the resource usage information from a container.
func Stats(containerDir string, containerMemoryLimit int64, machineMemory int64) (*ResourceStats, error) {
	f, err := os.Open(filepath.Join(containerDir, "state.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	type network struct {
		Type              string
		HostInterfaceName string
	}

	state := struct {
		CgroupPaths map[string]string `json:"cgroup_paths"`
		Networks    []network
	}{}

	if err := json.NewDecoder(f).Decode(&state); err != nil {
		return nil, err
	}
	now := time.Now()

	mgr := fs.Manager{Paths: state.CgroupPaths}
	cstats, err := mgr.GetStats()
	if err != nil {
		return nil, err
	}
	stats := &libcontainer.Stats{CgroupStats: cstats}
	// if the container does not have any memory limit specified set the
	// limit to the machines memory
	memoryLimit := containerMemoryLimit
	if memoryLimit == 0 {
		memoryLimit = machineMemory
	}
	for _, iface := range state.Networks {
		switch iface.Type {
		case "veth":
			istats, err := getNetworkInterfaceStats(iface.HostInterfaceName)
			if err != nil {
				return nil, err
			}
			stats.Interfaces = append(stats.Interfaces, istats)
		}
	}
	return &ResourceStats{
		Stats:       stats,
		Read:        now,
		MemoryLimit: memoryLimit,
	}, nil
}

// User contains the uid and gid representing a Unix user
type User struct {
	UID int `json:"root_uid"`
	GID int `json:"root_gid"`
}

// ExitStatus provides exit reasons for a container.
type ExitStatus struct {
	// The exit code with which the container exited.
	ExitCode int

	// Whether the container encountered an OOM.
	OOMKilled bool
}
