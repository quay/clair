// +build linux

// Package specconv implements conversion of specifications to libcontainer
// configurations
package specconv

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/seccomp"
	libcontainerUtils "github.com/opencontainers/runc/libcontainer/utils"
	"github.com/opencontainers/runtime-spec/specs-go"
)

const wildcard = -1

var namespaceMapping = map[specs.NamespaceType]configs.NamespaceType{
	specs.PIDNamespace:     configs.NEWPID,
	specs.NetworkNamespace: configs.NEWNET,
	specs.MountNamespace:   configs.NEWNS,
	specs.UserNamespace:    configs.NEWUSER,
	specs.IPCNamespace:     configs.NEWIPC,
	specs.UTSNamespace:     configs.NEWUTS,
}

var mountPropagationMapping = map[string]int{
	"rprivate": syscall.MS_PRIVATE | syscall.MS_REC,
	"private":  syscall.MS_PRIVATE,
	"rslave":   syscall.MS_SLAVE | syscall.MS_REC,
	"slave":    syscall.MS_SLAVE,
	"rshared":  syscall.MS_SHARED | syscall.MS_REC,
	"shared":   syscall.MS_SHARED,
	"":         syscall.MS_PRIVATE | syscall.MS_REC,
}

var allowedDevices = []*configs.Device{
	// allow mknod for any device
	{
		Type:        'c',
		Major:       wildcard,
		Minor:       wildcard,
		Permissions: "m",
		Allow:       true,
	},
	{
		Type:        'b',
		Major:       wildcard,
		Minor:       wildcard,
		Permissions: "m",
		Allow:       true,
	},
	{
		Type:        'c',
		Path:        "/dev/null",
		Major:       1,
		Minor:       3,
		Permissions: "rwm",
		Allow:       true,
	},
	{
		Type:        'c',
		Path:        "/dev/random",
		Major:       1,
		Minor:       8,
		Permissions: "rwm",
		Allow:       true,
	},
	{
		Type:        'c',
		Path:        "/dev/full",
		Major:       1,
		Minor:       7,
		Permissions: "rwm",
		Allow:       true,
	},
	{
		Type:        'c',
		Path:        "/dev/tty",
		Major:       5,
		Minor:       0,
		Permissions: "rwm",
		Allow:       true,
	},
	{
		Type:        'c',
		Path:        "/dev/zero",
		Major:       1,
		Minor:       5,
		Permissions: "rwm",
		Allow:       true,
	},
	{
		Type:        'c',
		Path:        "/dev/urandom",
		Major:       1,
		Minor:       9,
		Permissions: "rwm",
		Allow:       true,
	},
	{
		Path:        "/dev/console",
		Type:        'c',
		Major:       5,
		Minor:       1,
		Permissions: "rwm",
		Allow:       true,
	},
	// /dev/pts/ - pts namespaces are "coming soon"
	{
		Path:        "",
		Type:        'c',
		Major:       136,
		Minor:       wildcard,
		Permissions: "rwm",
		Allow:       true,
	},
	{
		Path:        "",
		Type:        'c',
		Major:       5,
		Minor:       2,
		Permissions: "rwm",
		Allow:       true,
	},
	// tuntap
	{
		Path:        "",
		Type:        'c',
		Major:       10,
		Minor:       200,
		Permissions: "rwm",
		Allow:       true,
	},
}

type CreateOpts struct {
	CgroupName       string
	UseSystemdCgroup bool
	NoPivotRoot      bool
	NoNewKeyring     bool
	Spec             *specs.Spec
}

// CreateLibcontainerConfig creates a new libcontainer configuration from a
// given specification and a cgroup name
func CreateLibcontainerConfig(opts *CreateOpts) (*configs.Config, error) {
	// runc's cwd will always be the bundle path
	rcwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	cwd, err := filepath.Abs(rcwd)
	if err != nil {
		return nil, err
	}
	spec := opts.Spec
	rootfsPath := spec.Root.Path
	if !filepath.IsAbs(rootfsPath) {
		rootfsPath = filepath.Join(cwd, rootfsPath)
	}
	labels := []string{}
	for k, v := range spec.Annotations {
		labels = append(labels, fmt.Sprintf("%s=%s", k, v))
	}
	config := &configs.Config{
		Rootfs:       rootfsPath,
		NoPivotRoot:  opts.NoPivotRoot,
		Readonlyfs:   spec.Root.Readonly,
		Hostname:     spec.Hostname,
		Labels:       append(labels, fmt.Sprintf("bundle=%s", cwd)),
		NoNewKeyring: opts.NoNewKeyring,
	}

	exists := false
	if config.RootPropagation, exists = mountPropagationMapping[spec.Linux.RootfsPropagation]; !exists {
		return nil, fmt.Errorf("rootfsPropagation=%v is not supported", spec.Linux.RootfsPropagation)
	}

	for _, ns := range spec.Linux.Namespaces {
		t, exists := namespaceMapping[ns.Type]
		if !exists {
			return nil, fmt.Errorf("namespace %q does not exist", ns)
		}
		config.Namespaces.Add(t, ns.Path)
	}
	if config.Namespaces.Contains(configs.NEWNET) {
		config.Networks = []*configs.Network{
			{
				Type: "loopback",
			},
		}
	}
	for _, m := range spec.Mounts {
		config.Mounts = append(config.Mounts, createLibcontainerMount(cwd, m))
	}
	if err := createDevices(spec, config); err != nil {
		return nil, err
	}
	if err := setupUserNamespace(spec, config); err != nil {
		return nil, err
	}
	c, err := createCgroupConfig(opts.CgroupName, opts.UseSystemdCgroup, spec)
	if err != nil {
		return nil, err
	}
	config.Cgroups = c
	// set extra path masking for libcontainer for the various unsafe places in proc
	config.MaskPaths = spec.Linux.MaskedPaths
	config.ReadonlyPaths = spec.Linux.ReadonlyPaths
	if spec.Linux.Seccomp != nil {
		seccomp, err := setupSeccomp(spec.Linux.Seccomp)
		if err != nil {
			return nil, err
		}
		config.Seccomp = seccomp
	}
	if spec.Process.SelinuxLabel != "" {
		config.ProcessLabel = spec.Process.SelinuxLabel
	}
	config.Sysctl = spec.Linux.Sysctl
	if spec.Linux.Resources != nil && spec.Linux.Resources.OOMScoreAdj != nil {
		config.OomScoreAdj = *spec.Linux.Resources.OOMScoreAdj
	}
	createHooks(spec, config)
	config.MountLabel = spec.Linux.MountLabel
	config.Version = specs.Version
	return config, nil
}

func createLibcontainerMount(cwd string, m specs.Mount) *configs.Mount {
	flags, pgflags, data, ext := parseMountOptions(m.Options)
	source := m.Source
	if m.Type == "bind" {
		if !filepath.IsAbs(source) {
			source = filepath.Join(cwd, m.Source)
		}
	}
	return &configs.Mount{
		Device:           m.Type,
		Source:           source,
		Destination:      m.Destination,
		Data:             data,
		Flags:            flags,
		PropagationFlags: pgflags,
		Extensions:       ext,
	}
}

func createCgroupConfig(name string, useSystemdCgroup bool, spec *specs.Spec) (*configs.Cgroup, error) {
	var myCgroupPath string

	c := &configs.Cgroup{
		Resources: &configs.Resources{},
	}

	if spec.Linux != nil && spec.Linux.CgroupsPath != nil {
		myCgroupPath = libcontainerUtils.CleanPath(*spec.Linux.CgroupsPath)
		if useSystemdCgroup {
			myCgroupPath = *spec.Linux.CgroupsPath
		}
	}

	if useSystemdCgroup {
		if myCgroupPath == "" {
			c.Parent = "system.slice"
			c.ScopePrefix = "runc"
			c.Name = name
		} else {
			// Parse the path from expected "slice:prefix:name"
			// for e.g. "system.slice:docker:1234"
			parts := strings.Split(myCgroupPath, ":")
			if len(parts) != 3 {
				return nil, fmt.Errorf("expected cgroupsPath to be of format \"slice:prefix:name\" for systemd cgroups")
			}
			c.Parent = parts[0]
			c.ScopePrefix = parts[1]
			c.Name = parts[2]
		}
	} else {
		if myCgroupPath == "" {
			c.Name = name
		}
		c.Path = myCgroupPath
	}

	c.Resources.AllowedDevices = allowedDevices
	if spec.Linux == nil {
		return c, nil
	}
	r := spec.Linux.Resources
	if r == nil {
		return c, nil
	}
	for i, d := range spec.Linux.Resources.Devices {
		var (
			t     = "a"
			major = int64(-1)
			minor = int64(-1)
		)
		if d.Type != nil {
			t = *d.Type
		}
		if d.Major != nil {
			major = *d.Major
		}
		if d.Minor != nil {
			minor = *d.Minor
		}
		if d.Access == nil || *d.Access == "" {
			return nil, fmt.Errorf("device access at %d field cannot be empty", i)
		}
		dt, err := stringToDeviceRune(t)
		if err != nil {
			return nil, err
		}
		dd := &configs.Device{
			Type:        dt,
			Major:       major,
			Minor:       minor,
			Permissions: *d.Access,
			Allow:       d.Allow,
		}
		c.Resources.Devices = append(c.Resources.Devices, dd)
	}
	// append the default allowed devices to the end of the list
	c.Resources.Devices = append(c.Resources.Devices, allowedDevices...)
	if r.Memory != nil {
		if r.Memory.Limit != nil {
			c.Resources.Memory = int64(*r.Memory.Limit)
		}
		if r.Memory.Reservation != nil {
			c.Resources.MemoryReservation = int64(*r.Memory.Reservation)
		}
		if r.Memory.Swap != nil {
			c.Resources.MemorySwap = int64(*r.Memory.Swap)
		}
		if r.Memory.Kernel != nil {
			c.Resources.KernelMemory = int64(*r.Memory.Kernel)
		}
		if r.Memory.KernelTCP != nil {
			c.Resources.KernelMemoryTCP = int64(*r.Memory.KernelTCP)
		}
		if r.Memory.Swappiness != nil {
			swappiness := int64(*r.Memory.Swappiness)
			c.Resources.MemorySwappiness = &swappiness
		}
	}
	if r.CPU != nil {
		if r.CPU.Shares != nil {
			c.Resources.CpuShares = int64(*r.CPU.Shares)
		}
		if r.CPU.Quota != nil {
			c.Resources.CpuQuota = int64(*r.CPU.Quota)
		}
		if r.CPU.Period != nil {
			c.Resources.CpuPeriod = int64(*r.CPU.Period)
		}
		if r.CPU.RealtimeRuntime != nil {
			c.Resources.CpuRtRuntime = int64(*r.CPU.RealtimeRuntime)
		}
		if r.CPU.RealtimePeriod != nil {
			c.Resources.CpuRtPeriod = int64(*r.CPU.RealtimePeriod)
		}
		if r.CPU.Cpus != nil {
			c.Resources.CpusetCpus = *r.CPU.Cpus
		}
		if r.CPU.Mems != nil {
			c.Resources.CpusetMems = *r.CPU.Mems
		}
	}
	if r.Pids != nil && r.Pids.Limit != nil {
		c.Resources.PidsLimit = *r.Pids.Limit
	}
	if r.BlockIO != nil {
		if r.BlockIO.Weight != nil {
			c.Resources.BlkioWeight = *r.BlockIO.Weight
		}
		if r.BlockIO.LeafWeight != nil {
			c.Resources.BlkioLeafWeight = *r.BlockIO.LeafWeight
		}
		if r.BlockIO.WeightDevice != nil {
			for _, wd := range r.BlockIO.WeightDevice {
				var weight, leafWeight uint16
				if wd.Weight != nil {
					weight = *wd.Weight
				}
				if wd.LeafWeight != nil {
					leafWeight = *wd.LeafWeight
				}
				weightDevice := configs.NewWeightDevice(wd.Major, wd.Minor, weight, leafWeight)
				c.Resources.BlkioWeightDevice = append(c.Resources.BlkioWeightDevice, weightDevice)
			}
		}
		if r.BlockIO.ThrottleReadBpsDevice != nil {
			for _, td := range r.BlockIO.ThrottleReadBpsDevice {
				var rate uint64
				if td.Rate != nil {
					rate = *td.Rate
				}
				throttleDevice := configs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleReadBpsDevice = append(c.Resources.BlkioThrottleReadBpsDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleWriteBpsDevice != nil {
			for _, td := range r.BlockIO.ThrottleWriteBpsDevice {
				var rate uint64
				if td.Rate != nil {
					rate = *td.Rate
				}
				throttleDevice := configs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleWriteBpsDevice = append(c.Resources.BlkioThrottleWriteBpsDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleReadIOPSDevice != nil {
			for _, td := range r.BlockIO.ThrottleReadIOPSDevice {
				var rate uint64
				if td.Rate != nil {
					rate = *td.Rate
				}
				throttleDevice := configs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleReadIOPSDevice = append(c.Resources.BlkioThrottleReadIOPSDevice, throttleDevice)
			}
		}
		if r.BlockIO.ThrottleWriteIOPSDevice != nil {
			for _, td := range r.BlockIO.ThrottleWriteIOPSDevice {
				var rate uint64
				if td.Rate != nil {
					rate = *td.Rate
				}
				throttleDevice := configs.NewThrottleDevice(td.Major, td.Minor, rate)
				c.Resources.BlkioThrottleWriteIOPSDevice = append(c.Resources.BlkioThrottleWriteIOPSDevice, throttleDevice)
			}
		}
	}
	for _, l := range r.HugepageLimits {
		if l.Pagesize == nil || l.Limit == nil {
			return nil, fmt.Errorf("pagesize and limit can not be empty")
		}
		c.Resources.HugetlbLimit = append(c.Resources.HugetlbLimit, &configs.HugepageLimit{
			Pagesize: *l.Pagesize,
			Limit:    *l.Limit,
		})
	}
	if r.DisableOOMKiller != nil {
		c.Resources.OomKillDisable = *r.DisableOOMKiller
	}
	if r.Network != nil {
		if r.Network.ClassID != nil {
			c.Resources.NetClsClassid = *r.Network.ClassID
		}
		for _, m := range r.Network.Priorities {
			c.Resources.NetPrioIfpriomap = append(c.Resources.NetPrioIfpriomap, &configs.IfPrioMap{
				Interface: m.Name,
				Priority:  int64(m.Priority),
			})
		}
	}
	return c, nil
}

func stringToDeviceRune(s string) (rune, error) {
	switch s {
	case "a":
		return 'a', nil
	case "b":
		return 'b', nil
	case "c":
		return 'c', nil
	default:
		return 0, fmt.Errorf("invalid device type %q", s)
	}
}

func createDevices(spec *specs.Spec, config *configs.Config) error {
	// add whitelisted devices
	config.Devices = []*configs.Device{
		{
			Type:     'c',
			Path:     "/dev/null",
			Major:    1,
			Minor:    3,
			FileMode: 0666,
			Uid:      0,
			Gid:      0,
		},
		{
			Type:     'c',
			Path:     "/dev/random",
			Major:    1,
			Minor:    8,
			FileMode: 0666,
			Uid:      0,
			Gid:      0,
		},
		{
			Type:     'c',
			Path:     "/dev/full",
			Major:    1,
			Minor:    7,
			FileMode: 0666,
			Uid:      0,
			Gid:      0,
		},
		{
			Type:     'c',
			Path:     "/dev/tty",
			Major:    5,
			Minor:    0,
			FileMode: 0666,
			Uid:      0,
			Gid:      0,
		},
		{
			Type:     'c',
			Path:     "/dev/zero",
			Major:    1,
			Minor:    5,
			FileMode: 0666,
			Uid:      0,
			Gid:      0,
		},
		{
			Type:     'c',
			Path:     "/dev/urandom",
			Major:    1,
			Minor:    9,
			FileMode: 0666,
			Uid:      0,
			Gid:      0,
		},
	}
	// merge in additional devices from the spec
	for _, d := range spec.Linux.Devices {
		var uid, gid uint32
		var filemode os.FileMode = 0666

		if d.UID != nil {
			uid = *d.UID
		}
		if d.GID != nil {
			gid = *d.GID
		}
		dt, err := stringToDeviceRune(d.Type)
		if err != nil {
			return err
		}
		if d.FileMode != nil {
			filemode = *d.FileMode
		}
		device := &configs.Device{
			Type:     dt,
			Path:     d.Path,
			Major:    d.Major,
			Minor:    d.Minor,
			FileMode: filemode,
			Uid:      uid,
			Gid:      gid,
		}
		config.Devices = append(config.Devices, device)
	}
	return nil
}

func setupUserNamespace(spec *specs.Spec, config *configs.Config) error {
	if len(spec.Linux.UIDMappings) == 0 {
		return nil
	}
	create := func(m specs.IDMapping) configs.IDMap {
		return configs.IDMap{
			HostID:      int(m.HostID),
			ContainerID: int(m.ContainerID),
			Size:        int(m.Size),
		}
	}
	for _, m := range spec.Linux.UIDMappings {
		config.UidMappings = append(config.UidMappings, create(m))
	}
	for _, m := range spec.Linux.GIDMappings {
		config.GidMappings = append(config.GidMappings, create(m))
	}
	rootUID, err := config.HostUID()
	if err != nil {
		return err
	}
	rootGID, err := config.HostGID()
	if err != nil {
		return err
	}
	for _, node := range config.Devices {
		node.Uid = uint32(rootUID)
		node.Gid = uint32(rootGID)
	}
	return nil
}

// parseMountOptions parses the string and returns the flags, propagation
// flags and any mount data that it contains.
func parseMountOptions(options []string) (int, []int, string, int) {
	var (
		flag     int
		pgflag   []int
		data     []string
		extFlags int
	)
	flags := map[string]struct {
		clear bool
		flag  int
	}{
		"async":         {true, syscall.MS_SYNCHRONOUS},
		"atime":         {true, syscall.MS_NOATIME},
		"bind":          {false, syscall.MS_BIND},
		"defaults":      {false, 0},
		"dev":           {true, syscall.MS_NODEV},
		"diratime":      {true, syscall.MS_NODIRATIME},
		"dirsync":       {false, syscall.MS_DIRSYNC},
		"exec":          {true, syscall.MS_NOEXEC},
		"mand":          {false, syscall.MS_MANDLOCK},
		"noatime":       {false, syscall.MS_NOATIME},
		"nodev":         {false, syscall.MS_NODEV},
		"nodiratime":    {false, syscall.MS_NODIRATIME},
		"noexec":        {false, syscall.MS_NOEXEC},
		"nomand":        {true, syscall.MS_MANDLOCK},
		"norelatime":    {true, syscall.MS_RELATIME},
		"nostrictatime": {true, syscall.MS_STRICTATIME},
		"nosuid":        {false, syscall.MS_NOSUID},
		"rbind":         {false, syscall.MS_BIND | syscall.MS_REC},
		"relatime":      {false, syscall.MS_RELATIME},
		"remount":       {false, syscall.MS_REMOUNT},
		"ro":            {false, syscall.MS_RDONLY},
		"rw":            {true, syscall.MS_RDONLY},
		"strictatime":   {false, syscall.MS_STRICTATIME},
		"suid":          {true, syscall.MS_NOSUID},
		"sync":          {false, syscall.MS_SYNCHRONOUS},
	}
	propagationFlags := map[string]int{
		"private":     syscall.MS_PRIVATE,
		"shared":      syscall.MS_SHARED,
		"slave":       syscall.MS_SLAVE,
		"unbindable":  syscall.MS_UNBINDABLE,
		"rprivate":    syscall.MS_PRIVATE | syscall.MS_REC,
		"rshared":     syscall.MS_SHARED | syscall.MS_REC,
		"rslave":      syscall.MS_SLAVE | syscall.MS_REC,
		"runbindable": syscall.MS_UNBINDABLE | syscall.MS_REC,
	}
	extensionFlags := map[string]struct {
		clear bool
		flag  int
	}{
		"tmpcopyup": {false, configs.EXT_COPYUP},
	}
	for _, o := range options {
		// If the option does not exist in the flags table or the flag
		// is not supported on the platform,
		// then it is a data value for a specific fs type
		if f, exists := flags[o]; exists && f.flag != 0 {
			if f.clear {
				flag &= ^f.flag
			} else {
				flag |= f.flag
			}
		} else if f, exists := propagationFlags[o]; exists && f != 0 {
			pgflag = append(pgflag, f)
		} else if f, exists := extensionFlags[o]; exists && f.flag != 0 {
			if f.clear {
				extFlags &= ^f.flag
			} else {
				extFlags |= f.flag
			}
		} else {
			data = append(data, o)
		}
	}
	return flag, pgflag, strings.Join(data, ","), extFlags
}

func setupSeccomp(config *specs.Seccomp) (*configs.Seccomp, error) {
	if config == nil {
		return nil, nil
	}

	// No default action specified, no syscalls listed, assume seccomp disabled
	if config.DefaultAction == "" && len(config.Syscalls) == 0 {
		return nil, nil
	}

	newConfig := new(configs.Seccomp)
	newConfig.Syscalls = []*configs.Syscall{}

	if len(config.Architectures) > 0 {
		newConfig.Architectures = []string{}
		for _, arch := range config.Architectures {
			newArch, err := seccomp.ConvertStringToArch(string(arch))
			if err != nil {
				return nil, err
			}
			newConfig.Architectures = append(newConfig.Architectures, newArch)
		}
	}

	// Convert default action from string representation
	newDefaultAction, err := seccomp.ConvertStringToAction(string(config.DefaultAction))
	if err != nil {
		return nil, err
	}
	newConfig.DefaultAction = newDefaultAction

	// Loop through all syscall blocks and convert them to libcontainer format
	for _, call := range config.Syscalls {
		newAction, err := seccomp.ConvertStringToAction(string(call.Action))
		if err != nil {
			return nil, err
		}

		newCall := configs.Syscall{
			Name:   call.Name,
			Action: newAction,
			Args:   []*configs.Arg{},
		}

		// Loop through all the arguments of the syscall and convert them
		for _, arg := range call.Args {
			newOp, err := seccomp.ConvertStringToOperator(string(arg.Op))
			if err != nil {
				return nil, err
			}

			newArg := configs.Arg{
				Index:    arg.Index,
				Value:    arg.Value,
				ValueTwo: arg.ValueTwo,
				Op:       newOp,
			}

			newCall.Args = append(newCall.Args, &newArg)
		}

		newConfig.Syscalls = append(newConfig.Syscalls, &newCall)
	}

	return newConfig, nil
}

func createHooks(rspec *specs.Spec, config *configs.Config) {
	config.Hooks = &configs.Hooks{}
	for _, h := range rspec.Hooks.Prestart {
		cmd := createCommandHook(h)
		config.Hooks.Prestart = append(config.Hooks.Prestart, configs.NewCommandHook(cmd))
	}
	for _, h := range rspec.Hooks.Poststart {
		cmd := createCommandHook(h)
		config.Hooks.Poststart = append(config.Hooks.Poststart, configs.NewCommandHook(cmd))
	}
	for _, h := range rspec.Hooks.Poststop {
		cmd := createCommandHook(h)
		config.Hooks.Poststop = append(config.Hooks.Poststop, configs.NewCommandHook(cmd))
	}
}

func createCommandHook(h specs.Hook) configs.Command {
	cmd := configs.Command{
		Path: h.Path,
		Args: h.Args,
		Env:  h.Env,
	}
	if h.Timeout != nil {
		d := time.Duration(*h.Timeout) * time.Second
		cmd.Timeout = &d
	}
	return cmd
}
