package opts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"
	"strconv"
	"strings"

	"github.com/docker/docker/opts"
	flag "github.com/docker/docker/pkg/mflag"
	"github.com/docker/docker/pkg/mount"
	"github.com/docker/docker/pkg/signal"
	"github.com/docker/engine-api/types/container"
	networktypes "github.com/docker/engine-api/types/network"
	"github.com/docker/engine-api/types/strslice"
	"github.com/docker/go-connections/nat"
	"github.com/docker/go-units"
)

// Parse parses the specified args for the specified command and generates a Config,
// a HostConfig and returns them with the specified command.
// If the specified args are not valid, it will return an error.
func Parse(cmd *flag.FlagSet, args []string) (*container.Config, *container.HostConfig, *networktypes.NetworkingConfig, *flag.FlagSet, error) {
	var (
		// FIXME: use utils.ListOpts for attach and volumes?
		flAttach            = opts.NewListOpts(ValidateAttach)
		flVolumes           = opts.NewListOpts(nil)
		flTmpfs             = opts.NewListOpts(nil)
		flBlkioWeightDevice = NewWeightdeviceOpt(ValidateWeightDevice)
		flDeviceReadBps     = NewThrottledeviceOpt(ValidateThrottleBpsDevice)
		flDeviceWriteBps    = NewThrottledeviceOpt(ValidateThrottleBpsDevice)
		flLinks             = opts.NewListOpts(ValidateLink)
		flAliases           = opts.NewListOpts(nil)
		flDeviceReadIOps    = NewThrottledeviceOpt(ValidateThrottleIOpsDevice)
		flDeviceWriteIOps   = NewThrottledeviceOpt(ValidateThrottleIOpsDevice)
		flEnv               = opts.NewListOpts(ValidateEnv)
		flLabels            = opts.NewListOpts(ValidateEnv)
		flDevices           = opts.NewListOpts(ValidateDevice)

		flUlimits = NewUlimitOpt(nil)

		flPublish           = opts.NewListOpts(nil)
		flExpose            = opts.NewListOpts(nil)
		flDNS               = opts.NewListOpts(opts.ValidateIPAddress)
		flDNSSearch         = opts.NewListOpts(opts.ValidateDNSSearch)
		flDNSOptions        = opts.NewListOpts(nil)
		flExtraHosts        = opts.NewListOpts(ValidateExtraHost)
		flVolumesFrom       = opts.NewListOpts(nil)
		flEnvFile           = opts.NewListOpts(nil)
		flCapAdd            = opts.NewListOpts(nil)
		flCapDrop           = opts.NewListOpts(nil)
		flGroupAdd          = opts.NewListOpts(nil)
		flSecurityOpt       = opts.NewListOpts(nil)
		flLabelsFile        = opts.NewListOpts(nil)
		flLoggingOpts       = opts.NewListOpts(nil)
		flPrivileged        = cmd.Bool([]string{"-privileged"}, false, "Give extended privileges to this container")
		flPidMode           = cmd.String([]string{"-pid"}, "", "PID namespace to use")
		flUTSMode           = cmd.String([]string{"-uts"}, "", "UTS namespace to use")
		flPublishAll        = cmd.Bool([]string{"P", "-publish-all"}, false, "Publish all exposed ports to random ports")
		flStdin             = cmd.Bool([]string{"i", "-interactive"}, false, "Keep STDIN open even if not attached")
		flTty               = cmd.Bool([]string{"t", "-tty"}, false, "Allocate a pseudo-TTY")
		flOomKillDisable    = cmd.Bool([]string{"-oom-kill-disable"}, false, "Disable OOM Killer")
		flOomScoreAdj       = cmd.Int([]string{"-oom-score-adj"}, 0, "Tune host's OOM preferences (-1000 to 1000)")
		flContainerIDFile   = cmd.String([]string{"-cidfile"}, "", "Write the container ID to the file")
		flEntrypoint        = cmd.String([]string{"-entrypoint"}, "", "Overwrite the default ENTRYPOINT of the image")
		flHostname          = cmd.String([]string{"h", "-hostname"}, "", "Container host name")
		flMemoryString      = cmd.String([]string{"m", "-memory"}, "", "Memory limit")
		flMemoryReservation = cmd.String([]string{"-memory-reservation"}, "", "Memory soft limit")
		flMemorySwap        = cmd.String([]string{"-memory-swap"}, "", "Swap limit equal to memory plus swap: '-1' to enable unlimited swap")
		flKernelMemory      = cmd.String([]string{"-kernel-memory"}, "", "Kernel memory limit")
		flUser              = cmd.String([]string{"u", "-user"}, "", "Username or UID (format: <name|uid>[:<group|gid>])")
		flWorkingDir        = cmd.String([]string{"w", "-workdir"}, "", "Working directory inside the container")
		flCPUShares         = cmd.Int64([]string{"#c", "-cpu-shares"}, 0, "CPU shares (relative weight)")
		flCPUPeriod         = cmd.Int64([]string{"-cpu-period"}, 0, "Limit CPU CFS (Completely Fair Scheduler) period")
		flCPUQuota          = cmd.Int64([]string{"-cpu-quota"}, 0, "Limit CPU CFS (Completely Fair Scheduler) quota")
		flCpusetCpus        = cmd.String([]string{"-cpuset-cpus"}, "", "CPUs in which to allow execution (0-3, 0,1)")
		flCpusetMems        = cmd.String([]string{"-cpuset-mems"}, "", "MEMs in which to allow execution (0-3, 0,1)")
		flBlkioWeight       = cmd.Uint16([]string{"-blkio-weight"}, 0, "Block IO (relative weight), between 10 and 1000")
		flSwappiness        = cmd.Int64([]string{"-memory-swappiness"}, -1, "Tune container memory swappiness (0 to 100)")
		flNetMode           = cmd.String([]string{"-net"}, "default", "Connect a container to a network")
		flMacAddress        = cmd.String([]string{"-mac-address"}, "", "Container MAC address (e.g. 92:d0:c6:0a:29:33)")
		flIPv4Address       = cmd.String([]string{"-ip"}, "", "Container IPv4 address (e.g. 172.30.100.104)")
		flIPv6Address       = cmd.String([]string{"-ip6"}, "", "Container IPv6 address (e.g. 2001:db8::33)")
		flIpcMode           = cmd.String([]string{"-ipc"}, "", "IPC namespace to use")
		flRestartPolicy     = cmd.String([]string{"-restart"}, "no", "Restart policy to apply when a container exits")
		flReadonlyRootfs    = cmd.Bool([]string{"-read-only"}, false, "Mount the container's root filesystem as read only")
		flLoggingDriver     = cmd.String([]string{"-log-driver"}, "", "Logging driver for container")
		flCgroupParent      = cmd.String([]string{"-cgroup-parent"}, "", "Optional parent cgroup for the container")
		flVolumeDriver      = cmd.String([]string{"-volume-driver"}, "", "Optional volume driver for the container")
		flStopSignal        = cmd.String([]string{"-stop-signal"}, signal.DefaultStopSignal, fmt.Sprintf("Signal to stop a container, %v by default", signal.DefaultStopSignal))
		flIsolation         = cmd.String([]string{"-isolation"}, "", "Container isolation technology")
		flShmSize           = cmd.String([]string{"-shm-size"}, "", "Size of /dev/shm, default value is 64MB")
	)

	cmd.Var(&flAttach, []string{"a", "-attach"}, "Attach to STDIN, STDOUT or STDERR")
	cmd.Var(&flBlkioWeightDevice, []string{"-blkio-weight-device"}, "Block IO weight (relative device weight)")
	cmd.Var(&flDeviceReadBps, []string{"-device-read-bps"}, "Limit read rate (bytes per second) from a device")
	cmd.Var(&flDeviceWriteBps, []string{"-device-write-bps"}, "Limit write rate (bytes per second) to a device")
	cmd.Var(&flDeviceReadIOps, []string{"-device-read-iops"}, "Limit read rate (IO per second) from a device")
	cmd.Var(&flDeviceWriteIOps, []string{"-device-write-iops"}, "Limit write rate (IO per second) to a device")
	cmd.Var(&flVolumes, []string{"v", "-volume"}, "Bind mount a volume")
	cmd.Var(&flTmpfs, []string{"-tmpfs"}, "Mount a tmpfs directory")
	cmd.Var(&flLinks, []string{"-link"}, "Add link to another container")
	cmd.Var(&flAliases, []string{"-net-alias"}, "Add network-scoped alias for the container")
	cmd.Var(&flDevices, []string{"-device"}, "Add a host device to the container")
	cmd.Var(&flLabels, []string{"l", "-label"}, "Set meta data on a container")
	cmd.Var(&flLabelsFile, []string{"-label-file"}, "Read in a line delimited file of labels")
	cmd.Var(&flEnv, []string{"e", "-env"}, "Set environment variables")
	cmd.Var(&flEnvFile, []string{"-env-file"}, "Read in a file of environment variables")
	cmd.Var(&flPublish, []string{"p", "-publish"}, "Publish a container's port(s) to the host")
	cmd.Var(&flExpose, []string{"-expose"}, "Expose a port or a range of ports")
	cmd.Var(&flDNS, []string{"-dns"}, "Set custom DNS servers")
	cmd.Var(&flDNSSearch, []string{"-dns-search"}, "Set custom DNS search domains")
	cmd.Var(&flDNSOptions, []string{"-dns-opt"}, "Set DNS options")
	cmd.Var(&flExtraHosts, []string{"-add-host"}, "Add a custom host-to-IP mapping (host:ip)")
	cmd.Var(&flVolumesFrom, []string{"-volumes-from"}, "Mount volumes from the specified container(s)")
	cmd.Var(&flCapAdd, []string{"-cap-add"}, "Add Linux capabilities")
	cmd.Var(&flCapDrop, []string{"-cap-drop"}, "Drop Linux capabilities")
	cmd.Var(&flGroupAdd, []string{"-group-add"}, "Add additional groups to join")
	cmd.Var(&flSecurityOpt, []string{"-security-opt"}, "Security Options")
	cmd.Var(flUlimits, []string{"-ulimit"}, "Ulimit options")
	cmd.Var(&flLoggingOpts, []string{"-log-opt"}, "Log driver options")

	cmd.Require(flag.Min, 1)

	if err := cmd.ParseFlags(args, true); err != nil {
		return nil, nil, nil, cmd, err
	}

	var (
		attachStdin  = flAttach.Get("stdin")
		attachStdout = flAttach.Get("stdout")
		attachStderr = flAttach.Get("stderr")
	)

	// Validate the input mac address
	if *flMacAddress != "" {
		if _, err := ValidateMACAddress(*flMacAddress); err != nil {
			return nil, nil, nil, cmd, fmt.Errorf("%s is not a valid mac address", *flMacAddress)
		}
	}
	if *flStdin {
		attachStdin = true
	}
	// If -a is not set attach to the output stdio
	if flAttach.Len() == 0 {
		attachStdout = true
		attachStderr = true
	}

	var err error

	var flMemory int64
	if *flMemoryString != "" {
		flMemory, err = units.RAMInBytes(*flMemoryString)
		if err != nil {
			return nil, nil, nil, cmd, err
		}
	}

	var MemoryReservation int64
	if *flMemoryReservation != "" {
		MemoryReservation, err = units.RAMInBytes(*flMemoryReservation)
		if err != nil {
			return nil, nil, nil, cmd, err
		}
	}

	var memorySwap int64
	if *flMemorySwap != "" {
		if *flMemorySwap == "-1" {
			memorySwap = -1
		} else {
			memorySwap, err = units.RAMInBytes(*flMemorySwap)
			if err != nil {
				return nil, nil, nil, cmd, err
			}
		}
	}

	var KernelMemory int64
	if *flKernelMemory != "" {
		KernelMemory, err = units.RAMInBytes(*flKernelMemory)
		if err != nil {
			return nil, nil, nil, cmd, err
		}
	}

	swappiness := *flSwappiness
	if swappiness != -1 && (swappiness < 0 || swappiness > 100) {
		return nil, nil, nil, cmd, fmt.Errorf("invalid value: %d. Valid memory swappiness range is 0-100", swappiness)
	}

	var shmSize int64
	if *flShmSize != "" {
		shmSize, err = units.RAMInBytes(*flShmSize)
		if err != nil {
			return nil, nil, nil, cmd, err
		}
	}

	var binds []string
	// add any bind targets to the list of container volumes
	for bind := range flVolumes.GetMap() {
		if arr := volumeSplitN(bind, 2); len(arr) > 1 {
			// after creating the bind mount we want to delete it from the flVolumes values because
			// we do not want bind mounts being committed to image configs
			binds = append(binds, bind)
			flVolumes.Delete(bind)
		}
	}

	// Can't evaluate options passed into --tmpfs until we actually mount
	tmpfs := make(map[string]string)
	for _, t := range flTmpfs.GetAll() {
		if arr := strings.SplitN(t, ":", 2); len(arr) > 1 {
			if _, _, err := mount.ParseTmpfsOptions(arr[1]); err != nil {
				return nil, nil, nil, cmd, err
			}
			tmpfs[arr[0]] = arr[1]
		} else {
			tmpfs[arr[0]] = ""
		}
	}

	var (
		parsedArgs = cmd.Args()
		runCmd     strslice.StrSlice
		entrypoint strslice.StrSlice
		image      = cmd.Arg(0)
	)
	if len(parsedArgs) > 1 {
		runCmd = strslice.StrSlice(parsedArgs[1:])
	}
	if *flEntrypoint != "" {
		entrypoint = strslice.StrSlice{*flEntrypoint}
	}

	var (
		domainname string
		hostname   = *flHostname
		parts      = strings.SplitN(hostname, ".", 2)
	)
	if len(parts) > 1 {
		hostname = parts[0]
		domainname = parts[1]
	}

	ports, portBindings, err := nat.ParsePortSpecs(flPublish.GetAll())
	if err != nil {
		return nil, nil, nil, cmd, err
	}

	// Merge in exposed ports to the map of published ports
	for _, e := range flExpose.GetAll() {
		if strings.Contains(e, ":") {
			return nil, nil, nil, cmd, fmt.Errorf("invalid port format for --expose: %s", e)
		}
		//support two formats for expose, original format <portnum>/[<proto>] or <startport-endport>/[<proto>]
		proto, port := nat.SplitProtoPort(e)
		//parse the start and end port and create a sequence of ports to expose
		//if expose a port, the start and end port are the same
		start, end, err := nat.ParsePortRange(port)
		if err != nil {
			return nil, nil, nil, cmd, fmt.Errorf("invalid range format for --expose: %s, error: %s", e, err)
		}
		for i := start; i <= end; i++ {
			p, err := nat.NewPort(proto, strconv.FormatUint(i, 10))
			if err != nil {
				return nil, nil, nil, cmd, err
			}
			if _, exists := ports[p]; !exists {
				ports[p] = struct{}{}
			}
		}
	}

	// parse device mappings
	deviceMappings := []container.DeviceMapping{}
	for _, device := range flDevices.GetAll() {
		deviceMapping, err := ParseDevice(device)
		if err != nil {
			return nil, nil, nil, cmd, err
		}
		deviceMappings = append(deviceMappings, deviceMapping)
	}

	// collect all the environment variables for the container
	envVariables, err := readKVStrings(flEnvFile.GetAll(), flEnv.GetAll())
	if err != nil {
		return nil, nil, nil, cmd, err
	}

	// collect all the labels for the container
	labels, err := readKVStrings(flLabelsFile.GetAll(), flLabels.GetAll())
	if err != nil {
		return nil, nil, nil, cmd, err
	}

	ipcMode := container.IpcMode(*flIpcMode)
	if !ipcMode.Valid() {
		return nil, nil, nil, cmd, fmt.Errorf("--ipc: invalid IPC mode")
	}

	pidMode := container.PidMode(*flPidMode)
	if !pidMode.Valid() {
		return nil, nil, nil, cmd, fmt.Errorf("--pid: invalid PID mode")
	}

	utsMode := container.UTSMode(*flUTSMode)
	if !utsMode.Valid() {
		return nil, nil, nil, cmd, fmt.Errorf("--uts: invalid UTS mode")
	}

	restartPolicy, err := ParseRestartPolicy(*flRestartPolicy)
	if err != nil {
		return nil, nil, nil, cmd, err
	}

	loggingOpts, err := parseLoggingOpts(*flLoggingDriver, flLoggingOpts.GetAll())
	if err != nil {
		return nil, nil, nil, cmd, err
	}

	securityOpts, err := parseSecurityOpts(flSecurityOpt.GetAll())
	if err != nil {
		return nil, nil, nil, cmd, err
	}

	resources := container.Resources{
		CgroupParent:         *flCgroupParent,
		Memory:               flMemory,
		MemoryReservation:    MemoryReservation,
		MemorySwap:           memorySwap,
		MemorySwappiness:     flSwappiness,
		KernelMemory:         KernelMemory,
		OomKillDisable:       flOomKillDisable,
		CPUShares:            *flCPUShares,
		CPUPeriod:            *flCPUPeriod,
		CpusetCpus:           *flCpusetCpus,
		CpusetMems:           *flCpusetMems,
		CPUQuota:             *flCPUQuota,
		BlkioWeight:          *flBlkioWeight,
		BlkioWeightDevice:    flBlkioWeightDevice.GetList(),
		BlkioDeviceReadBps:   flDeviceReadBps.GetList(),
		BlkioDeviceWriteBps:  flDeviceWriteBps.GetList(),
		BlkioDeviceReadIOps:  flDeviceReadIOps.GetList(),
		BlkioDeviceWriteIOps: flDeviceWriteIOps.GetList(),
		Ulimits:              flUlimits.GetList(),
		Devices:              deviceMappings,
	}

	config := &container.Config{
		Hostname:     hostname,
		Domainname:   domainname,
		ExposedPorts: ports,
		User:         *flUser,
		Tty:          *flTty,
		// TODO: deprecated, it comes from -n, --networking
		// it's still needed internally to set the network to disabled
		// if e.g. bridge is none in daemon opts, and in inspect
		NetworkDisabled: false,
		OpenStdin:       *flStdin,
		AttachStdin:     attachStdin,
		AttachStdout:    attachStdout,
		AttachStderr:    attachStderr,
		Env:             envVariables,
		Cmd:             runCmd,
		Image:           image,
		Volumes:         flVolumes.GetMap(),
		MacAddress:      *flMacAddress,
		Entrypoint:      entrypoint,
		WorkingDir:      *flWorkingDir,
		Labels:          ConvertKVStringsToMap(labels),
	}
	if cmd.IsSet("-stop-signal") {
		config.StopSignal = *flStopSignal
	}

	hostConfig := &container.HostConfig{
		Binds:           binds,
		ContainerIDFile: *flContainerIDFile,
		OomScoreAdj:     *flOomScoreAdj,
		Privileged:      *flPrivileged,
		PortBindings:    portBindings,
		Links:           flLinks.GetAll(),
		PublishAllPorts: *flPublishAll,
		// Make sure the dns fields are never nil.
		// New containers don't ever have those fields nil,
		// but pre created containers can still have those nil values.
		// See https://github.com/docker/docker/pull/17779
		// for a more detailed explanation on why we don't want that.
		DNS:            flDNS.GetAllOrEmpty(),
		DNSSearch:      flDNSSearch.GetAllOrEmpty(),
		DNSOptions:     flDNSOptions.GetAllOrEmpty(),
		ExtraHosts:     flExtraHosts.GetAll(),
		VolumesFrom:    flVolumesFrom.GetAll(),
		NetworkMode:    container.NetworkMode(*flNetMode),
		IpcMode:        ipcMode,
		PidMode:        pidMode,
		UTSMode:        utsMode,
		CapAdd:         strslice.StrSlice(flCapAdd.GetAll()),
		CapDrop:        strslice.StrSlice(flCapDrop.GetAll()),
		GroupAdd:       flGroupAdd.GetAll(),
		RestartPolicy:  restartPolicy,
		SecurityOpt:    securityOpts,
		ReadonlyRootfs: *flReadonlyRootfs,
		LogConfig:      container.LogConfig{Type: *flLoggingDriver, Config: loggingOpts},
		VolumeDriver:   *flVolumeDriver,
		Isolation:      container.Isolation(*flIsolation),
		ShmSize:        shmSize,
		Resources:      resources,
		Tmpfs:          tmpfs,
	}

	// When allocating stdin in attached mode, close stdin at client disconnect
	if config.OpenStdin && config.AttachStdin {
		config.StdinOnce = true
	}

	networkingConfig := &networktypes.NetworkingConfig{
		EndpointsConfig: make(map[string]*networktypes.EndpointSettings),
	}

	if *flIPv4Address != "" || *flIPv6Address != "" {
		networkingConfig.EndpointsConfig[string(hostConfig.NetworkMode)] = &networktypes.EndpointSettings{
			IPAMConfig: &networktypes.EndpointIPAMConfig{
				IPv4Address: *flIPv4Address,
				IPv6Address: *flIPv6Address,
			},
		}
	}

	if hostConfig.NetworkMode.IsUserDefined() && len(hostConfig.Links) > 0 {
		epConfig := networkingConfig.EndpointsConfig[string(hostConfig.NetworkMode)]
		if epConfig == nil {
			epConfig = &networktypes.EndpointSettings{}
		}
		epConfig.Links = make([]string, len(hostConfig.Links))
		copy(epConfig.Links, hostConfig.Links)
		networkingConfig.EndpointsConfig[string(hostConfig.NetworkMode)] = epConfig
	}

	if flAliases.Len() > 0 {
		epConfig := networkingConfig.EndpointsConfig[string(hostConfig.NetworkMode)]
		if epConfig == nil {
			epConfig = &networktypes.EndpointSettings{}
		}
		epConfig.Aliases = make([]string, flAliases.Len())
		copy(epConfig.Aliases, flAliases.GetAll())
		networkingConfig.EndpointsConfig[string(hostConfig.NetworkMode)] = epConfig
	}

	return config, hostConfig, networkingConfig, cmd, nil
}

// reads a file of line terminated key=value pairs and override that with override parameter
func readKVStrings(files []string, override []string) ([]string, error) {
	envVariables := []string{}
	for _, ef := range files {
		parsedVars, err := ParseEnvFile(ef)
		if err != nil {
			return nil, err
		}
		envVariables = append(envVariables, parsedVars...)
	}
	// parse the '-e' and '--env' after, to allow override
	envVariables = append(envVariables, override...)

	return envVariables, nil
}

// ConvertKVStringsToMap converts ["key=value"] to {"key":"value"}
func ConvertKVStringsToMap(values []string) map[string]string {
	result := make(map[string]string, len(values))
	for _, value := range values {
		kv := strings.SplitN(value, "=", 2)
		if len(kv) == 1 {
			result[kv[0]] = ""
		} else {
			result[kv[0]] = kv[1]
		}
	}

	return result
}

func parseLoggingOpts(loggingDriver string, loggingOpts []string) (map[string]string, error) {
	loggingOptsMap := ConvertKVStringsToMap(loggingOpts)
	if loggingDriver == "none" && len(loggingOpts) > 0 {
		return map[string]string{}, fmt.Errorf("invalid logging opts for driver %s", loggingDriver)
	}
	return loggingOptsMap, nil
}

// takes a local seccomp daemon, reads the file contents for sending to the daemon
func parseSecurityOpts(securityOpts []string) ([]string, error) {
	for key, opt := range securityOpts {
		con := strings.SplitN(opt, ":", 2)
		if len(con) == 1 {
			return securityOpts, fmt.Errorf("invalid --security-opt: %q", opt)
		}
		if con[0] == "seccomp" && con[1] != "unconfined" {
			f, err := ioutil.ReadFile(con[1])
			if err != nil {
				return securityOpts, fmt.Errorf("opening seccomp profile (%s) failed: %v", con[1], err)
			}
			b := bytes.NewBuffer(nil)
			if err := json.Compact(b, f); err != nil {
				return securityOpts, fmt.Errorf("compacting json for seccomp profile (%s) failed: %v", con[1], err)
			}
			securityOpts[key] = fmt.Sprintf("seccomp:%s", b.Bytes())
		}
	}

	return securityOpts, nil
}

// ParseRestartPolicy returns the parsed policy or an error indicating what is incorrect
func ParseRestartPolicy(policy string) (container.RestartPolicy, error) {
	p := container.RestartPolicy{}

	if policy == "" {
		return p, nil
	}

	var (
		parts = strings.Split(policy, ":")
		name  = parts[0]
	)

	p.Name = name
	switch name {
	case "always", "unless-stopped":
		if len(parts) > 1 {
			return p, fmt.Errorf("maximum restart count not valid with restart policy of \"%s\"", name)
		}
	case "no":
		// do nothing
	case "on-failure":
		if len(parts) > 2 {
			return p, fmt.Errorf("restart count format is not valid, usage: 'on-failure:N' or 'on-failure'")
		}
		if len(parts) == 2 {
			count, err := strconv.Atoi(parts[1])
			if err != nil {
				return p, err
			}

			p.MaximumRetryCount = count
		}
	default:
		return p, fmt.Errorf("invalid restart policy %s", name)
	}

	return p, nil
}

// ParseDevice parses a device mapping string to a container.DeviceMapping struct
func ParseDevice(device string) (container.DeviceMapping, error) {
	src := ""
	dst := ""
	permissions := "rwm"
	arr := strings.Split(device, ":")
	switch len(arr) {
	case 3:
		permissions = arr[2]
		fallthrough
	case 2:
		if ValidDeviceMode(arr[1]) {
			permissions = arr[1]
		} else {
			dst = arr[1]
		}
		fallthrough
	case 1:
		src = arr[0]
	default:
		return container.DeviceMapping{}, fmt.Errorf("invalid device specification: %s", device)
	}

	if dst == "" {
		dst = src
	}

	deviceMapping := container.DeviceMapping{
		PathOnHost:        src,
		PathInContainer:   dst,
		CgroupPermissions: permissions,
	}
	return deviceMapping, nil
}

// ParseLink parses and validates the specified string as a link format (name:alias)
func ParseLink(val string) (string, string, error) {
	if val == "" {
		return "", "", fmt.Errorf("empty string specified for links")
	}
	arr := strings.Split(val, ":")
	if len(arr) > 2 {
		return "", "", fmt.Errorf("bad format for links: %s", val)
	}
	if len(arr) == 1 {
		return val, val, nil
	}
	// This is kept because we can actually get an HostConfig with links
	// from an already created container and the format is not `foo:bar`
	// but `/foo:/c1/bar`
	if strings.HasPrefix(arr[0], "/") {
		_, alias := path.Split(arr[1])
		return arr[0][1:], alias, nil
	}
	return arr[0], arr[1], nil
}

// ValidateLink validates that the specified string has a valid link format (containerName:alias).
func ValidateLink(val string) (string, error) {
	if _, _, err := ParseLink(val); err != nil {
		return val, err
	}
	return val, nil
}

// ValidDeviceMode checks if the mode for device is valid or not.
// Valid mode is a composition of r (read), w (write), and m (mknod).
func ValidDeviceMode(mode string) bool {
	var legalDeviceMode = map[rune]bool{
		'r': true,
		'w': true,
		'm': true,
	}
	if mode == "" {
		return false
	}
	for _, c := range mode {
		if !legalDeviceMode[c] {
			return false
		}
		legalDeviceMode[c] = false
	}
	return true
}

// ValidateDevice validates a path for devices
// It will make sure 'val' is in the form:
//    [host-dir:]container-path[:mode]
// It also validates the device mode.
func ValidateDevice(val string) (string, error) {
	return validatePath(val, ValidDeviceMode)
}

func validatePath(val string, validator func(string) bool) (string, error) {
	var containerPath string
	var mode string

	if strings.Count(val, ":") > 2 {
		return val, fmt.Errorf("bad format for path: %s", val)
	}

	split := strings.SplitN(val, ":", 3)
	if split[0] == "" {
		return val, fmt.Errorf("bad format for path: %s", val)
	}
	switch len(split) {
	case 1:
		containerPath = split[0]
		val = path.Clean(containerPath)
	case 2:
		if isValid := validator(split[1]); isValid {
			containerPath = split[0]
			mode = split[1]
			val = fmt.Sprintf("%s:%s", path.Clean(containerPath), mode)
		} else {
			containerPath = split[1]
			val = fmt.Sprintf("%s:%s", split[0], path.Clean(containerPath))
		}
	case 3:
		containerPath = split[1]
		mode = split[2]
		if isValid := validator(split[2]); !isValid {
			return val, fmt.Errorf("bad mode specified: %s", mode)
		}
		val = fmt.Sprintf("%s:%s:%s", split[0], containerPath, mode)
	}

	if !path.IsAbs(containerPath) {
		return val, fmt.Errorf("%s is not an absolute path", containerPath)
	}
	return val, nil
}

// volumeSplitN splits raw into a maximum of n parts, separated by a separator colon.
// A separator colon is the last `:` character in the regex `[/:\\]?[a-zA-Z]:` (note `\\` is `\` escaped).
// This allows to correctly split strings such as `C:\foo:D:\:rw`.
func volumeSplitN(raw string, n int) []string {
	var array []string
	if len(raw) == 0 || raw[0] == ':' {
		// invalid
		return nil
	}
	// numberOfParts counts the number of parts separated by a separator colon
	numberOfParts := 0
	// left represents the left-most cursor in raw, updated at every `:` character considered as a separator.
	left := 0
	// right represents the right-most cursor in raw incremented with the loop. Note this
	// starts at index 1 as index 0 is already handle above as a special case.
	for right := 1; right < len(raw); right++ {
		// stop parsing if reached maximum number of parts
		if n >= 0 && numberOfParts >= n {
			break
		}
		if raw[right] != ':' {
			continue
		}
		potentialDriveLetter := raw[right-1]
		if (potentialDriveLetter >= 'A' && potentialDriveLetter <= 'Z') || (potentialDriveLetter >= 'a' && potentialDriveLetter <= 'z') {
			if right > 1 {
				beforePotentialDriveLetter := raw[right-2]
				if beforePotentialDriveLetter != ':' && beforePotentialDriveLetter != '/' && beforePotentialDriveLetter != '\\' {
					// e.g. `C:` is not preceded by any delimiter, therefore it was not a drive letter but a path ending with `C:`.
					array = append(array, raw[left:right])
					left = right + 1
					numberOfParts++
				}
				// else, `C:` is considered as a drive letter and not as a delimiter, so we continue parsing.
			}
			// if right == 1, then `C:` is the beginning of the raw string, therefore `:` is again not considered a delimiter and we continue parsing.
		} else {
			// if `:` is not preceded by a potential drive letter, then consider it as a delimiter.
			array = append(array, raw[left:right])
			left = right + 1
			numberOfParts++
		}
	}
	// need to take care of the last part
	if left < len(raw) {
		if n >= 0 && numberOfParts >= n {
			// if the maximum number of parts is reached, just append the rest to the last part
			// left-1 is at the last `:` that needs to be included since not considered a separator.
			array[n-1] += raw[left-1:]
		} else {
			array = append(array, raw[left:])
		}
	}
	return array
}
