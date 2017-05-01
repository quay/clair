package formatter

import (
	"fmt"
	"sync"

	units "github.com/docker/go-units"
)

const (
	winOSType                  = "windows"
	defaultStatsTableFormat    = "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDs}}"
	winDefaultStatsTableFormat = "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"

	containerHeader = "CONTAINER"
	cpuPercHeader   = "CPU %"
	netIOHeader     = "NET I/O"
	blockIOHeader   = "BLOCK I/O"
	memPercHeader   = "MEM %"             // Used only on Linux
	winMemUseHeader = "PRIV WORKING SET"  // Used only on Windows
	memUseHeader    = "MEM USAGE / LIMIT" // Used only on Linux
	pidsHeader      = "PIDS"              // Used only on Linux
)

// StatsEntry represents represents the statistics data collected from a container
type StatsEntry struct {
	Container        string
	Name             string
	ID               string
	CPUPercentage    float64
	Memory           float64 // On Windows this is the private working set
	MemoryLimit      float64 // Not used on Windows
	MemoryPercentage float64 // Not used on Windows
	NetworkRx        float64
	NetworkTx        float64
	BlockRead        float64
	BlockWrite       float64
	PidsCurrent      uint64 // Not used on Windows
	IsInvalid        bool
	OSType           string
}

// ContainerStats represents an entity to store containers statistics synchronously
type ContainerStats struct {
	mutex sync.Mutex
	StatsEntry
	err error
}

// GetError returns the container statistics error.
// This is used to determine whether the statistics are valid or not
func (cs *ContainerStats) GetError() error {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	return cs.err
}

// SetErrorAndReset zeroes all the container statistics and store the error.
// It is used when receiving time out error during statistics collecting to reduce lock overhead
func (cs *ContainerStats) SetErrorAndReset(err error) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.CPUPercentage = 0
	cs.Memory = 0
	cs.MemoryPercentage = 0
	cs.MemoryLimit = 0
	cs.NetworkRx = 0
	cs.NetworkTx = 0
	cs.BlockRead = 0
	cs.BlockWrite = 0
	cs.PidsCurrent = 0
	cs.err = err
	cs.IsInvalid = true
}

// SetError sets container statistics error
func (cs *ContainerStats) SetError(err error) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.err = err
	if err != nil {
		cs.IsInvalid = true
	}
}

// SetStatistics set the container statistics
func (cs *ContainerStats) SetStatistics(s StatsEntry) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	s.Container = cs.Container
	s.OSType = cs.OSType
	cs.StatsEntry = s
}

// GetStatistics returns container statistics with other meta data such as the container name
func (cs *ContainerStats) GetStatistics() StatsEntry {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	return cs.StatsEntry
}

// NewStatsFormat returns a format for rendering an CStatsContext
func NewStatsFormat(source, osType string) Format {
	if source == TableFormatKey {
		if osType == winOSType {
			return Format(winDefaultStatsTableFormat)
		}
		return Format(defaultStatsTableFormat)
	}
	return Format(source)
}

// NewContainerStats returns a new ContainerStats entity and sets in it the given name
func NewContainerStats(container, osType string) *ContainerStats {
	return &ContainerStats{
		StatsEntry: StatsEntry{Container: container, OSType: osType},
	}
}

// ContainerStatsWrite renders the context for a list of containers statistics
func ContainerStatsWrite(ctx Context, containerStats []StatsEntry) error {
	render := func(format func(subContext subContext) error) error {
		for _, cstats := range containerStats {
			containerStatsCtx := &containerStatsContext{
				s: cstats,
			}
			if err := format(containerStatsCtx); err != nil {
				return err
			}
		}
		return nil
	}
	return ctx.Write(&containerStatsContext{}, render)
}

type containerStatsContext struct {
	HeaderContext
	s StatsEntry
}

func (c *containerStatsContext) MarshalJSON() ([]byte, error) {
	return marshalJSON(c)
}

func (c *containerStatsContext) Container() string {
	c.AddHeader(containerHeader)
	return c.s.Container
}

func (c *containerStatsContext) Name() string {
	c.AddHeader(nameHeader)
	name := c.s.Name[1:]
	return name
}

func (c *containerStatsContext) ID() string {
	c.AddHeader(containerIDHeader)
	return c.s.ID
}

func (c *containerStatsContext) CPUPerc() string {
	c.AddHeader(cpuPercHeader)
	if c.s.IsInvalid {
		return fmt.Sprintf("--")
	}
	return fmt.Sprintf("%.2f%%", c.s.CPUPercentage)
}

func (c *containerStatsContext) MemUsage() string {
	header := memUseHeader
	if c.s.OSType == winOSType {
		header = winMemUseHeader
	}
	c.AddHeader(header)
	if c.s.IsInvalid {
		return fmt.Sprintf("-- / --")
	}
	if c.s.OSType == winOSType {
		return fmt.Sprintf("%s", units.BytesSize(c.s.Memory))
	}
	return fmt.Sprintf("%s / %s", units.BytesSize(c.s.Memory), units.BytesSize(c.s.MemoryLimit))
}

func (c *containerStatsContext) MemPerc() string {
	header := memPercHeader
	c.AddHeader(header)
	if c.s.IsInvalid || c.s.OSType == winOSType {
		return fmt.Sprintf("--")
	}
	return fmt.Sprintf("%.2f%%", c.s.MemoryPercentage)
}

func (c *containerStatsContext) NetIO() string {
	c.AddHeader(netIOHeader)
	if c.s.IsInvalid {
		return fmt.Sprintf("--")
	}
	return fmt.Sprintf("%s / %s", units.HumanSizeWithPrecision(c.s.NetworkRx, 3), units.HumanSizeWithPrecision(c.s.NetworkTx, 3))
}

func (c *containerStatsContext) BlockIO() string {
	c.AddHeader(blockIOHeader)
	if c.s.IsInvalid {
		return fmt.Sprintf("--")
	}
	return fmt.Sprintf("%s / %s", units.HumanSizeWithPrecision(c.s.BlockRead, 3), units.HumanSizeWithPrecision(c.s.BlockWrite, 3))
}

func (c *containerStatsContext) PIDs() string {
	c.AddHeader(pidsHeader)
	if c.s.IsInvalid || c.s.OSType == winOSType {
		return fmt.Sprintf("--")
	}
	return fmt.Sprintf("%d", c.s.PidsCurrent)
}
