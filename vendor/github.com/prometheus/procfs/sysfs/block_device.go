// Copyright 2018 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !windows

package sysfs

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/prometheus/procfs/iostats"
)

const (
	blockPath             = "block"
	blockDeviceStatFormat = "%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d"
)

// BlockDevice represents block device in the sys filesystem
// Docs here: https://www.kernel.org/doc/Documentation/block/
type BlockDevice struct {
	DeviceName string
	fs         FS
}

// AllBlockDevices gets the list of block devices from the sys file system
func (fs FS) AllBlockDevices() ([]BlockDevice, error) {
	deviceDirs, err := ioutil.ReadDir(fs.Path(blockPath))
	if err != nil {
		return nil, err
	}
	devices := []BlockDevice{}
	for _, deviceDir := range deviceDirs {
		if deviceDir.IsDir() {
			devices = append(devices, BlockDevice{deviceDir.Name(), fs})
		}
	}
	return devices, nil
}

// NewBlockDeviceStat returns stats for the block device read from /sys/block/<device>/stat.
func (d BlockDevice) NewBlockDeviceStat() (iostats.IOStats, error) {
	stat := iostats.IOStats{}
	bytes, err := ioutil.ReadFile(d.fs.Path(blockPath, d.DeviceName, "stat"))
	if err != nil {
		return stat, err
	}
	count, err := fmt.Sscanf(strings.TrimSpace(string(bytes)), blockDeviceStatFormat,
		&stat.ReadIOs,
		&stat.ReadMerges,
		&stat.ReadSectors,
		&stat.ReadTicks,
		&stat.WriteIOs,
		&stat.WriteMerges,
		&stat.WriteSectors,
		&stat.WriteTicks,
		&stat.IOsInProgress,
		&stat.IOsTotalTicks,
		&stat.WeightedIOTicks,
		&stat.DiscardIOs,
		&stat.DiscardMerges,
		&stat.DiscardSectors,
		&stat.DiscardTicks,
	)
	if count == 11 || count == 15 {
		return stat, nil
	}
	return iostats.IOStats{}, err
}
