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
	"testing"
)

const (
	failMsgFormat        = "%v, expected %v, actual %v"
	expectedNumOfDevices = 2
)

func TestBlockDevice(t *testing.T) {
	devices, err := FS("fixtures").AllBlockDevices()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != expectedNumOfDevices {
		t.Fatalf(failMsgFormat, "Incorrect number of devices", expectedNumOfDevices, len(devices))
	}
	if devices[0].DeviceName != "dm-0" {
		t.Errorf(failMsgFormat, "Incorrect device name", "dm-0", devices[0].DeviceName)
	}
	device0stats, err := devices[0].NewBlockDeviceStat()
	if err != nil {
		t.Fatal(err)
	}
	if device0stats.ReadIOs != 6447303 {
		t.Errorf(failMsgFormat, "Incorrect read I/Os", 6447303, device0stats.ReadIOs)
	}
	if device0stats.WeightedIOTicks != 6088971 {
		t.Errorf(failMsgFormat, "Incorrect time in queue", 6088971, device0stats.WeightedIOTicks)
	}
	device1stats, err := devices[1].NewBlockDeviceStat()
	if err != nil {
		t.Fatal(err)
	}
	if device1stats.WriteSectors != 286915323 {
		t.Errorf(failMsgFormat, "Incorrect write merges", 286915323, device1stats.WriteSectors)
	}
	if device1stats.DiscardTicks != 12 {
		t.Errorf(failMsgFormat, "Incorrect discard ticks", 12, device1stats.DiscardTicks)
	}
}
