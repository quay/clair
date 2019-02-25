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

package procfs

import (
	"testing"
)

const (
	failMsgFormat        = "%v, expected %v, actual %v"
	expectedNumOfDevices = 49
)

func TestDiskstats(t *testing.T) {
	diskstats, err := FS("fixtures").NewDiskstats()
	if err != nil {
		t.Fatal(err)
	}
	if len(diskstats) != expectedNumOfDevices {
		t.Errorf(failMsgFormat, "Incorrect number of devices", expectedNumOfDevices, len(diskstats))
	}
	if diskstats[0].DeviceName != "ram0" {
		t.Errorf(failMsgFormat, "Incorrect device name", "ram0", diskstats[0].DeviceName)
	}
	if diskstats[24].WriteIOs != 28444756 {
		t.Errorf(failMsgFormat, "Incorrect writes completed", 28444756, diskstats[24].WriteIOs)
	}
	if diskstats[48].DiscardTicks != 11130 {
		t.Errorf(failMsgFormat, "Incorrect discard time", 11130, diskstats[48].DiscardTicks)
	}
}
