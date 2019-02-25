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
	"reflect"
	"testing"
)

func makeUint64(v uint64) *uint64 {
	return &v
}

func TestNewSystemCpufreq(t *testing.T) {
	fs, err := NewFS("fixtures")
	if err != nil {
		t.Fatal(err)
	}

	c, err := fs.NewSystemCpufreq()
	if err != nil {
		t.Fatal(err)
	}

	systemCpufreq := []SystemCPUCpufreqStats{
		// Has missing `cpuinfo_cur_freq` file.
		{
			Name:                     "0",
			CpuinfoCurrentFrequency:  nil,
			CpuinfoMinimumFrequency:  makeUint64(800000),
			CpuinfoMaximumFrequency:  makeUint64(2400000),
			CpuinfoTransitionLatency: makeUint64(0),
			ScalingCurrentFrequency:  makeUint64(1219917),
			ScalingMinimumFrequency:  makeUint64(800000),
			ScalingMaximumFrequency:  makeUint64(2400000),
			AvailableGovernors:       "performance powersave",
			Driver:                   "intel_pstate",
			Governor:                 "powersave",
			RelatedCpus:              "0",
			SetSpeed:                 "<unsupported>",
		},
		// Has missing `scaling_cur_freq` file.
		{
			Name:                     "1",
			CpuinfoCurrentFrequency:  makeUint64(1200195),
			CpuinfoMinimumFrequency:  makeUint64(1200000),
			CpuinfoMaximumFrequency:  makeUint64(3300000),
			CpuinfoTransitionLatency: makeUint64(4294967295),
			ScalingCurrentFrequency:  nil,
			ScalingMinimumFrequency:  makeUint64(1200000),
			ScalingMaximumFrequency:  makeUint64(3300000),
			AvailableGovernors:       "performance powersave",
			Driver:                   "intel_pstate",
			Governor:                 "powersave",
			RelatedCpus:              "1",
			SetSpeed:                 "<unsupported>",
		},
	}

	if !reflect.DeepEqual(systemCpufreq, c) {
		t.Errorf("Result not correct: want %v, have %v", systemCpufreq, c)
	}
}
