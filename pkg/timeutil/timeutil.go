// Copyright 2018 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package timeutil implements extra utilities dealing with time not found
// in the standard library.
package timeutil

import (
	"math"
	"math/rand"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/coreos/clair/pkg/stopper"
)

// ApproxSleep is a stoppable time.Sleep that adds a slight random variation to
// the wakeup time in order to prevent thundering herds.
func ApproxSleep(approxWakeup time.Time, st *stopper.Stopper) (stopped bool) {
	waitUntil := approxWakeup.Add(time.Duration(rand.ExpFloat64()/0.5) * time.Second)
	log.WithField("wakeup", waitUntil).Debug("updater sleeping")
	now := time.Now().UTC()
	if !waitUntil.Before(now) {
		if !st.Sleep(waitUntil.Sub(now)) {
			return true
		}
	}
	return false
}

// ExpBackoff doubles the backoff time, if the result is longer than the
// parameter max, max will be returned.
func ExpBackoff(prev, max time.Duration) time.Duration {
	t := 2 * prev
	if t > max {
		t = max
	}
	if t == 0 {
		return time.Second
	}
	return t
}

// FractionalDuration calculates the fraction of a Duration rounding half way
// from zero.
func FractionalDuration(fraction float64, d time.Duration) time.Duration {
	return time.Duration(math.Round(float64(d) * fraction))
}
