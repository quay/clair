// Copyright 2015 clair authors
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

// Package locks defines an interface for interacting with named locks.
package locks

import (
	"fmt"
	"time"

	"github.com/coreos/clair/config"
	"github.com/coreos/clair/services"
)

type Driver func(cfg config.RegistrableComponentConfig) (Service, error)

var lockDrivers = make(map[string]Driver)

// Register makes a Service constructor available by the provided name.
//
// If this function is called twice with the same name or if the Constructor is
// nil, it panics.
func Register(name string, driver Driver) {
	if driver == nil {
		panic("locks: could not register nil Driver")
	}
	if _, dup := lockDrivers[name]; dup {
		panic("locks: could not register duplicate Driver: " + name)
	}
	lockDrivers[name] = driver
}

// Open opens a Datastore specified by a configuration.
func Open(cfg config.RegistrableComponentConfig) (ls Service, err error) {
	driver, ok := lockDrivers[cfg.Type]
	if !ok {
		err = fmt.Errorf("locks: unknown Driver %q (forgotten configuration or import?)", cfg.Type)
		return
	}
	return driver(cfg)
}

type Service interface {
	services.Base
	// # Lock
	// Lock creates or renew a Lock in the database with the given name, owner and duration.
	// After the specified duration, the Lock expires by itself if it hasn't been unlocked, and thus,
	// let other users create a Lock with the same name. However, the owner can renew its Lock by
	// setting renew to true. Lock should not block, it should instead returns whether the Lock has
	// been successfully acquired/renewed. If it's the case, the expiration time of that Lock is
	// returned as well.
	Lock(name string, owner string, duration time.Duration, renew bool) (bool, time.Time)
	// Unlock releases an existing Lock.
	Unlock(name, owner string)
	// FindLock returns the owner of a Lock specified by the name, and its experation time if it
	// exists.
	FindLock(name string) (string, time.Time, error)
}
