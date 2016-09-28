// +build linux freebsd

package builtin

import (
	"fmt"

	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/ipam"
	"github.com/docker/libnetwork/ipamapi"
)

// Init registers the built-in ipam service with libnetwork
func Init(ic ipamapi.Callback, l, g interface{}) error {
	var (
		ok                bool
		localDs, globalDs datastore.DataStore
	)

	if l != nil {
		if localDs, ok = l.(datastore.DataStore); !ok {
			return fmt.Errorf("incorrect local datastore passed to built-in ipam init")
		}
	}

	if g != nil {
		if globalDs, ok = g.(datastore.DataStore); !ok {
			return fmt.Errorf("incorrect global datastore passed to built-in ipam init")
		}
	}
	a, err := ipam.NewAllocator(localDs, globalDs)
	if err != nil {
		return err
	}

	return ic.RegisterIpamDriver(ipamapi.DefaultIPAM, a)
}
