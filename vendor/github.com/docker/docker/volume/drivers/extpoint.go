//go:generate pluginrpc-gen -i $GOFILE -o proxy.go -type volumeDriver -name VolumeDriver

package volumedrivers

import (
	"fmt"
	"sync"

	"github.com/docker/docker/pkg/locker"
	"github.com/docker/docker/pkg/plugins"
	"github.com/docker/docker/volume"
)

// currently created by hand. generation tool would generate this like:
// $ extpoint-gen Driver > volume/extpoint.go

var drivers = &driverExtpoint{extensions: make(map[string]volume.Driver), driverLock: &locker.Locker{}}

const extName = "VolumeDriver"

// NewVolumeDriver returns a driver has the given name mapped on the given client.
func NewVolumeDriver(name string, c client) volume.Driver {
	proxy := &volumeDriverProxy{c}
	return &volumeDriverAdapter{name, proxy}
}

type opts map[string]string
type list []*proxyVolume

// volumeDriver defines the available functions that volume plugins must implement.
// This interface is only defined to generate the proxy objects.
// It's not intended to be public or reused.
type volumeDriver interface {
	// Create a volume with the given name
	Create(name string, opts opts) (err error)
	// Remove the volume with the given name
	Remove(name string) (err error)
	// Get the mountpoint of the given volume
	Path(name string) (mountpoint string, err error)
	// Mount the given volume and return the mountpoint
	Mount(name string) (mountpoint string, err error)
	// Unmount the given volume
	Unmount(name string) (err error)
	// List lists all the volumes known to the driver
	List() (volumes list, err error)
	// Get retrieves the volume with the requested name
	Get(name string) (volume *proxyVolume, err error)
}

type driverExtpoint struct {
	extensions map[string]volume.Driver
	sync.Mutex
	driverLock *locker.Locker
}

// Register associates the given driver to the given name, checking if
// the name is already associated
func Register(extension volume.Driver, name string) bool {
	if name == "" {
		return false
	}

	drivers.Lock()
	defer drivers.Unlock()

	_, exists := drivers.extensions[name]
	if exists {
		return false
	}
	drivers.extensions[name] = extension
	return true
}

// Unregister dissociates the name from it's driver, if the association exists.
func Unregister(name string) bool {
	drivers.Lock()
	defer drivers.Unlock()

	_, exists := drivers.extensions[name]
	if !exists {
		return false
	}
	delete(drivers.extensions, name)
	return true
}

// Lookup returns the driver associated with the given name. If a
// driver with the given name has not been registered it checks if
// there is a VolumeDriver plugin available with the given name.
func Lookup(name string) (volume.Driver, error) {
	drivers.driverLock.Lock(name)
	defer drivers.driverLock.Unlock(name)

	drivers.Lock()
	ext, ok := drivers.extensions[name]
	drivers.Unlock()
	if ok {
		return ext, nil
	}

	pl, err := plugins.Get(name, extName)
	if err != nil {
		return nil, fmt.Errorf("Error looking up volume plugin %s: %v", name, err)
	}

	drivers.Lock()
	defer drivers.Unlock()
	if ext, ok := drivers.extensions[name]; ok {
		return ext, nil
	}

	d := NewVolumeDriver(name, pl.Client)
	drivers.extensions[name] = d
	return d, nil
}

// GetDriver returns a volume driver by it's name.
// If the driver is empty, it looks for the local driver.
func GetDriver(name string) (volume.Driver, error) {
	if name == "" {
		name = volume.DefaultDriverName
	}
	return Lookup(name)
}

// GetDriverList returns list of volume drivers registered.
// If no driver is registered, empty string list will be returned.
func GetDriverList() []string {
	var driverList []string
	drivers.Lock()
	for driverName := range drivers.extensions {
		driverList = append(driverList, driverName)
	}
	drivers.Unlock()
	return driverList
}

// GetAllDrivers lists all the registered drivers
func GetAllDrivers() ([]volume.Driver, error) {
	plugins, err := plugins.GetAll(extName)
	if err != nil {
		return nil, err
	}
	var ds []volume.Driver

	drivers.Lock()
	defer drivers.Unlock()

	for _, d := range drivers.extensions {
		ds = append(ds, d)
	}

	for _, p := range plugins {
		ext, ok := drivers.extensions[p.Name]
		if ok {
			continue
		}

		ext = NewVolumeDriver(p.Name, p.Client)
		drivers.extensions[p.Name] = ext
		ds = append(ds, ext)
	}
	return ds, nil
}
