package libnetwork

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/stringid"
	"github.com/docker/libnetwork/config"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/etchosts"
	"github.com/docker/libnetwork/ipamapi"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/netutils"
	"github.com/docker/libnetwork/options"
	"github.com/docker/libnetwork/types"
)

// A Network represents a logical connectivity zone that containers may
// join using the Link method. A Network is managed by a specific driver.
type Network interface {
	// A user chosen name for this network.
	Name() string

	// A system generated id for this network.
	ID() string

	// The type of network, which corresponds to its managing driver.
	Type() string

	// Create a new endpoint to this network symbolically identified by the
	// specified unique name. The options parameter carry driver specific options.
	CreateEndpoint(name string, options ...EndpointOption) (Endpoint, error)

	// Delete the network.
	Delete() error

	// Endpoints returns the list of Endpoint(s) in this network.
	Endpoints() []Endpoint

	// WalkEndpoints uses the provided function to walk the Endpoints
	WalkEndpoints(walker EndpointWalker)

	// EndpointByName returns the Endpoint which has the passed name. If not found, the error ErrNoSuchEndpoint is returned.
	EndpointByName(name string) (Endpoint, error)

	// EndpointByID returns the Endpoint which has the passed id. If not found, the error ErrNoSuchEndpoint is returned.
	EndpointByID(id string) (Endpoint, error)

	// Return certain operational data belonging to this network
	Info() NetworkInfo
}

// NetworkInfo returns some configuration and operational information about the network
type NetworkInfo interface {
	IpamConfig() (string, map[string]string, []*IpamConf, []*IpamConf)
	IpamInfo() ([]*IpamInfo, []*IpamInfo)
	DriverOptions() map[string]string
	Scope() string
	IPv6Enabled() bool
	Internal() bool
}

// EndpointWalker is a client provided function which will be used to walk the Endpoints.
// When the function returns true, the walk will stop.
type EndpointWalker func(ep Endpoint) bool

type svcInfo struct {
	svcMap map[string][]net.IP
	ipMap  map[string]string
}

// IpamConf contains all the ipam related configurations for a network
type IpamConf struct {
	// The master address pool for containers and network interfaces
	PreferredPool string
	// A subset of the master pool. If specified,
	// this becomes the container pool
	SubPool string
	// Preferred Network Gateway address (optional)
	Gateway string
	// Auxiliary addresses for network driver. Must be within the master pool.
	// libnetwork will reserve them if they fall into the container pool
	AuxAddresses map[string]string
}

// Validate checks whether the configuration is valid
func (c *IpamConf) Validate() error {
	if c.Gateway != "" && nil == net.ParseIP(c.Gateway) {
		return types.BadRequestErrorf("invalid gateway address %s in Ipam configuration", c.Gateway)
	}
	return nil
}

// IpamInfo contains all the ipam related operational info for a network
type IpamInfo struct {
	PoolID string
	Meta   map[string]string
	driverapi.IPAMData
}

// MarshalJSON encodes IpamInfo into json message
func (i *IpamInfo) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"PoolID": i.PoolID,
	}
	v, err := json.Marshal(&i.IPAMData)
	if err != nil {
		return nil, err
	}
	m["IPAMData"] = string(v)

	if i.Meta != nil {
		m["Meta"] = i.Meta
	}
	return json.Marshal(m)
}

// UnmarshalJSON decodes json message into PoolData
func (i *IpamInfo) UnmarshalJSON(data []byte) error {
	var (
		m   map[string]interface{}
		err error
	)
	if err = json.Unmarshal(data, &m); err != nil {
		return err
	}
	i.PoolID = m["PoolID"].(string)
	if v, ok := m["Meta"]; ok {
		b, _ := json.Marshal(v)
		if err = json.Unmarshal(b, &i.Meta); err != nil {
			return err
		}
	}
	if v, ok := m["IPAMData"]; ok {
		if err = json.Unmarshal([]byte(v.(string)), &i.IPAMData); err != nil {
			return err
		}
	}
	return nil
}

type network struct {
	ctrlr        *controller
	name         string
	networkType  string
	id           string
	scope        string
	ipamType     string
	ipamOptions  map[string]string
	addrSpace    string
	ipamV4Config []*IpamConf
	ipamV6Config []*IpamConf
	ipamV4Info   []*IpamInfo
	ipamV6Info   []*IpamInfo
	enableIPv6   bool
	postIPv6     bool
	epCnt        *endpointCnt
	generic      options.Generic
	dbIndex      uint64
	dbExists     bool
	persist      bool
	stopWatchCh  chan struct{}
	drvOnce      *sync.Once
	internal     bool
	sync.Mutex
}

func (n *network) Name() string {
	n.Lock()
	defer n.Unlock()

	return n.name
}

func (n *network) ID() string {
	n.Lock()
	defer n.Unlock()

	return n.id
}

func (n *network) Type() string {
	n.Lock()
	defer n.Unlock()

	return n.networkType
}

func (n *network) Key() []string {
	n.Lock()
	defer n.Unlock()
	return []string{datastore.NetworkKeyPrefix, n.id}
}

func (n *network) KeyPrefix() []string {
	return []string{datastore.NetworkKeyPrefix}
}

func (n *network) Value() []byte {
	n.Lock()
	defer n.Unlock()
	b, err := json.Marshal(n)
	if err != nil {
		return nil
	}
	return b
}

func (n *network) SetValue(value []byte) error {
	return json.Unmarshal(value, n)
}

func (n *network) Index() uint64 {
	n.Lock()
	defer n.Unlock()
	return n.dbIndex
}

func (n *network) SetIndex(index uint64) {
	n.Lock()
	n.dbIndex = index
	n.dbExists = true
	n.Unlock()
}

func (n *network) Exists() bool {
	n.Lock()
	defer n.Unlock()
	return n.dbExists
}

func (n *network) Skip() bool {
	n.Lock()
	defer n.Unlock()
	return !n.persist
}

func (n *network) New() datastore.KVObject {
	n.Lock()
	defer n.Unlock()

	return &network{
		ctrlr:   n.ctrlr,
		drvOnce: &sync.Once{},
		scope:   n.scope,
	}
}

// CopyTo deep copies to the destination IpamConfig
func (c *IpamConf) CopyTo(dstC *IpamConf) error {
	dstC.PreferredPool = c.PreferredPool
	dstC.SubPool = c.SubPool
	dstC.Gateway = c.Gateway
	if c.AuxAddresses != nil {
		dstC.AuxAddresses = make(map[string]string, len(c.AuxAddresses))
		for k, v := range c.AuxAddresses {
			dstC.AuxAddresses[k] = v
		}
	}
	return nil
}

// CopyTo deep copies to the destination IpamInfo
func (i *IpamInfo) CopyTo(dstI *IpamInfo) error {
	dstI.PoolID = i.PoolID
	if i.Meta != nil {
		dstI.Meta = make(map[string]string)
		for k, v := range i.Meta {
			dstI.Meta[k] = v
		}
	}

	dstI.AddressSpace = i.AddressSpace
	dstI.Pool = types.GetIPNetCopy(i.Pool)
	dstI.Gateway = types.GetIPNetCopy(i.Gateway)

	if i.AuxAddresses != nil {
		dstI.AuxAddresses = make(map[string]*net.IPNet)
		for k, v := range i.AuxAddresses {
			dstI.AuxAddresses[k] = types.GetIPNetCopy(v)
		}
	}

	return nil
}

func (n *network) CopyTo(o datastore.KVObject) error {
	n.Lock()
	defer n.Unlock()

	dstN := o.(*network)
	dstN.name = n.name
	dstN.id = n.id
	dstN.networkType = n.networkType
	dstN.scope = n.scope
	dstN.ipamType = n.ipamType
	dstN.enableIPv6 = n.enableIPv6
	dstN.persist = n.persist
	dstN.postIPv6 = n.postIPv6
	dstN.dbIndex = n.dbIndex
	dstN.dbExists = n.dbExists
	dstN.drvOnce = n.drvOnce
	dstN.internal = n.internal

	for _, v4conf := range n.ipamV4Config {
		dstV4Conf := &IpamConf{}
		v4conf.CopyTo(dstV4Conf)
		dstN.ipamV4Config = append(dstN.ipamV4Config, dstV4Conf)
	}

	for _, v4info := range n.ipamV4Info {
		dstV4Info := &IpamInfo{}
		v4info.CopyTo(dstV4Info)
		dstN.ipamV4Info = append(dstN.ipamV4Info, dstV4Info)
	}

	for _, v6conf := range n.ipamV6Config {
		dstV6Conf := &IpamConf{}
		v6conf.CopyTo(dstV6Conf)
		dstN.ipamV6Config = append(dstN.ipamV6Config, dstV6Conf)
	}

	for _, v6info := range n.ipamV6Info {
		dstV6Info := &IpamInfo{}
		v6info.CopyTo(dstV6Info)
		dstN.ipamV6Info = append(dstN.ipamV6Info, dstV6Info)
	}

	dstN.generic = options.Generic{}
	for k, v := range n.generic {
		dstN.generic[k] = v
	}

	return nil
}

func (n *network) DataScope() string {
	return n.Scope()
}

func (n *network) getEpCnt() *endpointCnt {
	n.Lock()
	defer n.Unlock()

	return n.epCnt
}

// TODO : Can be made much more generic with the help of reflection (but has some golang limitations)
func (n *network) MarshalJSON() ([]byte, error) {
	netMap := make(map[string]interface{})
	netMap["name"] = n.name
	netMap["id"] = n.id
	netMap["networkType"] = n.networkType
	netMap["scope"] = n.scope
	netMap["ipamType"] = n.ipamType
	netMap["addrSpace"] = n.addrSpace
	netMap["enableIPv6"] = n.enableIPv6
	if n.generic != nil {
		netMap["generic"] = n.generic
	}
	netMap["persist"] = n.persist
	netMap["postIPv6"] = n.postIPv6
	if len(n.ipamV4Config) > 0 {
		ics, err := json.Marshal(n.ipamV4Config)
		if err != nil {
			return nil, err
		}
		netMap["ipamV4Config"] = string(ics)
	}
	if len(n.ipamV4Info) > 0 {
		iis, err := json.Marshal(n.ipamV4Info)
		if err != nil {
			return nil, err
		}
		netMap["ipamV4Info"] = string(iis)
	}
	if len(n.ipamV6Config) > 0 {
		ics, err := json.Marshal(n.ipamV6Config)
		if err != nil {
			return nil, err
		}
		netMap["ipamV6Config"] = string(ics)
	}
	if len(n.ipamV6Info) > 0 {
		iis, err := json.Marshal(n.ipamV6Info)
		if err != nil {
			return nil, err
		}
		netMap["ipamV6Info"] = string(iis)
	}
	netMap["internal"] = n.internal
	return json.Marshal(netMap)
}

// TODO : Can be made much more generic with the help of reflection (but has some golang limitations)
func (n *network) UnmarshalJSON(b []byte) (err error) {
	var netMap map[string]interface{}
	if err := json.Unmarshal(b, &netMap); err != nil {
		return err
	}
	n.name = netMap["name"].(string)
	n.id = netMap["id"].(string)
	n.networkType = netMap["networkType"].(string)
	n.enableIPv6 = netMap["enableIPv6"].(bool)

	if v, ok := netMap["generic"]; ok {
		n.generic = v.(map[string]interface{})
		// Restore opts in their map[string]string form
		if v, ok := n.generic[netlabel.GenericData]; ok {
			var lmap map[string]string
			ba, err := json.Marshal(v)
			if err != nil {
				return err
			}
			if err := json.Unmarshal(ba, &lmap); err != nil {
				return err
			}
			n.generic[netlabel.GenericData] = lmap
		}
	}
	if v, ok := netMap["persist"]; ok {
		n.persist = v.(bool)
	}
	if v, ok := netMap["postIPv6"]; ok {
		n.postIPv6 = v.(bool)
	}
	if v, ok := netMap["ipamType"]; ok {
		n.ipamType = v.(string)
	} else {
		n.ipamType = ipamapi.DefaultIPAM
	}
	if v, ok := netMap["addrSpace"]; ok {
		n.addrSpace = v.(string)
	}
	if v, ok := netMap["ipamV4Config"]; ok {
		if err := json.Unmarshal([]byte(v.(string)), &n.ipamV4Config); err != nil {
			return err
		}
	}
	if v, ok := netMap["ipamV4Info"]; ok {
		if err := json.Unmarshal([]byte(v.(string)), &n.ipamV4Info); err != nil {
			return err
		}
	}
	if v, ok := netMap["ipamV6Config"]; ok {
		if err := json.Unmarshal([]byte(v.(string)), &n.ipamV6Config); err != nil {
			return err
		}
	}
	if v, ok := netMap["ipamV6Info"]; ok {
		if err := json.Unmarshal([]byte(v.(string)), &n.ipamV6Info); err != nil {
			return err
		}
	}
	if v, ok := netMap["internal"]; ok {
		n.internal = v.(bool)
	}
	if s, ok := netMap["scope"]; ok {
		n.scope = s.(string)
	}
	return nil
}

// NetworkOption is an option setter function type used to pass various options to
// NewNetwork method. The various setter functions of type NetworkOption are
// provided by libnetwork, they look like NetworkOptionXXXX(...)
type NetworkOption func(n *network)

// NetworkOptionGeneric function returns an option setter for a Generic option defined
// in a Dictionary of Key-Value pair
func NetworkOptionGeneric(generic map[string]interface{}) NetworkOption {
	return func(n *network) {
		if n.generic == nil {
			n.generic = make(map[string]interface{})
		}
		if val, ok := generic[netlabel.EnableIPv6]; ok {
			n.enableIPv6 = val.(bool)
		}
		if val, ok := generic[netlabel.Internal]; ok {
			n.internal = val.(bool)
		}
		for k, v := range generic {
			n.generic[k] = v
		}
	}
}

// NetworkOptionPersist returns an option setter to set persistence policy for a network
func NetworkOptionPersist(persist bool) NetworkOption {
	return func(n *network) {
		n.persist = persist
	}
}

// NetworkOptionEnableIPv6 returns an option setter to explicitly configure IPv6
func NetworkOptionEnableIPv6(enableIPv6 bool) NetworkOption {
	return func(n *network) {
		if n.generic == nil {
			n.generic = make(map[string]interface{})
		}
		n.enableIPv6 = enableIPv6
		n.generic[netlabel.EnableIPv6] = enableIPv6
	}
}

// NetworkOptionInternalNetwork returns an option setter to config the network
// to be internal which disables default gateway service
func NetworkOptionInternalNetwork() NetworkOption {
	return func(n *network) {
		if n.generic == nil {
			n.generic = make(map[string]interface{})
		}
		n.internal = true
		n.generic[netlabel.Internal] = true
	}
}

// NetworkOptionIpam function returns an option setter for the ipam configuration for this network
func NetworkOptionIpam(ipamDriver string, addrSpace string, ipV4 []*IpamConf, ipV6 []*IpamConf, opts map[string]string) NetworkOption {
	return func(n *network) {
		if ipamDriver != "" {
			n.ipamType = ipamDriver
		}
		n.ipamOptions = opts
		n.addrSpace = addrSpace
		n.ipamV4Config = ipV4
		n.ipamV6Config = ipV6
	}
}

// NetworkOptionDriverOpts function returns an option setter for any parameter described by a map
func NetworkOptionDriverOpts(opts map[string]string) NetworkOption {
	return func(n *network) {
		if n.generic == nil {
			n.generic = make(map[string]interface{})
		}
		if opts == nil {
			opts = make(map[string]string)
		}
		// Store the options
		n.generic[netlabel.GenericData] = opts
	}
}

// NetworkOptionDeferIPv6Alloc instructs the network to defer the IPV6 address allocation until after the endpoint has been created
// It is being provided to support the specific docker daemon flags where user can deterministically assign an IPv6 address
// to a container as combination of fixed-cidr-v6 + mac-address
// TODO: Remove this option setter once we support endpoint ipam options
func NetworkOptionDeferIPv6Alloc(enable bool) NetworkOption {
	return func(n *network) {
		n.postIPv6 = enable
	}
}

func (n *network) processOptions(options ...NetworkOption) {
	for _, opt := range options {
		if opt != nil {
			opt(n)
		}
	}
}

func (n *network) driverScope() string {
	c := n.getController()

	c.Lock()
	// Check if a driver for the specified network type is available
	dd, ok := c.drivers[n.networkType]
	c.Unlock()

	if !ok {
		var err error
		dd, err = c.loadDriver(n.networkType)
		if err != nil {
			// If driver could not be resolved simply return an empty string
			return ""
		}
	}

	return dd.capability.DataScope
}

func (n *network) driver(load bool) (driverapi.Driver, error) {
	c := n.getController()

	c.Lock()
	// Check if a driver for the specified network type is available
	dd, ok := c.drivers[n.networkType]
	c.Unlock()

	if !ok && load {
		var err error
		dd, err = c.loadDriver(n.networkType)
		if err != nil {
			return nil, err
		}
	} else if !ok {
		// dont fail if driver loading is not required
		return nil, nil
	}

	n.Lock()
	n.scope = dd.capability.DataScope
	n.Unlock()
	return dd.driver, nil
}

func (n *network) Delete() error {
	n.Lock()
	c := n.ctrlr
	name := n.name
	id := n.id
	n.Unlock()

	n, err := c.getNetworkFromStore(id)
	if err != nil {
		return &UnknownNetworkError{name: name, id: id}
	}

	numEps := n.getEpCnt().EndpointCnt()
	if numEps != 0 {
		return &ActiveEndpointsError{name: n.name, id: n.id}
	}

	if err = n.deleteNetwork(); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if e := c.addNetwork(n); e != nil {
				log.Warnf("failed to rollback deleteNetwork for network %s: %v",
					n.Name(), err)
			}
		}
	}()

	// deleteFromStore performs an atomic delete operation and the
	// network.epCnt will help prevent any possible
	// race between endpoint join and network delete
	if err = n.getController().deleteFromStore(n.getEpCnt()); err != nil {
		return fmt.Errorf("error deleting network endpoint count from store: %v", err)
	}

	n.ipamRelease()

	if err = n.getController().deleteFromStore(n); err != nil {
		return fmt.Errorf("error deleting network from store: %v", err)
	}

	return nil
}

func (n *network) deleteNetwork() error {
	d, err := n.driver(true)
	if err != nil {
		return fmt.Errorf("failed deleting network: %v", err)
	}

	if err := d.DeleteNetwork(n.ID()); err != nil {
		// Forbidden Errors should be honored
		if _, ok := err.(types.ForbiddenError); ok {
			return err
		}

		if _, ok := err.(types.MaskableError); !ok {
			log.Warnf("driver error deleting network %s : %v", n.name, err)
		}
	}

	return nil
}

func (n *network) addEndpoint(ep *endpoint) error {
	d, err := n.driver(true)
	if err != nil {
		return fmt.Errorf("failed to add endpoint: %v", err)
	}

	err = d.CreateEndpoint(n.id, ep.id, ep.Interface(), ep.generic)
	if err != nil {
		return types.InternalErrorf("failed to create endpoint %s on network %s: %v",
			ep.Name(), n.Name(), err)
	}

	return nil
}

func (n *network) CreateEndpoint(name string, options ...EndpointOption) (Endpoint, error) {
	var err error
	if !config.IsValidName(name) {
		return nil, ErrInvalidName(name)
	}

	if _, err = n.EndpointByName(name); err == nil {
		return nil, types.ForbiddenErrorf("service endpoint with name %s already exists", name)
	}

	ep := &endpoint{name: name, generic: make(map[string]interface{}), iface: &endpointInterface{}}
	ep.id = stringid.GenerateRandomID()

	// Initialize ep.network with a possibly stale copy of n. We need this to get network from
	// store. But once we get it from store we will have the most uptodate copy possibly.
	ep.network = n
	ep.locator = n.getController().clusterHostID()
	ep.network, err = ep.getNetworkFromStore()
	if err != nil {
		return nil, fmt.Errorf("failed to get network during CreateEndpoint: %v", err)
	}
	n = ep.network

	ep.processOptions(options...)

	if opt, ok := ep.generic[netlabel.MacAddress]; ok {
		if mac, ok := opt.(net.HardwareAddr); ok {
			ep.iface.mac = mac
		}
	}

	ipam, err := n.getController().getIPAM(n.ipamType)
	if err != nil {
		return nil, err
	}

	if ipam.capability.RequiresMACAddress {
		if ep.iface.mac == nil {
			ep.iface.mac = netutils.GenerateRandomMAC()
		}
		if ep.ipamOptions == nil {
			ep.ipamOptions = make(map[string]string)
		}
		ep.ipamOptions[netlabel.MacAddress] = ep.iface.mac.String()
	}

	if err = ep.assignAddress(ipam.driver, true, !n.postIPv6); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			ep.releaseAddress()
		}
	}()

	if err = n.addEndpoint(ep); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if e := ep.deleteEndpoint(false); e != nil {
				log.Warnf("cleaning up endpoint failed %s : %v", name, e)
			}
		}
	}()

	if err = ep.assignAddress(ipam.driver, false, n.postIPv6); err != nil {
		return nil, err
	}

	if err = n.getController().updateToStore(ep); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if e := n.getController().deleteFromStore(ep); e != nil {
				log.Warnf("error rolling back endpoint %s from store: %v", name, e)
			}
		}
	}()

	// Watch for service records
	n.getController().watchSvcRecord(ep)
	defer func() {
		if err != nil {
			n.getController().unWatchSvcRecord(ep)
		}
	}()

	// Increment endpoint count to indicate completion of endpoint addition
	if err = n.getEpCnt().IncEndpointCnt(); err != nil {
		return nil, err
	}

	return ep, nil
}

func (n *network) Endpoints() []Endpoint {
	var list []Endpoint

	endpoints, err := n.getEndpointsFromStore()
	if err != nil {
		log.Error(err)
	}

	for _, ep := range endpoints {
		list = append(list, ep)
	}

	return list
}

func (n *network) WalkEndpoints(walker EndpointWalker) {
	for _, e := range n.Endpoints() {
		if walker(e) {
			return
		}
	}
}

func (n *network) EndpointByName(name string) (Endpoint, error) {
	if name == "" {
		return nil, ErrInvalidName(name)
	}
	var e Endpoint

	s := func(current Endpoint) bool {
		if current.Name() == name {
			e = current
			return true
		}
		return false
	}

	n.WalkEndpoints(s)

	if e == nil {
		return nil, ErrNoSuchEndpoint(name)
	}

	return e, nil
}

func (n *network) EndpointByID(id string) (Endpoint, error) {
	if id == "" {
		return nil, ErrInvalidID(id)
	}

	ep, err := n.getEndpointFromStore(id)
	if err != nil {
		return nil, ErrNoSuchEndpoint(id)
	}

	return ep, nil
}

func (n *network) updateSvcRecord(ep *endpoint, localEps []*endpoint, isAdd bool) {
	epName := ep.Name()
	if iface := ep.Iface(); iface.Address() != nil {
		myAliases := ep.MyAliases()
		if isAdd {
			if !ep.isAnonymous() {
				n.addSvcRecords(epName, iface.Address().IP, true)
			}
			for _, alias := range myAliases {
				n.addSvcRecords(alias, iface.Address().IP, false)
			}
		} else {
			if !ep.isAnonymous() {
				n.deleteSvcRecords(epName, iface.Address().IP, true)
			}
			for _, alias := range myAliases {
				n.deleteSvcRecords(alias, iface.Address().IP, false)
			}
		}
	}
}

func (n *network) addSvcRecords(name string, epIP net.IP, ipMapUpdate bool) {
	c := n.getController()
	c.Lock()
	defer c.Unlock()
	sr, ok := c.svcDb[n.ID()]
	if !ok {
		sr = svcInfo{
			svcMap: make(map[string][]net.IP),
			ipMap:  make(map[string]string),
		}
		c.svcDb[n.ID()] = sr
	}

	if ipMapUpdate {
		reverseIP := netutils.ReverseIP(epIP.String())
		if _, ok := sr.ipMap[reverseIP]; !ok {
			sr.ipMap[reverseIP] = name
		}
	}

	ipList := sr.svcMap[name]
	for _, ip := range ipList {
		if ip.Equal(epIP) {
			return
		}
	}
	sr.svcMap[name] = append(sr.svcMap[name], epIP)
}

func (n *network) deleteSvcRecords(name string, epIP net.IP, ipMapUpdate bool) {
	c := n.getController()
	c.Lock()
	defer c.Unlock()
	sr, ok := c.svcDb[n.ID()]
	if !ok {
		return
	}

	if ipMapUpdate {
		delete(sr.ipMap, netutils.ReverseIP(epIP.String()))
	}

	ipList := sr.svcMap[name]
	for i, ip := range ipList {
		if ip.Equal(epIP) {
			ipList = append(ipList[:i], ipList[i+1:]...)
			break
		}
	}
	sr.svcMap[name] = ipList

	if len(ipList) == 0 {
		delete(sr.svcMap, name)
	}
}

func (n *network) getSvcRecords(ep *endpoint) []etchosts.Record {
	n.Lock()
	defer n.Unlock()

	var recs []etchosts.Record
	sr, _ := n.ctrlr.svcDb[n.id]

	for h, ip := range sr.svcMap {
		if ep != nil && strings.Split(h, ".")[0] == ep.Name() {
			continue
		}

		recs = append(recs, etchosts.Record{
			Hosts: h,
			IP:    ip[0].String(),
		})
	}

	return recs
}

func (n *network) getController() *controller {
	n.Lock()
	defer n.Unlock()
	return n.ctrlr
}

func (n *network) ipamAllocate() error {
	// For now also exclude bridge from using new ipam
	if n.Type() == "host" || n.Type() == "null" {
		return nil
	}

	ipam, err := n.getController().getIpamDriver(n.ipamType)
	if err != nil {
		return err
	}

	if n.addrSpace == "" {
		if n.addrSpace, err = n.deriveAddressSpace(); err != nil {
			return err
		}
	}

	err = n.ipamAllocateVersion(4, ipam)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			n.ipamReleaseVersion(4, ipam)
		}
	}()

	return n.ipamAllocateVersion(6, ipam)
}

func (n *network) ipamAllocateVersion(ipVer int, ipam ipamapi.Ipam) error {
	var (
		cfgList  *[]*IpamConf
		infoList *[]*IpamInfo
		err      error
	)

	switch ipVer {
	case 4:
		cfgList = &n.ipamV4Config
		infoList = &n.ipamV4Info
	case 6:
		cfgList = &n.ipamV6Config
		infoList = &n.ipamV6Info
	default:
		return types.InternalErrorf("incorrect ip version passed to ipam allocate: %d", ipVer)
	}

	if len(*cfgList) == 0 {
		if ipVer == 6 {
			return nil
		}
		*cfgList = []*IpamConf{{}}
	}

	*infoList = make([]*IpamInfo, len(*cfgList))

	log.Debugf("Allocating IPv%d pools for network %s (%s)", ipVer, n.Name(), n.ID())

	for i, cfg := range *cfgList {
		if err = cfg.Validate(); err != nil {
			return err
		}
		d := &IpamInfo{}
		(*infoList)[i] = d

		d.PoolID, d.Pool, d.Meta, err = ipam.RequestPool(n.addrSpace, cfg.PreferredPool, cfg.SubPool, n.ipamOptions, ipVer == 6)
		if err != nil {
			return err
		}

		defer func() {
			if err != nil {
				if err := ipam.ReleasePool(d.PoolID); err != nil {
					log.Warnf("Failed to release address pool %s after failure to create network %s (%s)", d.PoolID, n.Name(), n.ID())
				}
			}
		}()

		if gws, ok := d.Meta[netlabel.Gateway]; ok {
			if d.Gateway, err = types.ParseCIDR(gws); err != nil {
				return types.BadRequestErrorf("failed to parse gateway address (%v) returned by ipam driver: %v", gws, err)
			}
		}

		// If user requested a specific gateway, libnetwork will allocate it
		// irrespective of whether ipam driver returned a gateway already.
		// If none of the above is true, libnetwork will allocate one.
		if cfg.Gateway != "" || d.Gateway == nil {
			var gatewayOpts = map[string]string{
				ipamapi.RequestAddressType: netlabel.Gateway,
			}
			if d.Gateway, _, err = ipam.RequestAddress(d.PoolID, net.ParseIP(cfg.Gateway), gatewayOpts); err != nil {
				return types.InternalErrorf("failed to allocate gateway (%v): %v", cfg.Gateway, err)
			}
		}

		// Auxiliary addresses must be part of the master address pool
		// If they fall into the container addressable pool, libnetwork will reserve them
		if cfg.AuxAddresses != nil {
			var ip net.IP
			d.IPAMData.AuxAddresses = make(map[string]*net.IPNet, len(cfg.AuxAddresses))
			for k, v := range cfg.AuxAddresses {
				if ip = net.ParseIP(v); ip == nil {
					return types.BadRequestErrorf("non parsable secondary ip address (%s:%s) passed for network %s", k, v, n.Name())
				}
				if !d.Pool.Contains(ip) {
					return types.ForbiddenErrorf("auxilairy address: (%s:%s) must belong to the master pool: %s", k, v, d.Pool)
				}
				// Attempt reservation in the container addressable pool, silent the error if address does not belong to that pool
				if d.IPAMData.AuxAddresses[k], _, err = ipam.RequestAddress(d.PoolID, ip, nil); err != nil && err != ipamapi.ErrIPOutOfRange {
					return types.InternalErrorf("failed to allocate secondary ip address (%s:%s): %v", k, v, err)
				}
			}
		}
	}

	return nil
}

func (n *network) ipamRelease() {
	// For now exclude host and null
	if n.Type() == "host" || n.Type() == "null" {
		return
	}
	ipam, err := n.getController().getIpamDriver(n.ipamType)
	if err != nil {
		log.Warnf("Failed to retrieve ipam driver to release address pool(s) on delete of network %s (%s): %v", n.Name(), n.ID(), err)
		return
	}
	n.ipamReleaseVersion(4, ipam)
	n.ipamReleaseVersion(6, ipam)
}

func (n *network) ipamReleaseVersion(ipVer int, ipam ipamapi.Ipam) {
	var infoList []*IpamInfo

	switch ipVer {
	case 4:
		infoList = n.ipamV4Info
	case 6:
		infoList = n.ipamV6Info
	default:
		log.Warnf("incorrect ip version passed to ipam release: %d", ipVer)
		return
	}

	if infoList == nil {
		return
	}

	log.Debugf("releasing IPv%d pools from network %s (%s)", ipVer, n.Name(), n.ID())

	for _, d := range infoList {
		if d.Gateway != nil {
			if err := ipam.ReleaseAddress(d.PoolID, d.Gateway.IP); err != nil {
				log.Warnf("Failed to release gateway ip address %s on delete of network %s (%s): %v", d.Gateway.IP, n.Name(), n.ID(), err)
			}
		}
		if d.IPAMData.AuxAddresses != nil {
			for k, nw := range d.IPAMData.AuxAddresses {
				if d.Pool.Contains(nw.IP) {
					if err := ipam.ReleaseAddress(d.PoolID, nw.IP); err != nil && err != ipamapi.ErrIPOutOfRange {
						log.Warnf("Failed to release secondary ip address %s (%v) on delete of network %s (%s): %v", k, nw.IP, n.Name(), n.ID(), err)
					}
				}
			}
		}
		if err := ipam.ReleasePool(d.PoolID); err != nil {
			log.Warnf("Failed to release address pool %s on delete of network %s (%s): %v", d.PoolID, n.Name(), n.ID(), err)
		}
	}
}

func (n *network) getIPInfo(ipVer int) []*IpamInfo {
	var info []*IpamInfo
	switch ipVer {
	case 4:
		info = n.ipamV4Info
	case 6:
		info = n.ipamV6Info
	default:
		return nil
	}
	l := make([]*IpamInfo, 0, len(info))
	n.Lock()
	for _, d := range info {
		l = append(l, d)
	}
	n.Unlock()
	return l
}

func (n *network) getIPData(ipVer int) []driverapi.IPAMData {
	var info []*IpamInfo
	switch ipVer {
	case 4:
		info = n.ipamV4Info
	case 6:
		info = n.ipamV6Info
	default:
		return nil
	}
	l := make([]driverapi.IPAMData, 0, len(info))
	n.Lock()
	for _, d := range info {
		l = append(l, d.IPAMData)
	}
	n.Unlock()
	return l
}

func (n *network) deriveAddressSpace() (string, error) {
	c := n.getController()
	c.Lock()
	ipd, ok := c.ipamDrivers[n.ipamType]
	c.Unlock()
	if !ok {
		return "", types.NotFoundErrorf("could not find ipam driver %s to get default address space", n.ipamType)
	}
	if n.DataScope() == datastore.GlobalScope {
		return ipd.defaultGlobalAddressSpace, nil
	}
	return ipd.defaultLocalAddressSpace, nil
}

func (n *network) Info() NetworkInfo {
	return n
}

func (n *network) DriverOptions() map[string]string {
	n.Lock()
	defer n.Unlock()
	if n.generic != nil {
		if m, ok := n.generic[netlabel.GenericData]; ok {
			return m.(map[string]string)
		}
	}
	return map[string]string{}
}

func (n *network) Scope() string {
	n.Lock()
	defer n.Unlock()
	return n.scope
}

func (n *network) IpamConfig() (string, map[string]string, []*IpamConf, []*IpamConf) {
	n.Lock()
	defer n.Unlock()

	v4L := make([]*IpamConf, len(n.ipamV4Config))
	v6L := make([]*IpamConf, len(n.ipamV6Config))

	for i, c := range n.ipamV4Config {
		cc := &IpamConf{}
		c.CopyTo(cc)
		v4L[i] = cc
	}

	for i, c := range n.ipamV6Config {
		cc := &IpamConf{}
		c.CopyTo(cc)
		v6L[i] = cc
	}

	return n.ipamType, n.ipamOptions, v4L, v6L
}

func (n *network) IpamInfo() ([]*IpamInfo, []*IpamInfo) {
	n.Lock()
	defer n.Unlock()

	v4Info := make([]*IpamInfo, len(n.ipamV4Info))
	v6Info := make([]*IpamInfo, len(n.ipamV6Info))

	for i, info := range n.ipamV4Info {
		ic := &IpamInfo{}
		info.CopyTo(ic)
		v4Info[i] = ic
	}

	for i, info := range n.ipamV6Info {
		ic := &IpamInfo{}
		info.CopyTo(ic)
		v6Info[i] = ic
	}

	return v4Info, v6Info
}

func (n *network) Internal() bool {
	n.Lock()
	defer n.Unlock()

	return n.internal
}

func (n *network) IPv6Enabled() bool {
	n.Lock()
	defer n.Unlock()

	return n.enableIPv6
}
