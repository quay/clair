// +build windows

// Shim for the Host Network Service (HNS) to manage networking for
// Windows Server containers and Hyper-V containers. This module
// is a basic libnetwork driver that passes all the calls to HNS
// It implements the 4 networking modes supported by HNS L2Bridge,
// L2Tunnel, NAT and Transparent(DHCP)
//
// The network are stored in memory and docker daemon ensures discovering
// and loading these networks on startup

package windows

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/Microsoft/hcsshim"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/discoverapi"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/types"
)

// networkConfiguration for network specific configuration
type networkConfiguration struct {
	ID    string
	Type  string
	Name  string
	HnsID string
	RDID  string
}

type hnsEndpoint struct {
	id         string
	profileID  string
	macAddress net.HardwareAddr
	addr       *net.IPNet
}

type hnsNetwork struct {
	id        string
	config    *networkConfiguration
	endpoints map[string]*hnsEndpoint // key: endpoint id
	driver    *driver                 // The network's driver
	sync.Mutex
}

type driver struct {
	name     string
	networks map[string]*hnsNetwork
	sync.Mutex
}

func isValidNetworkType(networkType string) bool {
	if "L2Bridge" == networkType || "L2Tunnel" == networkType || "NAT" == networkType || "Transparent" == networkType {
		return true
	}

	return false
}

// New constructs a new bridge driver
func newDriver(networkType string) *driver {
	return &driver{name: networkType, networks: map[string]*hnsNetwork{}}
}

// GetInit returns an initializer for the given network type
func GetInit(networkType string) func(dc driverapi.DriverCallback, config map[string]interface{}) error {
	return func(dc driverapi.DriverCallback, config map[string]interface{}) error {
		if !isValidNetworkType(networkType) {
			return types.BadRequestErrorf("Network type not supported: %s", networkType)
		}

		return dc.RegisterDriver(networkType, newDriver(networkType), driverapi.Capability{
			DataScope: datastore.LocalScope,
		})
	}
}

func (d *driver) getNetwork(id string) (*hnsNetwork, error) {
	d.Lock()
	defer d.Unlock()

	if nw, ok := d.networks[id]; ok {
		return nw, nil
	}

	return nil, types.NotFoundErrorf("network not found: %s", id)
}

func (n *hnsNetwork) getEndpoint(eid string) (*hnsEndpoint, error) {
	n.Lock()
	defer n.Unlock()

	if ep, ok := n.endpoints[eid]; ok {
		return ep, nil
	}

	return nil, types.NotFoundErrorf("Endpoint not found: %s", eid)
}

func (d *driver) parseNetworkOptions(id string, genericOptions map[string]string) (*networkConfiguration, error) {
	config := &networkConfiguration{}

	for label, value := range genericOptions {
		switch label {
		case NetworkName:
			config.Name = value
		case HNSID:
			config.HnsID = value
		case RoutingDomain:
			config.RDID = value
		}
	}

	config.ID = id
	config.Type = d.name
	return config, nil
}

func (c *networkConfiguration) processIPAM(id string, ipamV4Data, ipamV6Data []driverapi.IPAMData) error {
	if len(ipamV6Data) > 0 {
		return types.ForbiddenErrorf("windowsshim driver doesnt support v6 subnets")
	}

	if len(ipamV4Data) == 0 {
		return types.BadRequestErrorf("network %s requires ipv4 configuration", id)
	}

	return nil
}

// Create a new network
func (d *driver) CreateNetwork(id string, option map[string]interface{}, ipV4Data, ipV6Data []driverapi.IPAMData) error {
	if _, err := d.getNetwork(id); err == nil {
		return types.ForbiddenErrorf("network %s exists", id)
	}

	genData, ok := option[netlabel.GenericData].(map[string]string)
	if !ok {
		return fmt.Errorf("Unknown generic data option")
	}

	// Parse and validate the config. It should not conflict with existing networks' config
	config, err := d.parseNetworkOptions(id, genData)
	if err != nil {
		return err
	}

	err = config.processIPAM(id, ipV4Data, ipV6Data)
	if err != nil {
		return err
	}

	network := &hnsNetwork{
		id:        config.ID,
		endpoints: make(map[string]*hnsEndpoint),
		config:    config,
		driver:    d,
	}

	d.Lock()
	d.networks[config.ID] = network
	d.Unlock()

	// A non blank hnsid indicates that the network was discovered
	// from HNS. No need to call HNS if this network was discovered
	// from HNS
	if config.HnsID == "" {
		subnets := []hcsshim.Subnet{}

		for _, ipData := range ipV4Data {
			subnet := hcsshim.Subnet{
				AddressPrefix:  ipData.Pool.String(),
				GatewayAddress: ipData.Gateway.IP.String(),
			}

			subnets = append(subnets, subnet)
		}

		network := &hcsshim.HNSNetwork{
			Name:    config.Name,
			Type:    d.name,
			Subnets: subnets,
		}

		if network.Name == "" {
			network.Name = id
		}

		configurationb, err := json.Marshal(network)
		if err != nil {
			return err
		}

		configuration := string(configurationb)
		log.Debugf("HNSNetwork Request =%v Address Space=%v", configuration, subnets)

		hnsresponse, err := hcsshim.HNSNetworkRequest("POST", "", configuration)
		if err != nil {
			return err
		}

		config.HnsID = hnsresponse.Id
		genData[HNSID] = config.HnsID
	}

	return nil
}

func (d *driver) DeleteNetwork(nid string) error {
	n, err := d.getNetwork(nid)
	if err != nil {
		return types.InternalMaskableErrorf("%s", err)
	}

	n.Lock()
	config := n.config
	n.Unlock()

	// Cannot remove network if endpoints are still present
	if len(n.endpoints) != 0 {
		return fmt.Errorf("network %s has active endpoint", n.id)
	}

	_, err = hcsshim.HNSNetworkRequest("DELETE", config.HnsID, "")
	if err != nil {
		return err
	}

	d.Lock()
	delete(d.networks, nid)
	d.Unlock()

	return nil
}

func convertPortBindings(portBindings []types.PortBinding) ([]json.RawMessage, error) {
	var pbs []json.RawMessage

	// Enumerate through the port bindings specified by the user and convert
	// them into the internal structure matching the JSON blob that can be
	// understood by the HCS.
	for _, elem := range portBindings {
		proto := strings.ToUpper(elem.Proto.String())
		if proto != "TCP" && proto != "UDP" {
			return nil, fmt.Errorf("invalid protocol %s", elem.Proto.String())
		}

		if elem.HostPort != elem.HostPortEnd {
			return nil, fmt.Errorf("Windows does not support more than one host port in NAT settings")
		}

		if len(elem.HostIP) != 0 {
			return nil, fmt.Errorf("Windows does not support host IP addresses in NAT settings")
		}

		encodedPolicy, err := json.Marshal(hcsshim.NatPolicy{
			Type:         "NAT",
			ExternalPort: elem.HostPort,
			InternalPort: elem.Port,
			Protocol:     elem.Proto.String(),
		})

		if err != nil {
			return nil, err
		}
		pbs = append(pbs, encodedPolicy)
	}
	return pbs, nil
}

func (d *driver) CreateEndpoint(nid, eid string, ifInfo driverapi.InterfaceInfo, epOptions map[string]interface{}) error {
	n, err := d.getNetwork(nid)
	if err != nil {
		return err
	}

	// Check if endpoint id is good and retrieve corresponding endpoint
	ep, err := n.getEndpoint(eid)
	if err == nil && ep != nil {
		return driverapi.ErrEndpointExists(eid)
	}

	endpointStruct := &hcsshim.HNSEndpoint{
		VirtualNetwork: n.config.HnsID,
	}

	// Convert the port mapping for the network
	if opt, ok := epOptions[netlabel.PortMap]; ok {
		if bs, ok := opt.([]types.PortBinding); ok {
			endpointStruct.Policies, err = convertPortBindings(bs)
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("Invalid endpoint configuration for endpoint id%s", eid)
		}
	}

	configurationb, err := json.Marshal(endpointStruct)
	if err != nil {
		return err
	}

	hnsresponse, err := hcsshim.HNSEndpointRequest("POST", "", string(configurationb))
	if err != nil {
		return err
	}

	mac, err := net.ParseMAC(hnsresponse.MacAddress)
	if err != nil {
		return err
	}

	// TODO For now the ip mask is not in the info generated by HNS
	endpoint := &hnsEndpoint{
		id:         eid,
		addr:       &net.IPNet{IP: hnsresponse.IPAddress, Mask: hnsresponse.IPAddress.DefaultMask()},
		macAddress: mac,
	}
	endpoint.profileID = hnsresponse.Id
	n.Lock()
	n.endpoints[eid] = endpoint
	n.Unlock()

	ifInfo.SetIPAddress(endpoint.addr)
	ifInfo.SetMacAddress(endpoint.macAddress)

	return nil
}

func (d *driver) DeleteEndpoint(nid, eid string) error {
	n, err := d.getNetwork(nid)
	if err != nil {
		return types.InternalMaskableErrorf("%s", err)
	}

	ep, err := n.getEndpoint(eid)
	if err != nil {
		return err
	}

	n.Lock()
	delete(n.endpoints, eid)
	n.Unlock()

	_, err = hcsshim.HNSEndpointRequest("DELETE", ep.profileID, "")
	if err != nil {
		return err
	}

	return nil
}

func (d *driver) EndpointOperInfo(nid, eid string) (map[string]interface{}, error) {
	network, err := d.getNetwork(nid)
	if err != nil {
		return nil, err
	}

	endpoint, err := network.getEndpoint(eid)
	if err != nil {
		return nil, err
	}

	data := make(map[string]interface{}, 1)
	data["hnsid"] = endpoint.profileID
	return data, nil
}

// Join method is invoked when a Sandbox is attached to an endpoint.
func (d *driver) Join(nid, eid string, sboxKey string, jinfo driverapi.JoinInfo, options map[string]interface{}) error {
	network, err := d.getNetwork(nid)
	if err != nil {
		return err
	}

	// Ensure that the endpoint exists
	_, err = network.getEndpoint(eid)
	if err != nil {
		return err
	}

	// This is just a stub for now

	jinfo.DisableGatewayService()
	return nil
}

// Leave method is invoked when a Sandbox detaches from an endpoint.
func (d *driver) Leave(nid, eid string) error {
	network, err := d.getNetwork(nid)
	if err != nil {
		return types.InternalMaskableErrorf("%s", err)
	}

	// Ensure that the endpoint exists
	_, err = network.getEndpoint(eid)
	if err != nil {
		return err
	}

	// This is just a stub for now

	return nil
}

func (d *driver) Type() string {
	return d.name
}

// DiscoverNew is a notification for a new discovery event, such as a new node joining a cluster
func (d *driver) DiscoverNew(dType discoverapi.DiscoveryType, data interface{}) error {
	return nil
}

// DiscoverDelete is a notification for a discovery delete event, such as a node leaving a cluster
func (d *driver) DiscoverDelete(dType discoverapi.DiscoveryType, data interface{}) error {
	return nil
}
