package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/docker/docker/pkg/integration/checker"
	"github.com/docker/engine-api/types"
	"github.com/docker/engine-api/types/filters"
	"github.com/docker/engine-api/types/network"
	"github.com/go-check/check"
)

func (s *DockerSuite) TestApiNetworkGetDefaults(c *check.C) {
	testRequires(c, DaemonIsLinux)
	// By default docker daemon creates 3 networks. check if they are present
	defaults := []string{"bridge", "host", "none"}
	for _, nn := range defaults {
		c.Assert(isNetworkAvailable(c, nn), checker.Equals, true)
	}
}

func (s *DockerSuite) TestApiNetworkCreateDelete(c *check.C) {
	testRequires(c, DaemonIsLinux)
	// Create a network
	name := "testnetwork"
	config := types.NetworkCreate{
		Name:           name,
		CheckDuplicate: true,
	}
	id := createNetwork(c, config, true)
	c.Assert(isNetworkAvailable(c, name), checker.Equals, true)

	// delete the network and make sure it is deleted
	deleteNetwork(c, id, true)
	c.Assert(isNetworkAvailable(c, name), checker.Equals, false)
}

func (s *DockerSuite) TestApiNetworkCreateCheckDuplicate(c *check.C) {
	testRequires(c, DaemonIsLinux)
	name := "testcheckduplicate"
	configOnCheck := types.NetworkCreate{
		Name:           name,
		CheckDuplicate: true,
	}
	configNotCheck := types.NetworkCreate{
		Name:           name,
		CheckDuplicate: false,
	}

	// Creating a new network first
	createNetwork(c, configOnCheck, true)
	c.Assert(isNetworkAvailable(c, name), checker.Equals, true)

	// Creating another network with same name and CheckDuplicate must fail
	createNetwork(c, configOnCheck, false)

	// Creating another network with same name and not CheckDuplicate must succeed
	createNetwork(c, configNotCheck, true)
}

func (s *DockerSuite) TestApiNetworkFilter(c *check.C) {
	testRequires(c, DaemonIsLinux)
	nr := getNetworkResource(c, getNetworkIDByName(c, "bridge"))
	c.Assert(nr.Name, checker.Equals, "bridge")
}

func (s *DockerSuite) TestApiNetworkInspect(c *check.C) {
	testRequires(c, DaemonIsLinux)
	// Inspect default bridge network
	nr := getNetworkResource(c, "bridge")
	c.Assert(nr.Name, checker.Equals, "bridge")

	// run a container and attach it to the default bridge network
	out, _ := dockerCmd(c, "run", "-d", "--name", "test", "busybox", "top")
	containerID := strings.TrimSpace(out)
	containerIP := findContainerIP(c, "test", "bridge")

	// inspect default bridge network again and make sure the container is connected
	nr = getNetworkResource(c, nr.ID)
	c.Assert(nr.Driver, checker.Equals, "bridge")
	c.Assert(nr.Scope, checker.Equals, "local")
	c.Assert(nr.Internal, checker.Equals, false)
	c.Assert(nr.EnableIPv6, checker.Equals, false)
	c.Assert(nr.IPAM.Driver, checker.Equals, "default")
	c.Assert(len(nr.Containers), checker.Equals, 1)
	c.Assert(nr.Containers[containerID], checker.NotNil)

	ip, _, err := net.ParseCIDR(nr.Containers[containerID].IPv4Address)
	c.Assert(err, checker.IsNil)
	c.Assert(ip.String(), checker.Equals, containerIP)

	// IPAM configuration inspect
	ipam := network.IPAM{
		Driver: "default",
		Config: []network.IPAMConfig{{Subnet: "172.28.0.0/16", IPRange: "172.28.5.0/24", Gateway: "172.28.5.254"}},
	}
	config := types.NetworkCreate{
		Name:    "br0",
		Driver:  "bridge",
		IPAM:    ipam,
		Options: map[string]string{"foo": "bar", "opts": "dopts"},
	}
	id0 := createNetwork(c, config, true)
	c.Assert(isNetworkAvailable(c, "br0"), checker.Equals, true)

	nr = getNetworkResource(c, id0)
	c.Assert(len(nr.IPAM.Config), checker.Equals, 1)
	c.Assert(nr.IPAM.Config[0].Subnet, checker.Equals, "172.28.0.0/16")
	c.Assert(nr.IPAM.Config[0].IPRange, checker.Equals, "172.28.5.0/24")
	c.Assert(nr.IPAM.Config[0].Gateway, checker.Equals, "172.28.5.254")
	c.Assert(nr.Options["foo"], checker.Equals, "bar")
	c.Assert(nr.Options["opts"], checker.Equals, "dopts")

	// delete the network and make sure it is deleted
	deleteNetwork(c, id0, true)
	c.Assert(isNetworkAvailable(c, "br0"), checker.Equals, false)
}

func (s *DockerSuite) TestApiNetworkConnectDisconnect(c *check.C) {
	testRequires(c, DaemonIsLinux)
	// Create test network
	name := "testnetwork"
	config := types.NetworkCreate{
		Name: name,
	}
	id := createNetwork(c, config, true)
	nr := getNetworkResource(c, id)
	c.Assert(nr.Name, checker.Equals, name)
	c.Assert(nr.ID, checker.Equals, id)
	c.Assert(len(nr.Containers), checker.Equals, 0)

	// run a container
	out, _ := dockerCmd(c, "run", "-d", "--name", "test", "busybox", "top")
	containerID := strings.TrimSpace(out)

	// connect the container to the test network
	connectNetwork(c, nr.ID, containerID)

	// inspect the network to make sure container is connected
	nr = getNetworkResource(c, nr.ID)
	c.Assert(len(nr.Containers), checker.Equals, 1)
	c.Assert(nr.Containers[containerID], checker.NotNil)

	// check if container IP matches network inspect
	ip, _, err := net.ParseCIDR(nr.Containers[containerID].IPv4Address)
	c.Assert(err, checker.IsNil)
	containerIP := findContainerIP(c, "test", "testnetwork")
	c.Assert(ip.String(), checker.Equals, containerIP)

	// disconnect container from the network
	disconnectNetwork(c, nr.ID, containerID)
	nr = getNetworkResource(c, nr.ID)
	c.Assert(nr.Name, checker.Equals, name)
	c.Assert(len(nr.Containers), checker.Equals, 0)

	// delete the network
	deleteNetwork(c, nr.ID, true)
}

func (s *DockerSuite) TestApiNetworkIpamMultipleBridgeNetworks(c *check.C) {
	testRequires(c, DaemonIsLinux)
	// test0 bridge network
	ipam0 := network.IPAM{
		Driver: "default",
		Config: []network.IPAMConfig{{Subnet: "192.178.0.0/16", IPRange: "192.178.128.0/17", Gateway: "192.178.138.100"}},
	}
	config0 := types.NetworkCreate{
		Name:   "test0",
		Driver: "bridge",
		IPAM:   ipam0,
	}
	id0 := createNetwork(c, config0, true)
	c.Assert(isNetworkAvailable(c, "test0"), checker.Equals, true)

	ipam1 := network.IPAM{
		Driver: "default",
		Config: []network.IPAMConfig{{Subnet: "192.178.128.0/17", Gateway: "192.178.128.1"}},
	}
	// test1 bridge network overlaps with test0
	config1 := types.NetworkCreate{
		Name:   "test1",
		Driver: "bridge",
		IPAM:   ipam1,
	}
	createNetwork(c, config1, false)
	c.Assert(isNetworkAvailable(c, "test1"), checker.Equals, false)

	ipam2 := network.IPAM{
		Driver: "default",
		Config: []network.IPAMConfig{{Subnet: "192.169.0.0/16", Gateway: "192.169.100.100"}},
	}
	// test2 bridge network does not overlap
	config2 := types.NetworkCreate{
		Name:   "test2",
		Driver: "bridge",
		IPAM:   ipam2,
	}
	createNetwork(c, config2, true)
	c.Assert(isNetworkAvailable(c, "test2"), checker.Equals, true)

	// remove test0 and retry to create test1
	deleteNetwork(c, id0, true)
	createNetwork(c, config1, true)
	c.Assert(isNetworkAvailable(c, "test1"), checker.Equals, true)

	// for networks w/o ipam specified, docker will choose proper non-overlapping subnets
	createNetwork(c, types.NetworkCreate{Name: "test3"}, true)
	c.Assert(isNetworkAvailable(c, "test3"), checker.Equals, true)
	createNetwork(c, types.NetworkCreate{Name: "test4"}, true)
	c.Assert(isNetworkAvailable(c, "test4"), checker.Equals, true)
	createNetwork(c, types.NetworkCreate{Name: "test5"}, true)
	c.Assert(isNetworkAvailable(c, "test5"), checker.Equals, true)

	for i := 1; i < 6; i++ {
		deleteNetwork(c, fmt.Sprintf("test%d", i), true)
	}
}

func (s *DockerSuite) TestApiCreateDeletePredefinedNetworks(c *check.C) {
	testRequires(c, DaemonIsLinux)
	createDeletePredefinedNetwork(c, "bridge")
	createDeletePredefinedNetwork(c, "none")
	createDeletePredefinedNetwork(c, "host")
}

func createDeletePredefinedNetwork(c *check.C, name string) {
	// Create pre-defined network
	config := types.NetworkCreate{
		Name:           name,
		CheckDuplicate: true,
	}
	shouldSucceed := false
	createNetwork(c, config, shouldSucceed)
	deleteNetwork(c, name, shouldSucceed)
}

func isNetworkAvailable(c *check.C, name string) bool {
	status, body, err := sockRequest("GET", "/networks", nil)
	c.Assert(status, checker.Equals, http.StatusOK)
	c.Assert(err, checker.IsNil)

	nJSON := []types.NetworkResource{}
	err = json.Unmarshal(body, &nJSON)
	c.Assert(err, checker.IsNil)

	for _, n := range nJSON {
		if n.Name == name {
			return true
		}
	}
	return false
}

func getNetworkIDByName(c *check.C, name string) string {
	var (
		v          = url.Values{}
		filterArgs = filters.NewArgs()
	)
	filterArgs.Add("name", name)
	filterJSON, err := filters.ToParam(filterArgs)
	c.Assert(err, checker.IsNil)
	v.Set("filters", filterJSON)

	status, body, err := sockRequest("GET", "/networks?"+v.Encode(), nil)
	c.Assert(status, checker.Equals, http.StatusOK)
	c.Assert(err, checker.IsNil)

	nJSON := []types.NetworkResource{}
	err = json.Unmarshal(body, &nJSON)
	c.Assert(err, checker.IsNil)
	c.Assert(len(nJSON), checker.Equals, 1)

	return nJSON[0].ID
}

func getNetworkResource(c *check.C, id string) *types.NetworkResource {
	_, obj, err := sockRequest("GET", "/networks/"+id, nil)
	c.Assert(err, checker.IsNil)

	nr := types.NetworkResource{}
	err = json.Unmarshal(obj, &nr)
	c.Assert(err, checker.IsNil)

	return &nr
}

func createNetwork(c *check.C, config types.NetworkCreate, shouldSucceed bool) string {
	status, resp, err := sockRequest("POST", "/networks/create", config)
	if !shouldSucceed {
		c.Assert(status, checker.Not(checker.Equals), http.StatusCreated)
		return ""
	}

	c.Assert(status, checker.Equals, http.StatusCreated)
	c.Assert(err, checker.IsNil)

	var nr types.NetworkCreateResponse
	err = json.Unmarshal(resp, &nr)
	c.Assert(err, checker.IsNil)

	return nr.ID
}

func connectNetwork(c *check.C, nid, cid string) {
	config := types.NetworkConnect{
		Container: cid,
	}

	status, _, err := sockRequest("POST", "/networks/"+nid+"/connect", config)
	c.Assert(status, checker.Equals, http.StatusOK)
	c.Assert(err, checker.IsNil)
}

func disconnectNetwork(c *check.C, nid, cid string) {
	config := types.NetworkConnect{
		Container: cid,
	}

	status, _, err := sockRequest("POST", "/networks/"+nid+"/disconnect", config)
	c.Assert(status, checker.Equals, http.StatusOK)
	c.Assert(err, checker.IsNil)
}

func deleteNetwork(c *check.C, id string, shouldSucceed bool) {
	status, _, err := sockRequest("DELETE", "/networks/"+id, nil)
	if !shouldSucceed {
		c.Assert(status, checker.Not(checker.Equals), http.StatusOK)
		return
	}
	c.Assert(status, checker.Equals, http.StatusOK)
	c.Assert(err, checker.IsNil)
}
