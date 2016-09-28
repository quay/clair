// +build !windows

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/docker/docker/pkg/integration/checker"
	"github.com/docker/docker/runconfig"
	"github.com/docker/engine-api/types"
	"github.com/docker/engine-api/types/versions/v1p20"
	"github.com/docker/libnetwork/driverapi"
	remoteapi "github.com/docker/libnetwork/drivers/remote/api"
	"github.com/docker/libnetwork/ipamapi"
	remoteipam "github.com/docker/libnetwork/ipams/remote/api"
	"github.com/docker/libnetwork/netlabel"
	"github.com/go-check/check"
	"github.com/vishvananda/netlink"
)

const dummyNetworkDriver = "dummy-network-driver"
const dummyIpamDriver = "dummy-ipam-driver"

var remoteDriverNetworkRequest remoteapi.CreateNetworkRequest

func init() {
	check.Suite(&DockerNetworkSuite{
		ds: &DockerSuite{},
	})
}

type DockerNetworkSuite struct {
	server *httptest.Server
	ds     *DockerSuite
	d      *Daemon
}

func (s *DockerNetworkSuite) SetUpTest(c *check.C) {
	s.d = NewDaemon(c)
}

func (s *DockerNetworkSuite) TearDownTest(c *check.C) {
	s.d.Stop()
	s.ds.TearDownTest(c)
}

func (s *DockerNetworkSuite) SetUpSuite(c *check.C) {
	mux := http.NewServeMux()
	s.server = httptest.NewServer(mux)
	c.Assert(s.server, check.NotNil, check.Commentf("Failed to start a HTTP Server"))
	setupRemoteNetworkDrivers(c, mux, s.server.URL, dummyNetworkDriver, dummyIpamDriver)
}

func setupRemoteNetworkDrivers(c *check.C, mux *http.ServeMux, url, netDrv, ipamDrv string) {

	mux.HandleFunc("/Plugin.Activate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1+json")
		fmt.Fprintf(w, `{"Implements": ["%s", "%s"]}`, driverapi.NetworkPluginEndpointType, ipamapi.PluginEndpointType)
	})

	// Network driver implementation
	mux.HandleFunc(fmt.Sprintf("/%s.GetCapabilities", driverapi.NetworkPluginEndpointType), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1+json")
		fmt.Fprintf(w, `{"Scope":"local"}`)
	})

	mux.HandleFunc(fmt.Sprintf("/%s.CreateNetwork", driverapi.NetworkPluginEndpointType), func(w http.ResponseWriter, r *http.Request) {
		err := json.NewDecoder(r.Body).Decode(&remoteDriverNetworkRequest)
		if err != nil {
			http.Error(w, "Unable to decode JSON payload: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1+json")
		fmt.Fprintf(w, "null")
	})

	mux.HandleFunc(fmt.Sprintf("/%s.DeleteNetwork", driverapi.NetworkPluginEndpointType), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1+json")
		fmt.Fprintf(w, "null")
	})

	mux.HandleFunc(fmt.Sprintf("/%s.CreateEndpoint", driverapi.NetworkPluginEndpointType), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1+json")
		fmt.Fprintf(w, `{"Interface":{"MacAddress":"a0:b1:c2:d3:e4:f5"}}`)
	})

	mux.HandleFunc(fmt.Sprintf("/%s.Join", driverapi.NetworkPluginEndpointType), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1+json")

		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "randomIfName", TxQLen: 0}, PeerName: "cnt0"}
		if err := netlink.LinkAdd(veth); err != nil {
			fmt.Fprintf(w, `{"Error":"failed to add veth pair: `+err.Error()+`"}`)
		} else {
			fmt.Fprintf(w, `{"InterfaceName":{ "SrcName":"cnt0", "DstPrefix":"veth"}}`)
		}
	})

	mux.HandleFunc(fmt.Sprintf("/%s.Leave", driverapi.NetworkPluginEndpointType), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1+json")
		fmt.Fprintf(w, "null")
	})

	mux.HandleFunc(fmt.Sprintf("/%s.DeleteEndpoint", driverapi.NetworkPluginEndpointType), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1+json")
		if link, err := netlink.LinkByName("cnt0"); err == nil {
			netlink.LinkDel(link)
		}
		fmt.Fprintf(w, "null")
	})

	// Ipam Driver implementation
	var (
		poolRequest       remoteipam.RequestPoolRequest
		poolReleaseReq    remoteipam.ReleasePoolRequest
		addressRequest    remoteipam.RequestAddressRequest
		addressReleaseReq remoteipam.ReleaseAddressRequest
		lAS               = "localAS"
		gAS               = "globalAS"
		pool              = "172.28.0.0/16"
		poolID            = lAS + "/" + pool
		gw                = "172.28.255.254/16"
	)

	mux.HandleFunc(fmt.Sprintf("/%s.GetDefaultAddressSpaces", ipamapi.PluginEndpointType), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1+json")
		fmt.Fprintf(w, `{"LocalDefaultAddressSpace":"`+lAS+`", "GlobalDefaultAddressSpace": "`+gAS+`"}`)
	})

	mux.HandleFunc(fmt.Sprintf("/%s.RequestPool", ipamapi.PluginEndpointType), func(w http.ResponseWriter, r *http.Request) {
		err := json.NewDecoder(r.Body).Decode(&poolRequest)
		if err != nil {
			http.Error(w, "Unable to decode JSON payload: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1+json")
		if poolRequest.AddressSpace != lAS && poolRequest.AddressSpace != gAS {
			fmt.Fprintf(w, `{"Error":"Unknown address space in pool request: `+poolRequest.AddressSpace+`"}`)
		} else if poolRequest.Pool != "" && poolRequest.Pool != pool {
			fmt.Fprintf(w, `{"Error":"Cannot handle explicit pool requests yet"}`)
		} else {
			fmt.Fprintf(w, `{"PoolID":"`+poolID+`", "Pool":"`+pool+`"}`)
		}
	})

	mux.HandleFunc(fmt.Sprintf("/%s.RequestAddress", ipamapi.PluginEndpointType), func(w http.ResponseWriter, r *http.Request) {
		err := json.NewDecoder(r.Body).Decode(&addressRequest)
		if err != nil {
			http.Error(w, "Unable to decode JSON payload: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1+json")
		// make sure libnetwork is now querying on the expected pool id
		if addressRequest.PoolID != poolID {
			fmt.Fprintf(w, `{"Error":"unknown pool id"}`)
		} else if addressRequest.Address != "" {
			fmt.Fprintf(w, `{"Error":"Cannot handle explicit address requests yet"}`)
		} else {
			fmt.Fprintf(w, `{"Address":"`+gw+`"}`)
		}
	})

	mux.HandleFunc(fmt.Sprintf("/%s.ReleaseAddress", ipamapi.PluginEndpointType), func(w http.ResponseWriter, r *http.Request) {
		err := json.NewDecoder(r.Body).Decode(&addressReleaseReq)
		if err != nil {
			http.Error(w, "Unable to decode JSON payload: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1+json")
		// make sure libnetwork is now asking to release the expected address from the expected poolid
		if addressRequest.PoolID != poolID {
			fmt.Fprintf(w, `{"Error":"unknown pool id"}`)
		} else if addressReleaseReq.Address != gw {
			fmt.Fprintf(w, `{"Error":"unknown address"}`)
		} else {
			fmt.Fprintf(w, "null")
		}
	})

	mux.HandleFunc(fmt.Sprintf("/%s.ReleasePool", ipamapi.PluginEndpointType), func(w http.ResponseWriter, r *http.Request) {
		err := json.NewDecoder(r.Body).Decode(&poolReleaseReq)
		if err != nil {
			http.Error(w, "Unable to decode JSON payload: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1+json")
		// make sure libnetwork is now asking to release the expected poolid
		if addressRequest.PoolID != poolID {
			fmt.Fprintf(w, `{"Error":"unknown pool id"}`)
		} else {
			fmt.Fprintf(w, "null")
		}
	})

	err := os.MkdirAll("/etc/docker/plugins", 0755)
	c.Assert(err, checker.IsNil)

	fileName := fmt.Sprintf("/etc/docker/plugins/%s.spec", netDrv)
	err = ioutil.WriteFile(fileName, []byte(url), 0644)
	c.Assert(err, checker.IsNil)

	ipamFileName := fmt.Sprintf("/etc/docker/plugins/%s.spec", ipamDrv)
	err = ioutil.WriteFile(ipamFileName, []byte(url), 0644)
	c.Assert(err, checker.IsNil)
}

func (s *DockerNetworkSuite) TearDownSuite(c *check.C) {
	if s.server == nil {
		return
	}

	s.server.Close()

	err := os.RemoveAll("/etc/docker/plugins")
	c.Assert(err, checker.IsNil)
}

func assertNwIsAvailable(c *check.C, name string) {
	if !isNwPresent(c, name) {
		c.Fatalf("Network %s not found in network ls o/p", name)
	}
}

func assertNwNotAvailable(c *check.C, name string) {
	if isNwPresent(c, name) {
		c.Fatalf("Found network %s in network ls o/p", name)
	}
}

func isNwPresent(c *check.C, name string) bool {
	out, _ := dockerCmd(c, "network", "ls")
	lines := strings.Split(out, "\n")
	for i := 1; i < len(lines)-1; i++ {
		netFields := strings.Fields(lines[i])
		if netFields[1] == name {
			return true
		}
	}
	return false
}

// assertNwList checks network list retrieved with ls command
// equals to expected network list
// note: out should be `network ls [option]` result
func assertNwList(c *check.C, out string, expectNws []string) {
	lines := strings.Split(out, "\n")
	var nwList []string
	for _, line := range lines[1 : len(lines)-1] {
		netFields := strings.Fields(line)
		// wrap all network name in nwList
		nwList = append(nwList, netFields[1])
	}

	// network ls should contains all expected networks
	c.Assert(nwList, checker.DeepEquals, expectNws)
}

func getNwResource(c *check.C, name string) *types.NetworkResource {
	out, _ := dockerCmd(c, "network", "inspect", name)
	nr := []types.NetworkResource{}
	err := json.Unmarshal([]byte(out), &nr)
	c.Assert(err, check.IsNil)
	return &nr[0]
}

func (s *DockerNetworkSuite) TestDockerNetworkLsDefault(c *check.C) {
	defaults := []string{"bridge", "host", "none"}
	for _, nn := range defaults {
		assertNwIsAvailable(c, nn)
	}
}

func (s *DockerNetworkSuite) TestDockerNetworkCreatePredefined(c *check.C) {
	predefined := []string{"bridge", "host", "none", "default"}
	for _, net := range predefined {
		// predefined networks can't be created again
		out, _, err := dockerCmdWithError("network", "create", net)
		c.Assert(err, checker.NotNil, check.Commentf("%v", out))
	}
}

func (s *DockerNetworkSuite) TestDockerNetworkCreateHostBind(c *check.C) {
	dockerCmd(c, "network", "create", "--subnet=192.168.10.0/24", "--gateway=192.168.10.1", "-o", "com.docker.network.bridge.host_binding_ipv4=192.168.10.1", "testbind")
	assertNwIsAvailable(c, "testbind")

	out, _ := runSleepingContainer(c, "--net=testbind", "-p", "5000:5000")
	id := strings.TrimSpace(out)
	c.Assert(waitRun(id), checker.IsNil)
	out, _ = dockerCmd(c, "ps")
	c.Assert(out, checker.Contains, "192.168.10.1:5000->5000/tcp")
}

func (s *DockerNetworkSuite) TestDockerNetworkRmPredefined(c *check.C) {
	predefined := []string{"bridge", "host", "none", "default"}
	for _, net := range predefined {
		// predefined networks can't be removed
		out, _, err := dockerCmdWithError("network", "rm", net)
		c.Assert(err, checker.NotNil, check.Commentf("%v", out))
	}
}

func (s *DockerNetworkSuite) TestDockerNetworkLsFilter(c *check.C) {
	out, _ := dockerCmd(c, "network", "create", "dev")
	defer func() {
		dockerCmd(c, "network", "rm", "dev")
	}()
	networkID := strings.TrimSpace(out)

	// filter with partial ID and partial name
	// only show 'bridge' and 'dev' network
	out, _ = dockerCmd(c, "network", "ls", "-f", "id="+networkID[0:5], "-f", "name=dge")
	assertNwList(c, out, []string{"bridge", "dev"})

	// only show built-in network (bridge, none, host)
	out, _ = dockerCmd(c, "network", "ls", "-f", "type=builtin")
	assertNwList(c, out, []string{"bridge", "host", "none"})

	// only show custom networks (dev)
	out, _ = dockerCmd(c, "network", "ls", "-f", "type=custom")
	assertNwList(c, out, []string{"dev"})

	// show all networks with filter
	// it should be equivalent of ls without option
	out, _ = dockerCmd(c, "network", "ls", "-f", "type=custom", "-f", "type=builtin")
	assertNwList(c, out, []string{"bridge", "dev", "host", "none"})
}

func (s *DockerNetworkSuite) TestDockerNetworkCreateDelete(c *check.C) {
	dockerCmd(c, "network", "create", "test")
	assertNwIsAvailable(c, "test")

	dockerCmd(c, "network", "rm", "test")
	assertNwNotAvailable(c, "test")
}

func (s *DockerSuite) TestDockerNetworkDeleteNotExists(c *check.C) {
	out, _, err := dockerCmdWithError("network", "rm", "test")
	c.Assert(err, checker.NotNil, check.Commentf("%v", out))
}

func (s *DockerSuite) TestDockerNetworkDeleteMultiple(c *check.C) {
	dockerCmd(c, "network", "create", "testDelMulti0")
	assertNwIsAvailable(c, "testDelMulti0")
	dockerCmd(c, "network", "create", "testDelMulti1")
	assertNwIsAvailable(c, "testDelMulti1")
	dockerCmd(c, "network", "create", "testDelMulti2")
	assertNwIsAvailable(c, "testDelMulti2")
	out, _ := dockerCmd(c, "run", "-d", "--net", "testDelMulti2", "busybox", "top")
	containerID := strings.TrimSpace(out)
	waitRun(containerID)

	// delete three networks at the same time, since testDelMulti2
	// contains active container, its deletion should fail.
	out, _, err := dockerCmdWithError("network", "rm", "testDelMulti0", "testDelMulti1", "testDelMulti2")
	// err should not be nil due to deleting testDelMulti2 failed.
	c.Assert(err, checker.NotNil, check.Commentf("out: %s", out))
	// testDelMulti2 should fail due to network has active endpoints
	c.Assert(out, checker.Contains, "has active endpoints")
	assertNwNotAvailable(c, "testDelMulti0")
	assertNwNotAvailable(c, "testDelMulti1")
	// testDelMulti2 can't be deleted, so it should exist
	assertNwIsAvailable(c, "testDelMulti2")
}

func (s *DockerSuite) TestDockerNetworkInspect(c *check.C) {
	out, _ := dockerCmd(c, "network", "inspect", "host")
	networkResources := []types.NetworkResource{}
	err := json.Unmarshal([]byte(out), &networkResources)
	c.Assert(err, check.IsNil)
	c.Assert(networkResources, checker.HasLen, 1)

	out, _ = dockerCmd(c, "network", "inspect", "--format='{{ .Name }}'", "host")
	c.Assert(strings.TrimSpace(out), check.Equals, "host")
}

func (s *DockerSuite) TestDockerInspectMultipleNetwork(c *check.C) {
	out, _ := dockerCmd(c, "network", "inspect", "host", "none")
	networkResources := []types.NetworkResource{}
	err := json.Unmarshal([]byte(out), &networkResources)
	c.Assert(err, check.IsNil)
	c.Assert(networkResources, checker.HasLen, 2)

	// Should print an error, return an exitCode 1 *but* should print the host network
	out, exitCode, err := dockerCmdWithError("network", "inspect", "host", "nonexistent")
	c.Assert(err, checker.NotNil)
	c.Assert(exitCode, checker.Equals, 1)
	c.Assert(out, checker.Contains, "Error: No such network: nonexistent")
	networkResources = []types.NetworkResource{}
	inspectOut := strings.SplitN(out, "\nError: No such network: nonexistent\n", 2)[0]
	err = json.Unmarshal([]byte(inspectOut), &networkResources)
	c.Assert(networkResources, checker.HasLen, 1)

	// Should print an error and return an exitCode, nothing else
	out, exitCode, err = dockerCmdWithError("network", "inspect", "nonexistent")
	c.Assert(err, checker.NotNil)
	c.Assert(exitCode, checker.Equals, 1)
	c.Assert(out, checker.Contains, "Error: No such network: nonexistent")
}

func (s *DockerSuite) TestDockerInspectNetworkWithContainerName(c *check.C) {
	dockerCmd(c, "network", "create", "brNetForInspect")
	assertNwIsAvailable(c, "brNetForInspect")
	defer func() {
		dockerCmd(c, "network", "rm", "brNetForInspect")
		assertNwNotAvailable(c, "brNetForInspect")
	}()

	out, _ := dockerCmd(c, "run", "-d", "--name", "testNetInspect1", "--net", "brNetForInspect", "busybox", "top")
	c.Assert(waitRun("testNetInspect1"), check.IsNil)
	containerID := strings.TrimSpace(out)
	defer func() {
		// we don't stop container by name, because we'll rename it later
		dockerCmd(c, "stop", containerID)
	}()

	out, _ = dockerCmd(c, "network", "inspect", "brNetForInspect")
	networkResources := []types.NetworkResource{}
	err := json.Unmarshal([]byte(out), &networkResources)
	c.Assert(err, check.IsNil)
	c.Assert(networkResources, checker.HasLen, 1)
	container, ok := networkResources[0].Containers[containerID]
	c.Assert(ok, checker.True)
	c.Assert(container.Name, checker.Equals, "testNetInspect1")

	// rename container and check docker inspect output update
	newName := "HappyNewName"
	dockerCmd(c, "rename", "testNetInspect1", newName)

	// check whether network inspect works properly
	out, _ = dockerCmd(c, "network", "inspect", "brNetForInspect")
	newNetRes := []types.NetworkResource{}
	err = json.Unmarshal([]byte(out), &newNetRes)
	c.Assert(err, check.IsNil)
	c.Assert(newNetRes, checker.HasLen, 1)
	container1, ok := newNetRes[0].Containers[containerID]
	c.Assert(ok, checker.True)
	c.Assert(container1.Name, checker.Equals, newName)

}

func (s *DockerNetworkSuite) TestDockerNetworkConnectDisconnect(c *check.C) {
	dockerCmd(c, "network", "create", "test")
	assertNwIsAvailable(c, "test")
	nr := getNwResource(c, "test")

	c.Assert(nr.Name, checker.Equals, "test")
	c.Assert(len(nr.Containers), checker.Equals, 0)

	// run a container
	out, _ := dockerCmd(c, "run", "-d", "--name", "test", "busybox", "top")
	c.Assert(waitRun("test"), check.IsNil)
	containerID := strings.TrimSpace(out)

	// connect the container to the test network
	dockerCmd(c, "network", "connect", "test", containerID)

	// inspect the network to make sure container is connected
	nr = getNetworkResource(c, nr.ID)
	c.Assert(len(nr.Containers), checker.Equals, 1)
	c.Assert(nr.Containers[containerID], check.NotNil)

	// check if container IP matches network inspect
	ip, _, err := net.ParseCIDR(nr.Containers[containerID].IPv4Address)
	c.Assert(err, check.IsNil)
	containerIP := findContainerIP(c, "test", "test")
	c.Assert(ip.String(), checker.Equals, containerIP)

	// disconnect container from the network
	dockerCmd(c, "network", "disconnect", "test", containerID)
	nr = getNwResource(c, "test")
	c.Assert(nr.Name, checker.Equals, "test")
	c.Assert(len(nr.Containers), checker.Equals, 0)

	// run another container
	out, _ = dockerCmd(c, "run", "-d", "--net", "test", "--name", "test2", "busybox", "top")
	c.Assert(waitRun("test2"), check.IsNil)
	containerID = strings.TrimSpace(out)

	nr = getNwResource(c, "test")
	c.Assert(nr.Name, checker.Equals, "test")
	c.Assert(len(nr.Containers), checker.Equals, 1)

	// force disconnect the container to the test network
	dockerCmd(c, "network", "disconnect", "-f", "test", containerID)

	nr = getNwResource(c, "test")
	c.Assert(nr.Name, checker.Equals, "test")
	c.Assert(len(nr.Containers), checker.Equals, 0)

	dockerCmd(c, "network", "rm", "test")
	assertNwNotAvailable(c, "test")
}

func (s *DockerNetworkSuite) TestDockerNetworkIpamMultipleNetworks(c *check.C) {
	// test0 bridge network
	dockerCmd(c, "network", "create", "--subnet=192.168.0.0/16", "test1")
	assertNwIsAvailable(c, "test1")

	// test2 bridge network does not overlap
	dockerCmd(c, "network", "create", "--subnet=192.169.0.0/16", "test2")
	assertNwIsAvailable(c, "test2")

	// for networks w/o ipam specified, docker will choose proper non-overlapping subnets
	dockerCmd(c, "network", "create", "test3")
	assertNwIsAvailable(c, "test3")
	dockerCmd(c, "network", "create", "test4")
	assertNwIsAvailable(c, "test4")
	dockerCmd(c, "network", "create", "test5")
	assertNwIsAvailable(c, "test5")

	// test network with multiple subnets
	// bridge network doesn't support multiple subnets. hence, use a dummy driver that supports

	dockerCmd(c, "network", "create", "-d", dummyNetworkDriver, "--subnet=192.168.0.0/16", "--subnet=192.170.0.0/16", "test6")
	assertNwIsAvailable(c, "test6")

	// test network with multiple subnets with valid ipam combinations
	// also check same subnet across networks when the driver supports it.
	dockerCmd(c, "network", "create", "-d", dummyNetworkDriver,
		"--subnet=192.168.0.0/16", "--subnet=192.170.0.0/16",
		"--gateway=192.168.0.100", "--gateway=192.170.0.100",
		"--ip-range=192.168.1.0/24",
		"--aux-address", "a=192.168.1.5", "--aux-address", "b=192.168.1.6",
		"--aux-address", "a=192.170.1.5", "--aux-address", "b=192.170.1.6",
		"test7")
	assertNwIsAvailable(c, "test7")

	// cleanup
	for i := 1; i < 8; i++ {
		dockerCmd(c, "network", "rm", fmt.Sprintf("test%d", i))
	}
}

func (s *DockerNetworkSuite) TestDockerNetworkCustomIpam(c *check.C) {
	// Create a bridge network using custom ipam driver
	dockerCmd(c, "network", "create", "--ipam-driver", dummyIpamDriver, "br0")
	assertNwIsAvailable(c, "br0")

	// Verify expected network ipam fields are there
	nr := getNetworkResource(c, "br0")
	c.Assert(nr.Driver, checker.Equals, "bridge")
	c.Assert(nr.IPAM.Driver, checker.Equals, dummyIpamDriver)

	// remove network and exercise remote ipam driver
	dockerCmd(c, "network", "rm", "br0")
	assertNwNotAvailable(c, "br0")
}

func (s *DockerNetworkSuite) TestDockerNetworkIpamOptions(c *check.C) {
	// Create a bridge network using custom ipam driver and options
	dockerCmd(c, "network", "create", "--ipam-driver", dummyIpamDriver, "--ipam-opt", "opt1=drv1", "--ipam-opt", "opt2=drv2", "br0")
	assertNwIsAvailable(c, "br0")

	// Verify expected network ipam options
	nr := getNetworkResource(c, "br0")
	opts := nr.IPAM.Options
	c.Assert(opts["opt1"], checker.Equals, "drv1")
	c.Assert(opts["opt2"], checker.Equals, "drv2")
}

func (s *DockerNetworkSuite) TestDockerNetworkInspectDefault(c *check.C) {
	nr := getNetworkResource(c, "none")
	c.Assert(nr.Driver, checker.Equals, "null")
	c.Assert(nr.Scope, checker.Equals, "local")
	c.Assert(nr.Internal, checker.Equals, false)
	c.Assert(nr.EnableIPv6, checker.Equals, false)
	c.Assert(nr.IPAM.Driver, checker.Equals, "default")
	c.Assert(len(nr.IPAM.Config), checker.Equals, 0)

	nr = getNetworkResource(c, "host")
	c.Assert(nr.Driver, checker.Equals, "host")
	c.Assert(nr.Scope, checker.Equals, "local")
	c.Assert(nr.Internal, checker.Equals, false)
	c.Assert(nr.EnableIPv6, checker.Equals, false)
	c.Assert(nr.IPAM.Driver, checker.Equals, "default")
	c.Assert(len(nr.IPAM.Config), checker.Equals, 0)

	nr = getNetworkResource(c, "bridge")
	c.Assert(nr.Driver, checker.Equals, "bridge")
	c.Assert(nr.Scope, checker.Equals, "local")
	c.Assert(nr.Internal, checker.Equals, false)
	c.Assert(nr.EnableIPv6, checker.Equals, false)
	c.Assert(nr.IPAM.Driver, checker.Equals, "default")
	c.Assert(len(nr.IPAM.Config), checker.Equals, 1)
	c.Assert(nr.IPAM.Config[0].Subnet, checker.NotNil)
	c.Assert(nr.IPAM.Config[0].Gateway, checker.NotNil)
}

func (s *DockerNetworkSuite) TestDockerNetworkInspectCustomUnspecified(c *check.C) {
	// if unspecified, network subnet will be selected from inside preferred pool
	dockerCmd(c, "network", "create", "test01")
	assertNwIsAvailable(c, "test01")

	nr := getNetworkResource(c, "test01")
	c.Assert(nr.Driver, checker.Equals, "bridge")
	c.Assert(nr.Scope, checker.Equals, "local")
	c.Assert(nr.Internal, checker.Equals, false)
	c.Assert(nr.EnableIPv6, checker.Equals, false)
	c.Assert(nr.IPAM.Driver, checker.Equals, "default")
	c.Assert(len(nr.IPAM.Config), checker.Equals, 1)
	c.Assert(nr.IPAM.Config[0].Subnet, checker.NotNil)
	c.Assert(nr.IPAM.Config[0].Gateway, checker.NotNil)

	dockerCmd(c, "network", "rm", "test01")
	assertNwNotAvailable(c, "test01")
}

func (s *DockerNetworkSuite) TestDockerNetworkInspectCustomSpecified(c *check.C) {
	dockerCmd(c, "network", "create", "--driver=bridge", "--ipv6", "--subnet=172.28.0.0/16", "--ip-range=172.28.5.0/24", "--gateway=172.28.5.254", "br0")
	assertNwIsAvailable(c, "br0")

	nr := getNetworkResource(c, "br0")
	c.Assert(nr.Driver, checker.Equals, "bridge")
	c.Assert(nr.Scope, checker.Equals, "local")
	c.Assert(nr.Internal, checker.Equals, false)
	c.Assert(nr.EnableIPv6, checker.Equals, true)
	c.Assert(nr.IPAM.Driver, checker.Equals, "default")
	c.Assert(len(nr.IPAM.Config), checker.Equals, 1)
	c.Assert(nr.IPAM.Config[0].Subnet, checker.Equals, "172.28.0.0/16")
	c.Assert(nr.IPAM.Config[0].IPRange, checker.Equals, "172.28.5.0/24")
	c.Assert(nr.IPAM.Config[0].Gateway, checker.Equals, "172.28.5.254")
	c.Assert(nr.Internal, checker.False)
	dockerCmd(c, "network", "rm", "br0")
	assertNwNotAvailable(c, "test01")
}

func (s *DockerNetworkSuite) TestDockerNetworkIpamInvalidCombinations(c *check.C) {
	// network with ip-range out of subnet range
	_, _, err := dockerCmdWithError("network", "create", "--subnet=192.168.0.0/16", "--ip-range=192.170.0.0/16", "test")
	c.Assert(err, check.NotNil)

	// network with multiple gateways for a single subnet
	_, _, err = dockerCmdWithError("network", "create", "--subnet=192.168.0.0/16", "--gateway=192.168.0.1", "--gateway=192.168.0.2", "test")
	c.Assert(err, check.NotNil)

	// Multiple overlapping subnets in the same network must fail
	_, _, err = dockerCmdWithError("network", "create", "--subnet=192.168.0.0/16", "--subnet=192.168.1.0/16", "test")
	c.Assert(err, check.NotNil)

	// overlapping subnets across networks must fail
	// create a valid test0 network
	dockerCmd(c, "network", "create", "--subnet=192.168.0.0/16", "test0")
	assertNwIsAvailable(c, "test0")
	// create an overlapping test1 network
	_, _, err = dockerCmdWithError("network", "create", "--subnet=192.168.128.0/17", "test1")
	c.Assert(err, check.NotNil)
	dockerCmd(c, "network", "rm", "test0")
	assertNwNotAvailable(c, "test0")
}

func (s *DockerNetworkSuite) TestDockerNetworkDriverOptions(c *check.C) {
	dockerCmd(c, "network", "create", "-d", dummyNetworkDriver, "-o", "opt1=drv1", "-o", "opt2=drv2", "testopt")
	assertNwIsAvailable(c, "testopt")
	gopts := remoteDriverNetworkRequest.Options[netlabel.GenericData]
	c.Assert(gopts, checker.NotNil)
	opts, ok := gopts.(map[string]interface{})
	c.Assert(ok, checker.Equals, true)
	c.Assert(opts["opt1"], checker.Equals, "drv1")
	c.Assert(opts["opt2"], checker.Equals, "drv2")
	dockerCmd(c, "network", "rm", "testopt")
	assertNwNotAvailable(c, "testopt")

}

func (s *DockerDaemonSuite) TestDockerNetworkNoDiscoveryDefaultBridgeNetwork(c *check.C) {
	testRequires(c, ExecSupport)
	// On default bridge network built-in service discovery should not happen
	hostsFile := "/etc/hosts"
	bridgeName := "external-bridge"
	bridgeIP := "192.169.255.254/24"
	out, err := createInterface(c, "bridge", bridgeName, bridgeIP)
	c.Assert(err, check.IsNil, check.Commentf(out))
	defer deleteInterface(c, bridgeName)

	err = s.d.StartWithBusybox("--bridge", bridgeName)
	c.Assert(err, check.IsNil)
	defer s.d.Restart()

	// run two containers and store first container's etc/hosts content
	out, err = s.d.Cmd("run", "-d", "busybox", "top")
	c.Assert(err, check.IsNil)
	cid1 := strings.TrimSpace(out)
	defer s.d.Cmd("stop", cid1)

	hosts, err := s.d.Cmd("exec", cid1, "cat", hostsFile)
	c.Assert(err, checker.IsNil)

	out, err = s.d.Cmd("run", "-d", "--name", "container2", "busybox", "top")
	c.Assert(err, check.IsNil)
	cid2 := strings.TrimSpace(out)

	// verify first container's etc/hosts file has not changed after spawning the second named container
	hostsPost, err := s.d.Cmd("exec", cid1, "cat", hostsFile)
	c.Assert(err, checker.IsNil)
	c.Assert(string(hosts), checker.Equals, string(hostsPost),
		check.Commentf("Unexpected %s change on second container creation", hostsFile))

	// stop container 2 and verify first container's etc/hosts has not changed
	_, err = s.d.Cmd("stop", cid2)
	c.Assert(err, check.IsNil)

	hostsPost, err = s.d.Cmd("exec", cid1, "cat", hostsFile)
	c.Assert(err, checker.IsNil)
	c.Assert(string(hosts), checker.Equals, string(hostsPost),
		check.Commentf("Unexpected %s change on second container creation", hostsFile))

	// but discovery is on when connecting to non default bridge network
	network := "anotherbridge"
	out, err = s.d.Cmd("network", "create", network)
	c.Assert(err, check.IsNil, check.Commentf(out))
	defer s.d.Cmd("network", "rm", network)

	out, err = s.d.Cmd("network", "connect", network, cid1)
	c.Assert(err, check.IsNil, check.Commentf(out))

	hosts, err = s.d.Cmd("exec", cid1, "cat", hostsFile)
	c.Assert(err, checker.IsNil)

	hostsPost, err = s.d.Cmd("exec", cid1, "cat", hostsFile)
	c.Assert(err, checker.IsNil)
	c.Assert(string(hosts), checker.Equals, string(hostsPost),
		check.Commentf("Unexpected %s change on second network connection", hostsFile))
}

func (s *DockerNetworkSuite) TestDockerNetworkAnonymousEndpoint(c *check.C) {
	testRequires(c, ExecSupport, NotArm)
	hostsFile := "/etc/hosts"
	cstmBridgeNw := "custom-bridge-nw"
	cstmBridgeNw1 := "custom-bridge-nw1"

	dockerCmd(c, "network", "create", "-d", "bridge", cstmBridgeNw)
	assertNwIsAvailable(c, cstmBridgeNw)

	// run two anonymous containers and store their etc/hosts content
	out, _ := dockerCmd(c, "run", "-d", "--net", cstmBridgeNw, "busybox", "top")
	cid1 := strings.TrimSpace(out)

	hosts1, err := readContainerFileWithExec(cid1, hostsFile)
	c.Assert(err, checker.IsNil)

	out, _ = dockerCmd(c, "run", "-d", "--net", cstmBridgeNw, "busybox", "top")
	cid2 := strings.TrimSpace(out)

	hosts2, err := readContainerFileWithExec(cid2, hostsFile)
	c.Assert(err, checker.IsNil)

	// verify first container etc/hosts file has not changed
	hosts1post, err := readContainerFileWithExec(cid1, hostsFile)
	c.Assert(err, checker.IsNil)
	c.Assert(string(hosts1), checker.Equals, string(hosts1post),
		check.Commentf("Unexpected %s change on anonymous container creation", hostsFile))

	// Connect the 2nd container to a new network and verify the
	// first container /etc/hosts file still hasn't changed.
	dockerCmd(c, "network", "create", "-d", "bridge", cstmBridgeNw1)
	assertNwIsAvailable(c, cstmBridgeNw1)

	dockerCmd(c, "network", "connect", cstmBridgeNw1, cid2)

	hosts2, err = readContainerFileWithExec(cid2, hostsFile)
	c.Assert(err, checker.IsNil)

	hosts1post, err = readContainerFileWithExec(cid1, hostsFile)
	c.Assert(err, checker.IsNil)
	c.Assert(string(hosts1), checker.Equals, string(hosts1post),
		check.Commentf("Unexpected %s change on container connect", hostsFile))

	// start a named container
	cName := "AnyName"
	out, _ = dockerCmd(c, "run", "-d", "--net", cstmBridgeNw, "--name", cName, "busybox", "top")
	cid3 := strings.TrimSpace(out)

	// verify that container 1 and 2 can ping the named container
	dockerCmd(c, "exec", cid1, "ping", "-c", "1", cName)
	dockerCmd(c, "exec", cid2, "ping", "-c", "1", cName)

	// Stop named container and verify first two containers' etc/hosts file hasn't changed
	dockerCmd(c, "stop", cid3)
	hosts1post, err = readContainerFileWithExec(cid1, hostsFile)
	c.Assert(err, checker.IsNil)
	c.Assert(string(hosts1), checker.Equals, string(hosts1post),
		check.Commentf("Unexpected %s change on name container creation", hostsFile))

	hosts2post, err := readContainerFileWithExec(cid2, hostsFile)
	c.Assert(err, checker.IsNil)
	c.Assert(string(hosts2), checker.Equals, string(hosts2post),
		check.Commentf("Unexpected %s change on name container creation", hostsFile))

	// verify that container 1 and 2 can't ping the named container now
	_, _, err = dockerCmdWithError("exec", cid1, "ping", "-c", "1", cName)
	c.Assert(err, check.NotNil)
	_, _, err = dockerCmdWithError("exec", cid2, "ping", "-c", "1", cName)
	c.Assert(err, check.NotNil)
}

func (s *DockerNetworkSuite) TestDockerNetworkLinkOndefaultNetworkOnly(c *check.C) {
	// Link feature must work only on default network, and not across networks
	cnt1 := "container1"
	cnt2 := "container2"
	network := "anotherbridge"

	// Run first container on default network
	dockerCmd(c, "run", "-d", "--name", cnt1, "busybox", "top")

	// Create another network and run the second container on it
	dockerCmd(c, "network", "create", network)
	assertNwIsAvailable(c, network)
	dockerCmd(c, "run", "-d", "--net", network, "--name", cnt2, "busybox", "top")

	// Try launching a container on default network, linking to the first container. Must succeed
	dockerCmd(c, "run", "-d", "--link", fmt.Sprintf("%s:%s", cnt1, cnt1), "busybox", "top")

	// Try launching a container on default network, linking to the second container. Must fail
	_, _, err := dockerCmdWithError("run", "-d", "--link", fmt.Sprintf("%s:%s", cnt2, cnt2), "busybox", "top")
	c.Assert(err, checker.NotNil)

	// Connect second container to default network. Now a container on default network can link to it
	dockerCmd(c, "network", "connect", "bridge", cnt2)
	dockerCmd(c, "run", "-d", "--link", fmt.Sprintf("%s:%s", cnt2, cnt2), "busybox", "top")
}

func (s *DockerNetworkSuite) TestDockerNetworkOverlayPortMapping(c *check.C) {
	// Verify exposed ports are present in ps output when running a container on
	// a network managed by a driver which does not provide the default gateway
	// for the container
	nwn := "ov"
	ctn := "bb"
	port1 := 80
	port2 := 443
	expose1 := fmt.Sprintf("--expose=%d", port1)
	expose2 := fmt.Sprintf("--expose=%d", port2)

	dockerCmd(c, "network", "create", "-d", dummyNetworkDriver, nwn)
	assertNwIsAvailable(c, nwn)

	dockerCmd(c, "run", "-d", "--net", nwn, "--name", ctn, expose1, expose2, "busybox", "top")

	// Check docker ps o/p for last created container reports the unpublished ports
	unpPort1 := fmt.Sprintf("%d/tcp", port1)
	unpPort2 := fmt.Sprintf("%d/tcp", port2)
	out, _ := dockerCmd(c, "ps", "-n=1")
	// Missing unpublished ports in docker ps output
	c.Assert(out, checker.Contains, unpPort1)
	// Missing unpublished ports in docker ps output
	c.Assert(out, checker.Contains, unpPort2)
}

func (s *DockerNetworkSuite) TestDockerNetworkDriverUngracefulRestart(c *check.C) {
	testRequires(c, DaemonIsLinux, NotUserNamespace)
	dnd := "dnd"
	did := "did"

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	setupRemoteNetworkDrivers(c, mux, server.URL, dnd, did)

	s.d.StartWithBusybox()
	_, err := s.d.Cmd("network", "create", "-d", dnd, "--subnet", "1.1.1.0/24", "net1")
	c.Assert(err, checker.IsNil)

	_, err = s.d.Cmd("run", "-itd", "--net", "net1", "--name", "foo", "--ip", "1.1.1.10", "busybox", "sh")
	c.Assert(err, checker.IsNil)

	// Kill daemon and restart
	if err = s.d.cmd.Process.Kill(); err != nil {
		c.Fatal(err)
	}

	server.Close()

	startTime := time.Now().Unix()
	if err = s.d.Restart(); err != nil {
		c.Fatal(err)
	}
	lapse := time.Now().Unix() - startTime
	if lapse > 60 {
		// In normal scenarios, daemon restart takes ~1 second.
		// Plugin retry mechanism can delay the daemon start. systemd may not like it.
		// Avoid accessing plugins during daemon bootup
		c.Logf("daemon restart took too long : %d seconds", lapse)
	}

	// Restart the custom dummy plugin
	mux = http.NewServeMux()
	server = httptest.NewServer(mux)
	setupRemoteNetworkDrivers(c, mux, server.URL, dnd, did)

	// trying to reuse the same ip must succeed
	_, err = s.d.Cmd("run", "-itd", "--net", "net1", "--name", "bar", "--ip", "1.1.1.10", "busybox", "sh")
	c.Assert(err, checker.IsNil)
}

func (s *DockerNetworkSuite) TestDockerNetworkMacInspect(c *check.C) {
	// Verify endpoint MAC address is correctly populated in container's network settings
	nwn := "ov"
	ctn := "bb"

	dockerCmd(c, "network", "create", "-d", dummyNetworkDriver, nwn)
	assertNwIsAvailable(c, nwn)

	dockerCmd(c, "run", "-d", "--net", nwn, "--name", ctn, "busybox", "top")

	mac := inspectField(c, ctn, "NetworkSettings.Networks."+nwn+".MacAddress")
	c.Assert(mac, checker.Equals, "a0:b1:c2:d3:e4:f5")
}

func (s *DockerSuite) TestInspectApiMultipleNetworks(c *check.C) {
	dockerCmd(c, "network", "create", "mybridge1")
	dockerCmd(c, "network", "create", "mybridge2")
	out, _ := dockerCmd(c, "run", "-d", "busybox", "top")
	id := strings.TrimSpace(out)
	c.Assert(waitRun(id), check.IsNil)

	dockerCmd(c, "network", "connect", "mybridge1", id)
	dockerCmd(c, "network", "connect", "mybridge2", id)

	body := getInspectBody(c, "v1.20", id)
	var inspect120 v1p20.ContainerJSON
	err := json.Unmarshal(body, &inspect120)
	c.Assert(err, checker.IsNil)

	versionedIP := inspect120.NetworkSettings.IPAddress

	body = getInspectBody(c, "v1.21", id)
	var inspect121 types.ContainerJSON
	err = json.Unmarshal(body, &inspect121)
	c.Assert(err, checker.IsNil)
	c.Assert(inspect121.NetworkSettings.Networks, checker.HasLen, 3)

	bridge := inspect121.NetworkSettings.Networks["bridge"]
	c.Assert(bridge.IPAddress, checker.Equals, versionedIP)
	c.Assert(bridge.IPAddress, checker.Equals, inspect121.NetworkSettings.IPAddress)
}

func connectContainerToNetworks(c *check.C, d *Daemon, cName string, nws []string) {
	// Run a container on the default network
	out, err := d.Cmd("run", "-d", "--name", cName, "busybox", "top")
	c.Assert(err, checker.IsNil, check.Commentf(out))

	// Attach the container to other networks
	for _, nw := range nws {
		out, err = d.Cmd("network", "create", nw)
		c.Assert(err, checker.IsNil, check.Commentf(out))
		out, err = d.Cmd("network", "connect", nw, cName)
		c.Assert(err, checker.IsNil, check.Commentf(out))
	}
}

func verifyContainerIsConnectedToNetworks(c *check.C, d *Daemon, cName string, nws []string) {
	// Verify container is connected to all the networks
	for _, nw := range nws {
		out, err := d.Cmd("inspect", "-f", fmt.Sprintf("{{.NetworkSettings.Networks.%s}}", nw), cName)
		c.Assert(err, checker.IsNil, check.Commentf(out))
		c.Assert(out, checker.Not(checker.Equals), "<no value>\n")
	}
}

func (s *DockerNetworkSuite) TestDockerNetworkMultipleNetworksGracefulDaemonRestart(c *check.C) {
	cName := "bb"
	nwList := []string{"nw1", "nw2", "nw3"}

	s.d.StartWithBusybox()

	connectContainerToNetworks(c, s.d, cName, nwList)
	verifyContainerIsConnectedToNetworks(c, s.d, cName, nwList)

	// Reload daemon
	s.d.Restart()

	_, err := s.d.Cmd("start", cName)
	c.Assert(err, checker.IsNil)

	verifyContainerIsConnectedToNetworks(c, s.d, cName, nwList)
}

func (s *DockerNetworkSuite) TestDockerNetworkMultipleNetworksUngracefulDaemonRestart(c *check.C) {
	cName := "cc"
	nwList := []string{"nw1", "nw2", "nw3"}

	s.d.StartWithBusybox()

	connectContainerToNetworks(c, s.d, cName, nwList)
	verifyContainerIsConnectedToNetworks(c, s.d, cName, nwList)

	// Kill daemon and restart
	if err := s.d.cmd.Process.Kill(); err != nil {
		c.Fatal(err)
	}
	s.d.Restart()

	// Restart container
	_, err := s.d.Cmd("start", cName)
	c.Assert(err, checker.IsNil)

	verifyContainerIsConnectedToNetworks(c, s.d, cName, nwList)
}

func (s *DockerNetworkSuite) TestDockerNetworkRunNetByID(c *check.C) {
	out, _ := dockerCmd(c, "network", "create", "one")
	containerOut, _, err := dockerCmdWithError("run", "-d", "--net", strings.TrimSpace(out), "busybox", "top")
	c.Assert(err, checker.IsNil, check.Commentf(containerOut))
}

func (s *DockerNetworkSuite) TestDockerNetworkHostModeUngracefulDaemonRestart(c *check.C) {
	testRequires(c, DaemonIsLinux, NotUserNamespace)
	s.d.StartWithBusybox()

	// Run a few containers on host network
	for i := 0; i < 10; i++ {
		cName := fmt.Sprintf("hostc-%d", i)
		out, err := s.d.Cmd("run", "-d", "--name", cName, "--net=host", "--restart=always", "busybox", "top")
		c.Assert(err, checker.IsNil, check.Commentf(out))

		// verfiy container has finished starting before killing daemon
		err = s.d.waitRun(cName)
		c.Assert(err, checker.IsNil)
	}

	// Kill daemon ungracefully and restart
	if err := s.d.cmd.Process.Kill(); err != nil {
		c.Fatal(err)
	}
	if err := s.d.Restart(); err != nil {
		c.Fatal(err)
	}

	// make sure all the containers are up and running
	for i := 0; i < 10; i++ {
		err := s.d.waitRun(fmt.Sprintf("hostc-%d", i))
		c.Assert(err, checker.IsNil)
	}
}

func (s *DockerNetworkSuite) TestDockerNetworkConnectToHostFromOtherNetwork(c *check.C) {
	dockerCmd(c, "run", "-d", "--name", "container1", "busybox", "top")
	c.Assert(waitRun("container1"), check.IsNil)
	dockerCmd(c, "network", "disconnect", "bridge", "container1")
	out, _, err := dockerCmdWithError("network", "connect", "host", "container1")
	c.Assert(err, checker.NotNil, check.Commentf(out))
	c.Assert(out, checker.Contains, runconfig.ErrConflictHostNetwork.Error())
}

func (s *DockerNetworkSuite) TestDockerNetworkDisconnectFromHost(c *check.C) {
	dockerCmd(c, "run", "-d", "--name", "container1", "--net=host", "busybox", "top")
	c.Assert(waitRun("container1"), check.IsNil)
	out, _, err := dockerCmdWithError("network", "disconnect", "host", "container1")
	c.Assert(err, checker.NotNil, check.Commentf("Should err out disconnect from host"))
	c.Assert(out, checker.Contains, runconfig.ErrConflictHostNetwork.Error())
}

func (s *DockerNetworkSuite) TestDockerNetworkConnectWithPortMapping(c *check.C) {
	testRequires(c, NotArm)
	dockerCmd(c, "network", "create", "test1")
	dockerCmd(c, "run", "-d", "--name", "c1", "-p", "5000:5000", "busybox", "top")
	c.Assert(waitRun("c1"), check.IsNil)
	dockerCmd(c, "network", "connect", "test1", "c1")
}

func (s *DockerNetworkSuite) TestDockerNetworkConnectWithMac(c *check.C) {
	macAddress := "02:42:ac:11:00:02"
	dockerCmd(c, "network", "create", "mynetwork")
	dockerCmd(c, "run", "--name=test", "-d", "--mac-address", macAddress, "busybox", "top")
	c.Assert(waitRun("test"), check.IsNil)
	mac1 := inspectField(c, "test", "NetworkSettings.Networks.bridge.MacAddress")
	c.Assert(strings.TrimSpace(mac1), checker.Equals, macAddress)
	dockerCmd(c, "network", "connect", "mynetwork", "test")
	mac2 := inspectField(c, "test", "NetworkSettings.Networks.mynetwork.MacAddress")
	c.Assert(strings.TrimSpace(mac2), checker.Not(checker.Equals), strings.TrimSpace(mac1))
}

func (s *DockerNetworkSuite) TestDockerNetworkInspectCreatedContainer(c *check.C) {
	dockerCmd(c, "create", "--name", "test", "busybox")
	networks := inspectField(c, "test", "NetworkSettings.Networks")
	c.Assert(networks, checker.Contains, "bridge", check.Commentf("Should return 'bridge' network"))
}

func (s *DockerNetworkSuite) TestDockerNetworkRestartWithMultipleNetworks(c *check.C) {
	dockerCmd(c, "network", "create", "test")
	dockerCmd(c, "run", "--name=foo", "-d", "busybox", "top")
	c.Assert(waitRun("foo"), checker.IsNil)
	dockerCmd(c, "network", "connect", "test", "foo")
	dockerCmd(c, "restart", "foo")
	networks := inspectField(c, "foo", "NetworkSettings.Networks")
	c.Assert(networks, checker.Contains, "bridge", check.Commentf("Should contain 'bridge' network"))
	c.Assert(networks, checker.Contains, "test", check.Commentf("Should contain 'test' network"))
}

func (s *DockerNetworkSuite) TestDockerNetworkConnectDisconnectToStoppedContainer(c *check.C) {
	dockerCmd(c, "network", "create", "test")
	dockerCmd(c, "create", "--name=foo", "busybox", "top")
	dockerCmd(c, "network", "connect", "test", "foo")
	networks := inspectField(c, "foo", "NetworkSettings.Networks")
	c.Assert(networks, checker.Contains, "test", check.Commentf("Should contain 'test' network"))

	// Restart docker daemon to test the config has persisted to disk
	s.d.Restart()
	networks = inspectField(c, "foo", "NetworkSettings.Networks")
	c.Assert(networks, checker.Contains, "test", check.Commentf("Should contain 'test' network"))

	// start the container and test if we can ping it from another container in the same network
	dockerCmd(c, "start", "foo")
	c.Assert(waitRun("foo"), checker.IsNil)
	ip := inspectField(c, "foo", "NetworkSettings.Networks.test.IPAddress")
	ip = strings.TrimSpace(ip)
	dockerCmd(c, "run", "--net=test", "busybox", "sh", "-c", fmt.Sprintf("ping -c 1 %s", ip))

	dockerCmd(c, "stop", "foo")

	// Test disconnect
	dockerCmd(c, "network", "disconnect", "test", "foo")
	networks = inspectField(c, "foo", "NetworkSettings.Networks")
	c.Assert(networks, checker.Not(checker.Contains), "test", check.Commentf("Should not contain 'test' network"))

	// Restart docker daemon to test the config has persisted to disk
	s.d.Restart()
	networks = inspectField(c, "foo", "NetworkSettings.Networks")
	c.Assert(networks, checker.Not(checker.Contains), "test", check.Commentf("Should not contain 'test' network"))

}

func (s *DockerNetworkSuite) TestDockerNetworkConnectPreferredIP(c *check.C) {
	// create two networks
	dockerCmd(c, "network", "create", "--subnet=172.28.0.0/16", "--subnet=2001:db8:1234::/64", "n0")
	assertNwIsAvailable(c, "n0")

	dockerCmd(c, "network", "create", "--subnet=172.30.0.0/16", "--ip-range=172.30.5.0/24", "--subnet=2001:db8:abcd::/64", "--ip-range=2001:db8:abcd::/80", "n1")
	assertNwIsAvailable(c, "n1")

	// run a container on first network specifying the ip addresses
	dockerCmd(c, "run", "-d", "--name", "c0", "--net=n0", "--ip", "172.28.99.88", "--ip6", "2001:db8:1234::9988", "busybox", "top")
	c.Assert(waitRun("c0"), check.IsNil)
	verifyIPAddressConfig(c, "c0", "n0", "172.28.99.88", "2001:db8:1234::9988")
	verifyIPAddresses(c, "c0", "n0", "172.28.99.88", "2001:db8:1234::9988")

	// connect the container to the second network specifying an ip addresses
	dockerCmd(c, "network", "connect", "--ip", "172.30.55.44", "--ip6", "2001:db8:abcd::5544", "n1", "c0")
	verifyIPAddressConfig(c, "c0", "n1", "172.30.55.44", "2001:db8:abcd::5544")
	verifyIPAddresses(c, "c0", "n1", "172.30.55.44", "2001:db8:abcd::5544")

	// Stop and restart the container
	dockerCmd(c, "stop", "c0")
	dockerCmd(c, "start", "c0")

	// verify requested addresses are applied and configs are still there
	verifyIPAddressConfig(c, "c0", "n0", "172.28.99.88", "2001:db8:1234::9988")
	verifyIPAddresses(c, "c0", "n0", "172.28.99.88", "2001:db8:1234::9988")
	verifyIPAddressConfig(c, "c0", "n1", "172.30.55.44", "2001:db8:abcd::5544")
	verifyIPAddresses(c, "c0", "n1", "172.30.55.44", "2001:db8:abcd::5544")

	// Still it should fail to connect to the default network with a specified IP (whatever ip)
	out, _, err := dockerCmdWithError("network", "connect", "--ip", "172.21.55.44", "bridge", "c0")
	c.Assert(err, checker.NotNil, check.Commentf("out: %s", out))
	c.Assert(out, checker.Contains, runconfig.ErrUnsupportedNetworkAndIP.Error())

}

func (s *DockerNetworkSuite) TestDockerNetworkConnectPreferredIPStoppedContainer(c *check.C) {
	// create a container
	dockerCmd(c, "create", "--name", "c0", "busybox", "top")

	// create a network
	dockerCmd(c, "network", "create", "--subnet=172.30.0.0/16", "--subnet=2001:db8:abcd::/64", "n0")
	assertNwIsAvailable(c, "n0")

	// connect the container to the network specifying an ip addresses
	dockerCmd(c, "network", "connect", "--ip", "172.30.55.44", "--ip6", "2001:db8:abcd::5544", "n0", "c0")
	verifyIPAddressConfig(c, "c0", "n0", "172.30.55.44", "2001:db8:abcd::5544")

	// start the container, verify config has not changed and ip addresses are assigned
	dockerCmd(c, "start", "c0")
	c.Assert(waitRun("c0"), check.IsNil)
	verifyIPAddressConfig(c, "c0", "n0", "172.30.55.44", "2001:db8:abcd::5544")
	verifyIPAddresses(c, "c0", "n0", "172.30.55.44", "2001:db8:abcd::5544")

	// stop the container and check ip config has not changed
	dockerCmd(c, "stop", "c0")
	verifyIPAddressConfig(c, "c0", "n0", "172.30.55.44", "2001:db8:abcd::5544")
}

func (s *DockerNetworkSuite) TestDockerNetworkUnsupportedRequiredIP(c *check.C) {
	// requested IP is not supported on predefined networks
	for _, mode := range []string{"none", "host", "bridge", "default"} {
		checkUnsupportedNetworkAndIP(c, mode)
	}

	// requested IP is not supported on networks with no user defined subnets
	dockerCmd(c, "network", "create", "n0")
	assertNwIsAvailable(c, "n0")

	out, _, err := dockerCmdWithError("run", "-d", "--ip", "172.28.99.88", "--net", "n0", "busybox", "top")
	c.Assert(err, checker.NotNil, check.Commentf("out: %s", out))
	c.Assert(out, checker.Contains, runconfig.ErrUnsupportedNetworkNoSubnetAndIP.Error())

	out, _, err = dockerCmdWithError("run", "-d", "--ip6", "2001:db8:1234::9988", "--net", "n0", "busybox", "top")
	c.Assert(err, checker.NotNil, check.Commentf("out: %s", out))
	c.Assert(out, checker.Contains, runconfig.ErrUnsupportedNetworkNoSubnetAndIP.Error())

	dockerCmd(c, "network", "rm", "n0")
	assertNwNotAvailable(c, "n0")
}

func checkUnsupportedNetworkAndIP(c *check.C, nwMode string) {
	out, _, err := dockerCmdWithError("run", "-d", "--net", nwMode, "--ip", "172.28.99.88", "--ip6", "2001:db8:1234::9988", "busybox", "top")
	c.Assert(err, checker.NotNil, check.Commentf("out: %s", out))
	c.Assert(out, checker.Contains, runconfig.ErrUnsupportedNetworkAndIP.Error())
}

func verifyIPAddressConfig(c *check.C, cName, nwname, ipv4, ipv6 string) {
	if ipv4 != "" {
		out := inspectField(c, cName, fmt.Sprintf("NetworkSettings.Networks.%s.IPAMConfig.IPv4Address", nwname))
		c.Assert(strings.TrimSpace(out), check.Equals, ipv4)
	}

	if ipv6 != "" {
		out := inspectField(c, cName, fmt.Sprintf("NetworkSettings.Networks.%s.IPAMConfig.IPv6Address", nwname))
		c.Assert(strings.TrimSpace(out), check.Equals, ipv6)
	}
}

func verifyIPAddresses(c *check.C, cName, nwname, ipv4, ipv6 string) {
	out := inspectField(c, cName, fmt.Sprintf("NetworkSettings.Networks.%s.IPAddress", nwname))
	c.Assert(strings.TrimSpace(out), check.Equals, ipv4)

	out = inspectField(c, cName, fmt.Sprintf("NetworkSettings.Networks.%s.GlobalIPv6Address", nwname))
	c.Assert(strings.TrimSpace(out), check.Equals, ipv6)
}

func (s *DockerSuite) TestUserDefinedNetworkConnectDisconnectLink(c *check.C) {
	testRequires(c, DaemonIsLinux, NotUserNamespace, NotArm)
	dockerCmd(c, "network", "create", "-d", "bridge", "foo1")
	dockerCmd(c, "network", "create", "-d", "bridge", "foo2")

	dockerCmd(c, "run", "-d", "--net=foo1", "--name=first", "busybox", "top")
	c.Assert(waitRun("first"), check.IsNil)

	// run a container in a user-defined network with a link for an existing container
	// and a link for a container that doesn't exist
	dockerCmd(c, "run", "-d", "--net=foo1", "--name=second", "--link=first:FirstInFoo1",
		"--link=third:bar", "busybox", "top")
	c.Assert(waitRun("second"), check.IsNil)

	// ping to first and its alias FirstInFoo1 must succeed
	_, _, err := dockerCmdWithError("exec", "second", "ping", "-c", "1", "first")
	c.Assert(err, check.IsNil)
	_, _, err = dockerCmdWithError("exec", "second", "ping", "-c", "1", "FirstInFoo1")
	c.Assert(err, check.IsNil)

	// connect first container to foo2 network
	dockerCmd(c, "network", "connect", "foo2", "first")
	// connect second container to foo2 network with a different alias for first container
	dockerCmd(c, "network", "connect", "--link=first:FirstInFoo2", "foo2", "second")

	// ping the new alias in network foo2
	_, _, err = dockerCmdWithError("exec", "second", "ping", "-c", "1", "FirstInFoo2")
	c.Assert(err, check.IsNil)

	// disconnect first container from foo1 network
	dockerCmd(c, "network", "disconnect", "foo1", "first")

	// link in foo1 network must fail
	_, _, err = dockerCmdWithError("exec", "second", "ping", "-c", "1", "FirstInFoo1")
	c.Assert(err, check.NotNil)

	// link in foo2 network must succeed
	_, _, err = dockerCmdWithError("exec", "second", "ping", "-c", "1", "FirstInFoo2")
	c.Assert(err, check.IsNil)
}

// #19100 This is a deprecated feature test, it should be removed in Docker 1.12
func (s *DockerNetworkSuite) TestDockerNetworkStartAPIWithHostconfig(c *check.C) {
	netName := "test"
	conName := "foo"
	dockerCmd(c, "network", "create", netName)
	dockerCmd(c, "create", "--name", conName, "busybox", "top")

	config := map[string]interface{}{
		"HostConfig": map[string]interface{}{
			"NetworkMode": netName,
		},
	}
	_, _, err := sockRequest("POST", "/containers/"+conName+"/start", config)
	c.Assert(err, checker.IsNil)
	c.Assert(waitRun(conName), checker.IsNil)
	networks := inspectField(c, conName, "NetworkSettings.Networks")
	c.Assert(networks, checker.Contains, netName, check.Commentf(fmt.Sprintf("Should contain '%s' network", netName)))
	c.Assert(networks, checker.Not(checker.Contains), "bridge", check.Commentf("Should not contain 'bridge' network"))
}

func (s *DockerNetworkSuite) TestDockerNetworkDisconnectDefault(c *check.C) {
	netWorkName1 := "test1"
	netWorkName2 := "test2"
	containerName := "foo"

	dockerCmd(c, "network", "create", netWorkName1)
	dockerCmd(c, "network", "create", netWorkName2)
	dockerCmd(c, "create", "--name", containerName, "busybox", "top")
	dockerCmd(c, "network", "connect", netWorkName1, containerName)
	dockerCmd(c, "network", "connect", netWorkName2, containerName)
	dockerCmd(c, "network", "disconnect", "bridge", containerName)

	dockerCmd(c, "start", containerName)
	c.Assert(waitRun(containerName), checker.IsNil)
	networks := inspectField(c, containerName, "NetworkSettings.Networks")
	c.Assert(networks, checker.Contains, netWorkName1, check.Commentf(fmt.Sprintf("Should contain '%s' network", netWorkName1)))
	c.Assert(networks, checker.Contains, netWorkName2, check.Commentf(fmt.Sprintf("Should contain '%s' network", netWorkName2)))
	c.Assert(networks, checker.Not(checker.Contains), "bridge", check.Commentf("Should not contain 'bridge' network"))
}

func (s *DockerSuite) TestUserDefinedNetworkConnectDisconnectAlias(c *check.C) {
	testRequires(c, DaemonIsLinux, NotUserNamespace, NotArm)
	dockerCmd(c, "network", "create", "-d", "bridge", "net1")
	dockerCmd(c, "network", "create", "-d", "bridge", "net2")

	dockerCmd(c, "run", "-d", "--net=net1", "--name=first", "--net-alias=foo", "busybox", "top")
	c.Assert(waitRun("first"), check.IsNil)

	dockerCmd(c, "run", "-d", "--net=net1", "--name=second", "busybox", "top")
	c.Assert(waitRun("second"), check.IsNil)

	// ping first container and its alias
	_, _, err := dockerCmdWithError("exec", "second", "ping", "-c", "1", "first")
	c.Assert(err, check.IsNil)
	_, _, err = dockerCmdWithError("exec", "second", "ping", "-c", "1", "foo")
	c.Assert(err, check.IsNil)

	// connect first container to net2 network
	dockerCmd(c, "network", "connect", "--alias=bar", "net2", "first")
	// connect second container to foo2 network with a different alias for first container
	dockerCmd(c, "network", "connect", "net2", "second")

	// ping the new alias in network foo2
	_, _, err = dockerCmdWithError("exec", "second", "ping", "-c", "1", "bar")
	c.Assert(err, check.IsNil)

	// disconnect first container from net1 network
	dockerCmd(c, "network", "disconnect", "net1", "first")

	// ping to net1 scoped alias "foo" must fail
	_, _, err = dockerCmdWithError("exec", "second", "ping", "-c", "1", "foo")
	c.Assert(err, check.NotNil)

	// ping to net2 scoped alias "bar" must still succeed
	_, _, err = dockerCmdWithError("exec", "second", "ping", "-c", "1", "bar")
	c.Assert(err, check.IsNil)

	// verify the alias option is rejected when running on predefined network
	out, _, err := dockerCmdWithError("run", "--rm", "--name=any", "--net-alias=any", "busybox", "top")
	c.Assert(err, checker.NotNil, check.Commentf("out: %s", out))
	c.Assert(out, checker.Contains, runconfig.ErrUnsupportedNetworkAndAlias.Error())

	// verify the alias option is rejected when connecting to predefined network
	out, _, err = dockerCmdWithError("network", "connect", "--alias=any", "bridge", "first")
	c.Assert(err, checker.NotNil, check.Commentf("out: %s", out))
	c.Assert(out, checker.Contains, runconfig.ErrUnsupportedNetworkAndAlias.Error())
}

func (s *DockerSuite) TestUserDefinedNetworkConnectivity(c *check.C) {
	testRequires(c, DaemonIsLinux, NotUserNamespace)
	dockerCmd(c, "network", "create", "-d", "bridge", "br.net1")

	dockerCmd(c, "run", "-d", "--net=br.net1", "--name=c1.net1", "busybox", "top")
	c.Assert(waitRun("c1.net1"), check.IsNil)

	dockerCmd(c, "run", "-d", "--net=br.net1", "--name=c2.net1", "busybox", "top")
	c.Assert(waitRun("c2.net1"), check.IsNil)

	// ping first container by its unqualified name
	_, _, err := dockerCmdWithError("exec", "c2.net1", "ping", "-c", "1", "c1.net1")
	c.Assert(err, check.IsNil)

	// ping first container by its qualified name
	_, _, err = dockerCmdWithError("exec", "c2.net1", "ping", "-c", "1", "c1.net1.br.net1")
	c.Assert(err, check.IsNil)

	// ping with first qualified name masked by an additional domain. should fail
	_, _, err = dockerCmdWithError("exec", "c2.net1", "ping", "-c", "1", "c1.net1.br.net1.google.com")
	c.Assert(err, check.NotNil)
}

func (s *DockerSuite) TestEmbeddedDNSInvalidInput(c *check.C) {
	testRequires(c, DaemonIsLinux, NotUserNamespace)
	dockerCmd(c, "network", "create", "-d", "bridge", "nw1")

	// Sending garbage to embedded DNS shouldn't crash the daemon
	dockerCmd(c, "run", "-i", "--net=nw1", "--name=c1", "debian:jessie", "bash", "-c", "echo InvalidQuery > /dev/udp/127.0.0.11/53")
}

func (s *DockerSuite) TestDockerNetworkConnectFailsNoInspectChange(c *check.C) {
	dockerCmd(c, "run", "-d", "--name=bb", "busybox", "top")
	c.Assert(waitRun("bb"), check.IsNil)

	ns0 := inspectField(c, "bb", "NetworkSettings.Networks.bridge")

	// A failing redundant network connect should not alter current container's endpoint settings
	_, _, err := dockerCmdWithError("network", "connect", "bridge", "bb")
	c.Assert(err, check.NotNil)

	ns1 := inspectField(c, "bb", "NetworkSettings.Networks.bridge")
	c.Assert(ns1, check.Equals, ns0)
}

func (s *DockerNetworkSuite) TestDockerNetworkInternalMode(c *check.C) {
	dockerCmd(c, "network", "create", "--driver=bridge", "--internal", "internal")
	assertNwIsAvailable(c, "internal")
	nr := getNetworkResource(c, "internal")
	c.Assert(nr.Internal, checker.True)

	dockerCmd(c, "run", "-d", "--net=internal", "--name=first", "busybox", "top")
	c.Assert(waitRun("first"), check.IsNil)
	dockerCmd(c, "run", "-d", "--net=internal", "--name=second", "busybox", "top")
	c.Assert(waitRun("second"), check.IsNil)
	_, _, err := dockerCmdWithError("exec", "first", "ping", "-c", "1", "www.google.com")
	c.Assert(err, check.NotNil)
	_, _, err = dockerCmdWithError("exec", "second", "ping", "-c", "1", "first")
	c.Assert(err, check.IsNil)
}
