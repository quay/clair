package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/opts"
	"github.com/docker/docker/pkg/httputils"
	"github.com/docker/docker/pkg/integration"
	"github.com/docker/docker/pkg/integration/checker"
	"github.com/docker/docker/pkg/ioutils"
	"github.com/docker/docker/pkg/stringutils"
	"github.com/docker/engine-api/types"
	"github.com/docker/go-connections/sockets"
	"github.com/docker/go-connections/tlsconfig"
	"github.com/docker/go-units"
	"github.com/go-check/check"
)

func init() {
	cmd := exec.Command(dockerBinary, "images")
	cmd.Env = appendBaseEnv(true)
	fmt.Println("foobar", cmd.Env)
	out, err := cmd.CombinedOutput()
	if err != nil {
		panic(fmt.Errorf("err=%v\nout=%s\n", err, out))
	}
	lines := strings.Split(string(out), "\n")[1:]
	for _, l := range lines {
		if l == "" {
			continue
		}
		fields := strings.Fields(l)
		imgTag := fields[0] + ":" + fields[1]
		// just for case if we have dangling images in tested daemon
		if imgTag != "<none>:<none>" {
			protectedImages[imgTag] = struct{}{}
		}
	}

	// Obtain the daemon platform so that it can be used by tests to make
	// intelligent decisions about how to configure themselves, and validate
	// that the target platform is valid.
	res, _, err := sockRequestRaw("GET", "/version", nil, "application/json")
	if err != nil || res == nil || (res != nil && res.StatusCode != http.StatusOK) {
		panic(fmt.Errorf("Init failed to get version: %v. Res=%v", err.Error(), res))
	}
	svrHeader, _ := httputils.ParseServerHeader(res.Header.Get("Server"))
	daemonPlatform = svrHeader.OS
	if daemonPlatform != "linux" && daemonPlatform != "windows" {
		panic("Cannot run tests against platform: " + daemonPlatform)
	}

	// On Windows, extract out the version as we need to make selective
	// decisions during integration testing as and when features are implemented.
	if daemonPlatform == "windows" {
		if body, err := ioutil.ReadAll(res.Body); err == nil {
			var server types.Version
			if err := json.Unmarshal(body, &server); err == nil {
				// eg in "10.0 10550 (10550.1000.amd64fre.branch.date-time)" we want 10550
				windowsDaemonKV, _ = strconv.Atoi(strings.Split(server.KernelVersion, " ")[1])
			}
		}
	}

	// Now we know the daemon platform, can set paths used by tests.
	_, body, err := sockRequest("GET", "/info", nil)
	if err != nil {
		panic(err)
	}

	var info types.Info
	err = json.Unmarshal(body, &info)
	dockerBasePath = info.DockerRootDir
	volumesConfigPath = filepath.Join(dockerBasePath, "volumes")
	containerStoragePath = filepath.Join(dockerBasePath, "containers")
	// Make sure in context of daemon, not the local platform. Note we can't
	// use filepath.FromSlash or ToSlash here as they are a no-op on Unix.
	if daemonPlatform == "windows" {
		volumesConfigPath = strings.Replace(volumesConfigPath, `/`, `\`, -1)
		containerStoragePath = strings.Replace(containerStoragePath, `/`, `\`, -1)
	} else {
		volumesConfigPath = strings.Replace(volumesConfigPath, `\`, `/`, -1)
		containerStoragePath = strings.Replace(containerStoragePath, `\`, `/`, -1)
	}
}

// Daemon represents a Docker daemon for the testing framework.
type Daemon struct {
	// Defaults to "daemon"
	// Useful to set to --daemon or -d for checking backwards compatibility
	Command     string
	GlobalFlags []string

	id                string
	c                 *check.C
	logFile           *os.File
	folder            string
	root              string
	stdin             io.WriteCloser
	stdout, stderr    io.ReadCloser
	cmd               *exec.Cmd
	storageDriver     string
	wait              chan error
	userlandProxy     bool
	useDefaultHost    bool
	useDefaultTLSHost bool
}

type clientConfig struct {
	transport *http.Transport
	scheme    string
	addr      string
}

// NewDaemon returns a Daemon instance to be used for testing.
// This will create a directory such as d123456789 in the folder specified by $DEST.
// The daemon will not automatically start.
func NewDaemon(c *check.C) *Daemon {
	dest := os.Getenv("DEST")
	c.Assert(dest, check.Not(check.Equals), "", check.Commentf("Please set the DEST environment variable"))

	id := fmt.Sprintf("d%d", time.Now().UnixNano()%100000000)
	dir := filepath.Join(dest, id)
	daemonFolder, err := filepath.Abs(dir)
	c.Assert(err, check.IsNil, check.Commentf("Could not make %q an absolute path", dir))
	daemonRoot := filepath.Join(daemonFolder, "root")

	c.Assert(os.MkdirAll(daemonRoot, 0755), check.IsNil, check.Commentf("Could not create daemon root %q", dir))

	userlandProxy := true
	if env := os.Getenv("DOCKER_USERLANDPROXY"); env != "" {
		if val, err := strconv.ParseBool(env); err != nil {
			userlandProxy = val
		}
	}

	return &Daemon{
		Command:       "daemon",
		id:            id,
		c:             c,
		folder:        daemonFolder,
		root:          daemonRoot,
		storageDriver: os.Getenv("DOCKER_GRAPHDRIVER"),
		userlandProxy: userlandProxy,
	}
}

func (d *Daemon) getClientConfig() (*clientConfig, error) {
	var (
		transport *http.Transport
		scheme    string
		addr      string
		proto     string
	)
	if d.useDefaultTLSHost {
		option := &tlsconfig.Options{
			CAFile:   "fixtures/https/ca.pem",
			CertFile: "fixtures/https/client-cert.pem",
			KeyFile:  "fixtures/https/client-key.pem",
		}
		tlsConfig, err := tlsconfig.Client(*option)
		if err != nil {
			return nil, err
		}
		transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
		addr = fmt.Sprintf("%s:%d", opts.DefaultHTTPHost, opts.DefaultTLSHTTPPort)
		scheme = "https"
		proto = "tcp"
	} else if d.useDefaultHost {
		addr = opts.DefaultUnixSocket
		proto = "unix"
		scheme = "http"
		transport = &http.Transport{}
	} else {
		addr = filepath.Join(d.folder, "docker.sock")
		proto = "unix"
		scheme = "http"
		transport = &http.Transport{}
	}

	d.c.Assert(sockets.ConfigureTransport(transport, proto, addr), check.IsNil)

	return &clientConfig{
		transport: transport,
		scheme:    scheme,
		addr:      addr,
	}, nil
}

// Start will start the daemon and return once it is ready to receive requests.
// You can specify additional daemon flags.
func (d *Daemon) Start(args ...string) error {
	logFile, err := os.OpenFile(filepath.Join(d.folder, "docker.log"), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	d.c.Assert(err, check.IsNil, check.Commentf("[%s] Could not create %s/docker.log", d.id, d.folder))

	return d.StartWithLogFile(logFile, args...)
}

// StartWithLogFile will start the daemon and attach its streams to a given file.
func (d *Daemon) StartWithLogFile(out *os.File, providedArgs ...string) error {
	dockerBinary, err := exec.LookPath(dockerBinary)
	d.c.Assert(err, check.IsNil, check.Commentf("[%s] could not find docker binary in $PATH", d.id))

	args := append(d.GlobalFlags,
		d.Command,
		"--graph", d.root,
		"--pidfile", fmt.Sprintf("%s/docker.pid", d.folder),
		fmt.Sprintf("--userland-proxy=%t", d.userlandProxy),
	)
	if !(d.useDefaultHost || d.useDefaultTLSHost) {
		args = append(args, []string{"--host", d.sock()}...)
	}
	if root := os.Getenv("DOCKER_REMAP_ROOT"); root != "" {
		args = append(args, []string{"--userns-remap", root}...)
	}

	// If we don't explicitly set the log-level or debug flag(-D) then
	// turn on debug mode
	foundLog := false
	foundSd := false
	for _, a := range providedArgs {
		if strings.Contains(a, "--log-level") || strings.Contains(a, "-D") || strings.Contains(a, "--debug") {
			foundLog = true
		}
		if strings.Contains(a, "--storage-driver") {
			foundSd = true
		}
	}
	if !foundLog {
		args = append(args, "--debug")
	}
	if d.storageDriver != "" && !foundSd {
		args = append(args, "--storage-driver", d.storageDriver)
	}

	args = append(args, providedArgs...)
	d.cmd = exec.Command(dockerBinary, args...)

	d.cmd.Stdout = out
	d.cmd.Stderr = out
	d.logFile = out

	if err := d.cmd.Start(); err != nil {
		return fmt.Errorf("[%s] could not start daemon container: %v", d.id, err)
	}

	wait := make(chan error)

	go func() {
		wait <- d.cmd.Wait()
		d.c.Logf("[%s] exiting daemon", d.id)
		close(wait)
	}()

	d.wait = wait

	tick := time.Tick(500 * time.Millisecond)
	// make sure daemon is ready to receive requests
	startTime := time.Now().Unix()
	for {
		d.c.Logf("[%s] waiting for daemon to start", d.id)
		if time.Now().Unix()-startTime > 5 {
			// After 5 seconds, give up
			return fmt.Errorf("[%s] Daemon exited and never started", d.id)
		}
		select {
		case <-time.After(2 * time.Second):
			return fmt.Errorf("[%s] timeout: daemon does not respond", d.id)
		case <-tick:
			clientConfig, err := d.getClientConfig()
			if err != nil {
				return err
			}

			client := &http.Client{
				Transport: clientConfig.transport,
			}

			req, err := http.NewRequest("GET", "/_ping", nil)
			d.c.Assert(err, check.IsNil, check.Commentf("[%s] could not create new request", d.id))
			req.URL.Host = clientConfig.addr
			req.URL.Scheme = clientConfig.scheme
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			if resp.StatusCode != http.StatusOK {
				d.c.Logf("[%s] received status != 200 OK: %s", d.id, resp.Status)
			}
			d.c.Logf("[%s] daemon started", d.id)
			d.root, err = d.queryRootDir()
			if err != nil {
				return fmt.Errorf("[%s] error querying daemon for root directory: %v", d.id, err)
			}
			return nil
		}
	}
}

// StartWithBusybox will first start the daemon with Daemon.Start()
// then save the busybox image from the main daemon and load it into this Daemon instance.
func (d *Daemon) StartWithBusybox(arg ...string) error {
	if err := d.Start(arg...); err != nil {
		return err
	}
	return d.LoadBusybox()
}

// Stop will send a SIGINT every second and wait for the daemon to stop.
// If it timeouts, a SIGKILL is sent.
// Stop will not delete the daemon directory. If a purged daemon is needed,
// instantiate a new one with NewDaemon.
func (d *Daemon) Stop() error {
	if d.cmd == nil || d.wait == nil {
		return errors.New("daemon not started")
	}

	defer func() {
		d.logFile.Close()
		d.cmd = nil
	}()

	i := 1
	tick := time.Tick(time.Second)

	if err := d.cmd.Process.Signal(os.Interrupt); err != nil {
		return fmt.Errorf("could not send signal: %v", err)
	}
out1:
	for {
		select {
		case err := <-d.wait:
			return err
		case <-time.After(15 * time.Second):
			// time for stopping jobs and run onShutdown hooks
			d.c.Log("timeout")
			break out1
		}
	}

out2:
	for {
		select {
		case err := <-d.wait:
			return err
		case <-tick:
			i++
			if i > 4 {
				d.c.Logf("tried to interrupt daemon for %d times, now try to kill it", i)
				break out2
			}
			d.c.Logf("Attempt #%d: daemon is still running with pid %d", i, d.cmd.Process.Pid)
			if err := d.cmd.Process.Signal(os.Interrupt); err != nil {
				return fmt.Errorf("could not send signal: %v", err)
			}
		}
	}

	if err := d.cmd.Process.Kill(); err != nil {
		d.c.Logf("Could not kill daemon: %v", err)
		return err
	}

	return nil
}

// Restart will restart the daemon by first stopping it and then starting it.
func (d *Daemon) Restart(arg ...string) error {
	d.Stop()
	// in the case of tests running a user namespace-enabled daemon, we have resolved
	// d.root to be the actual final path of the graph dir after the "uid.gid" of
	// remapped root is added--we need to subtract it from the path before calling
	// start or else we will continue making subdirectories rather than truly restarting
	// with the same location/root:
	if root := os.Getenv("DOCKER_REMAP_ROOT"); root != "" {
		d.root = filepath.Dir(d.root)
	}
	return d.Start(arg...)
}

// LoadBusybox will load the stored busybox into a newly started daemon
func (d *Daemon) LoadBusybox() error {
	bb := filepath.Join(d.folder, "busybox.tar")
	if _, err := os.Stat(bb); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("unexpected error on busybox.tar stat: %v", err)
		}
		// saving busybox image from main daemon
		if err := exec.Command(dockerBinary, "save", "--output", bb, "busybox:latest").Run(); err != nil {
			return fmt.Errorf("could not save busybox image: %v", err)
		}
	}
	// loading busybox image to this daemon
	if out, err := d.Cmd("load", "--input", bb); err != nil {
		return fmt.Errorf("could not load busybox image: %s", out)
	}
	if err := os.Remove(bb); err != nil {
		d.c.Logf("could not remove %s: %v", bb, err)
	}
	return nil
}

func (d *Daemon) queryRootDir() (string, error) {
	// update daemon root by asking /info endpoint (to support user
	// namespaced daemon with root remapped uid.gid directory)
	clientConfig, err := d.getClientConfig()
	if err != nil {
		return "", err
	}

	client := &http.Client{
		Transport: clientConfig.transport,
	}

	req, err := http.NewRequest("GET", "/info", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.URL.Host = clientConfig.addr
	req.URL.Scheme = clientConfig.scheme

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	body := ioutils.NewReadCloserWrapper(resp.Body, func() error {
		return resp.Body.Close()
	})

	type Info struct {
		DockerRootDir string
	}
	var b []byte
	var i Info
	b, err = readBody(body)
	if err == nil && resp.StatusCode == 200 {
		// read the docker root dir
		if err = json.Unmarshal(b, &i); err == nil {
			return i.DockerRootDir, nil
		}
	}
	return "", err
}

func (d *Daemon) sock() string {
	return fmt.Sprintf("unix://%s/docker.sock", d.folder)
}

func (d *Daemon) waitRun(contID string) error {
	args := []string{"--host", d.sock()}
	return waitInspectWithArgs(contID, "{{.State.Running}}", "true", 10*time.Second, args...)
}

func (d *Daemon) getBaseDeviceSize(c *check.C) int64 {
	infoCmdOutput, _, err := runCommandPipelineWithOutput(
		exec.Command(dockerBinary, "-H", d.sock(), "info"),
		exec.Command("grep", "Base Device Size"),
	)
	c.Assert(err, checker.IsNil)
	basesizeSlice := strings.Split(infoCmdOutput, ":")
	basesize := strings.Trim(basesizeSlice[1], " ")
	basesize = strings.Trim(basesize, "\n")[:len(basesize)-3]
	basesizeFloat, err := strconv.ParseFloat(strings.Trim(basesize, " "), 64)
	c.Assert(err, checker.IsNil)
	basesizeBytes := int64(basesizeFloat) * (1024 * 1024 * 1024)
	return basesizeBytes
}

func convertBasesize(basesizeBytes int64) (int64, error) {
	basesize := units.HumanSize(float64(basesizeBytes))
	basesize = strings.Trim(basesize, " ")[:len(basesize)-3]
	basesizeFloat, err := strconv.ParseFloat(strings.Trim(basesize, " "), 64)
	if err != nil {
		return 0, err
	}
	return int64(basesizeFloat) * 1024 * 1024 * 1024, nil
}

// Cmd will execute a docker CLI command against this Daemon.
// Example: d.Cmd("version") will run docker -H unix://path/to/unix.sock version
func (d *Daemon) Cmd(name string, arg ...string) (string, error) {
	args := []string{"--host", d.sock(), name}
	args = append(args, arg...)
	c := exec.Command(dockerBinary, args...)
	b, err := c.CombinedOutput()
	return string(b), err
}

// CmdWithArgs will execute a docker CLI command against a daemon with the
// given additional arguments
func (d *Daemon) CmdWithArgs(daemonArgs []string, name string, arg ...string) (string, error) {
	args := append(daemonArgs, name)
	args = append(args, arg...)
	c := exec.Command(dockerBinary, args...)
	b, err := c.CombinedOutput()
	return string(b), err
}

// LogFileName returns the path the the daemon's log file
func (d *Daemon) LogFileName() string {
	return d.logFile.Name()
}

func (d *Daemon) getIDByName(name string) (string, error) {
	return d.inspectFieldWithError(name, "Id")
}

func (d *Daemon) inspectFilter(name, filter string) (string, error) {
	format := fmt.Sprintf("{{%s}}", filter)
	out, err := d.Cmd("inspect", "-f", format, name)
	if err != nil {
		return "", fmt.Errorf("failed to inspect %s: %s", name, out)
	}
	return strings.TrimSpace(out), nil
}

func (d *Daemon) inspectFieldWithError(name, field string) (string, error) {
	return d.inspectFilter(name, fmt.Sprintf(".%s", field))
}

func daemonHost() string {
	daemonURLStr := "unix://" + opts.DefaultUnixSocket
	if daemonHostVar := os.Getenv("DOCKER_HOST"); daemonHostVar != "" {
		daemonURLStr = daemonHostVar
	}
	return daemonURLStr
}

func getTLSConfig() (*tls.Config, error) {
	dockerCertPath := os.Getenv("DOCKER_CERT_PATH")

	if dockerCertPath == "" {
		return nil, fmt.Errorf("DOCKER_TLS_VERIFY specified, but no DOCKER_CERT_PATH environment variable")
	}

	option := &tlsconfig.Options{
		CAFile:   filepath.Join(dockerCertPath, "ca.pem"),
		CertFile: filepath.Join(dockerCertPath, "cert.pem"),
		KeyFile:  filepath.Join(dockerCertPath, "key.pem"),
	}
	tlsConfig, err := tlsconfig.Client(*option)
	if err != nil {
		return nil, err
	}

	return tlsConfig, nil
}

func sockConn(timeout time.Duration) (net.Conn, error) {
	daemon := daemonHost()
	daemonURL, err := url.Parse(daemon)
	if err != nil {
		return nil, fmt.Errorf("could not parse url %q: %v", daemon, err)
	}

	var c net.Conn
	switch daemonURL.Scheme {
	case "unix":
		return net.DialTimeout(daemonURL.Scheme, daemonURL.Path, timeout)
	case "tcp":
		if os.Getenv("DOCKER_TLS_VERIFY") != "" {
			// Setup the socket TLS configuration.
			tlsConfig, err := getTLSConfig()
			if err != nil {
				return nil, err
			}
			dialer := &net.Dialer{Timeout: timeout}
			return tls.DialWithDialer(dialer, daemonURL.Scheme, daemonURL.Host, tlsConfig)
		}
		return net.DialTimeout(daemonURL.Scheme, daemonURL.Host, timeout)
	default:
		return c, fmt.Errorf("unknown scheme %v (%s)", daemonURL.Scheme, daemon)
	}
}

func sockRequest(method, endpoint string, data interface{}) (int, []byte, error) {
	jsonData := bytes.NewBuffer(nil)
	if err := json.NewEncoder(jsonData).Encode(data); err != nil {
		return -1, nil, err
	}

	res, body, err := sockRequestRaw(method, endpoint, jsonData, "application/json")
	if err != nil {
		return -1, nil, err
	}
	b, err := readBody(body)
	return res.StatusCode, b, err
}

func sockRequestRaw(method, endpoint string, data io.Reader, ct string) (*http.Response, io.ReadCloser, error) {
	req, client, err := newRequestClient(method, endpoint, data, ct)
	if err != nil {
		return nil, nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	body := ioutils.NewReadCloserWrapper(resp.Body, func() error {
		defer resp.Body.Close()
		return client.Close()
	})

	return resp, body, nil
}

func sockRequestHijack(method, endpoint string, data io.Reader, ct string) (net.Conn, *bufio.Reader, error) {
	req, client, err := newRequestClient(method, endpoint, data, ct)
	if err != nil {
		return nil, nil, err
	}

	client.Do(req)
	conn, br := client.Hijack()
	return conn, br, nil
}

func newRequestClient(method, endpoint string, data io.Reader, ct string) (*http.Request, *httputil.ClientConn, error) {
	c, err := sockConn(time.Duration(10 * time.Second))
	if err != nil {
		return nil, nil, fmt.Errorf("could not dial docker daemon: %v", err)
	}

	client := httputil.NewClientConn(c, nil)

	req, err := http.NewRequest(method, endpoint, data)
	if err != nil {
		client.Close()
		return nil, nil, fmt.Errorf("could not create new request: %v", err)
	}

	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	return req, client, nil
}

func readBody(b io.ReadCloser) ([]byte, error) {
	defer b.Close()
	return ioutil.ReadAll(b)
}

func deleteContainer(container string) error {
	container = strings.TrimSpace(strings.Replace(container, "\n", " ", -1))
	rmArgs := strings.Split(fmt.Sprintf("rm -fv %v", container), " ")
	exitCode, err := runCommand(exec.Command(dockerBinary, rmArgs...))
	// set error manually if not set
	if exitCode != 0 && err == nil {
		err = fmt.Errorf("failed to remove container: `docker rm` exit is non-zero")
	}

	return err
}

func getAllContainers() (string, error) {
	getContainersCmd := exec.Command(dockerBinary, "ps", "-q", "-a")
	out, exitCode, err := runCommandWithOutput(getContainersCmd)
	if exitCode != 0 && err == nil {
		err = fmt.Errorf("failed to get a list of containers: %v\n", out)
	}

	return out, err
}

func deleteAllContainers() error {
	containers, err := getAllContainers()
	if err != nil {
		fmt.Println(containers)
		return err
	}

	if containers != "" {
		if err = deleteContainer(containers); err != nil {
			return err
		}
	}
	return nil
}

func deleteAllNetworks() error {
	networks, err := getAllNetworks()
	if err != nil {
		return err
	}
	var errors []string
	for _, n := range networks {
		if n.Name == "bridge" || n.Name == "none" || n.Name == "host" {
			continue
		}
		status, b, err := sockRequest("DELETE", "/networks/"+n.Name, nil)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		if status != http.StatusNoContent {
			errors = append(errors, fmt.Sprintf("error deleting network %s: %s", n.Name, string(b)))
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf(strings.Join(errors, "\n"))
	}
	return nil
}

func getAllNetworks() ([]types.NetworkResource, error) {
	var networks []types.NetworkResource
	_, b, err := sockRequest("GET", "/networks", nil)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &networks); err != nil {
		return nil, err
	}
	return networks, nil
}

func deleteAllVolumes() error {
	volumes, err := getAllVolumes()
	if err != nil {
		return err
	}
	var errors []string
	for _, v := range volumes {
		status, b, err := sockRequest("DELETE", "/volumes/"+v.Name, nil)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		if status != http.StatusNoContent {
			errors = append(errors, fmt.Sprintf("error deleting volume %s: %s", v.Name, string(b)))
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf(strings.Join(errors, "\n"))
	}
	return nil
}

func getAllVolumes() ([]*types.Volume, error) {
	var volumes types.VolumesListResponse
	_, b, err := sockRequest("GET", "/volumes", nil)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &volumes); err != nil {
		return nil, err
	}
	return volumes.Volumes, nil
}

var protectedImages = map[string]struct{}{}

func deleteAllImages() error {
	cmd := exec.Command(dockerBinary, "images")
	cmd.Env = appendBaseEnv(true)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	lines := strings.Split(string(out), "\n")[1:]
	var imgs []string
	for _, l := range lines {
		if l == "" {
			continue
		}
		fields := strings.Fields(l)
		imgTag := fields[0] + ":" + fields[1]
		if _, ok := protectedImages[imgTag]; !ok {
			if fields[0] == "<none>" {
				imgs = append(imgs, fields[2])
				continue
			}
			imgs = append(imgs, imgTag)
		}
	}
	if len(imgs) == 0 {
		return nil
	}
	args := append([]string{"rmi", "-f"}, imgs...)
	if err := exec.Command(dockerBinary, args...).Run(); err != nil {
		return err
	}
	return nil
}

func getPausedContainers() (string, error) {
	getPausedContainersCmd := exec.Command(dockerBinary, "ps", "-f", "status=paused", "-q", "-a")
	out, exitCode, err := runCommandWithOutput(getPausedContainersCmd)
	if exitCode != 0 && err == nil {
		err = fmt.Errorf("failed to get a list of paused containers: %v\n", out)
	}

	return out, err
}

func getSliceOfPausedContainers() ([]string, error) {
	out, err := getPausedContainers()
	if err == nil {
		if len(out) == 0 {
			return nil, err
		}
		slice := strings.Split(strings.TrimSpace(out), "\n")
		return slice, err
	}
	return []string{out}, err
}

func unpauseContainer(container string) error {
	unpauseCmd := exec.Command(dockerBinary, "unpause", container)
	exitCode, err := runCommand(unpauseCmd)
	if exitCode != 0 && err == nil {
		err = fmt.Errorf("failed to unpause container")
	}

	return nil
}

func unpauseAllContainers() error {
	containers, err := getPausedContainers()
	if err != nil {
		fmt.Println(containers)
		return err
	}

	containers = strings.Replace(containers, "\n", " ", -1)
	containers = strings.Trim(containers, " ")
	containerList := strings.Split(containers, " ")

	for _, value := range containerList {
		if err = unpauseContainer(value); err != nil {
			return err
		}
	}

	return nil
}

func deleteImages(images ...string) error {
	args := []string{"rmi", "-f"}
	args = append(args, images...)
	rmiCmd := exec.Command(dockerBinary, args...)
	exitCode, err := runCommand(rmiCmd)
	// set error manually if not set
	if exitCode != 0 && err == nil {
		err = fmt.Errorf("failed to remove image: `docker rmi` exit is non-zero")
	}
	return err
}

func imageExists(image string) error {
	inspectCmd := exec.Command(dockerBinary, "inspect", image)
	exitCode, err := runCommand(inspectCmd)
	if exitCode != 0 && err == nil {
		err = fmt.Errorf("couldn't find image %q", image)
	}
	return err
}

func pullImageIfNotExist(image string) error {
	if err := imageExists(image); err != nil {
		pullCmd := exec.Command(dockerBinary, "pull", image)
		_, exitCode, err := runCommandWithOutput(pullCmd)

		if err != nil || exitCode != 0 {
			return fmt.Errorf("image %q wasn't found locally and it couldn't be pulled: %s", image, err)
		}
	}
	return nil
}

func dockerCmdWithError(args ...string) (string, int, error) {
	if err := validateArgs(args...); err != nil {
		return "", 0, err
	}
	return integration.DockerCmdWithError(dockerBinary, args...)
}

func dockerCmdWithStdoutStderr(c *check.C, args ...string) (string, string, int) {
	if err := validateArgs(args...); err != nil {
		c.Fatalf(err.Error())
	}
	return integration.DockerCmdWithStdoutStderr(dockerBinary, c, args...)
}

func dockerCmd(c *check.C, args ...string) (string, int) {
	if err := validateArgs(args...); err != nil {
		c.Fatalf(err.Error())
	}
	return integration.DockerCmd(dockerBinary, c, args...)
}

// execute a docker command with a timeout
func dockerCmdWithTimeout(timeout time.Duration, args ...string) (string, int, error) {
	if err := validateArgs(args...); err != nil {
		return "", 0, err
	}
	return integration.DockerCmdWithTimeout(dockerBinary, timeout, args...)
}

// execute a docker command in a directory
func dockerCmdInDir(c *check.C, path string, args ...string) (string, int, error) {
	if err := validateArgs(args...); err != nil {
		c.Fatalf(err.Error())
	}
	return integration.DockerCmdInDir(dockerBinary, path, args...)
}

// execute a docker command in a directory with a timeout
func dockerCmdInDirWithTimeout(timeout time.Duration, path string, args ...string) (string, int, error) {
	if err := validateArgs(args...); err != nil {
		return "", 0, err
	}
	return integration.DockerCmdInDirWithTimeout(dockerBinary, timeout, path, args...)
}

// validateArgs is a checker to ensure tests are not running commands which are
// not supported on platforms. Specifically on Windows this is 'busybox top'.
func validateArgs(args ...string) error {
	if daemonPlatform != "windows" {
		return nil
	}
	foundBusybox := -1
	for key, value := range args {
		if strings.ToLower(value) == "busybox" {
			foundBusybox = key
		}
		if (foundBusybox != -1) && (key == foundBusybox+1) && (strings.ToLower(value) == "top") {
			return errors.New("Cannot use 'busybox top' in tests on Windows. Use runSleepingContainer()")
		}
	}
	return nil
}

// find the State.ExitCode in container metadata
func findContainerExitCode(c *check.C, name string, vargs ...string) string {
	args := append(vargs, "inspect", "--format='{{ .State.ExitCode }} {{ .State.Error }}'", name)
	cmd := exec.Command(dockerBinary, args...)
	out, _, err := runCommandWithOutput(cmd)
	if err != nil {
		c.Fatal(err, out)
	}
	return out
}

func findContainerIP(c *check.C, id string, network string) string {
	out, _ := dockerCmd(c, "inspect", fmt.Sprintf("--format='{{ .NetworkSettings.Networks.%s.IPAddress }}'", network), id)
	return strings.Trim(out, " \r\n'")
}

func (d *Daemon) findContainerIP(id string) string {
	out, err := d.Cmd("inspect", fmt.Sprintf("--format='{{ .NetworkSettings.Networks.bridge.IPAddress }}'"), id)
	if err != nil {
		d.c.Log(err)
	}
	return strings.Trim(out, " \r\n'")
}

func getContainerCount() (int, error) {
	const containers = "Containers:"

	cmd := exec.Command(dockerBinary, "info")
	out, _, err := runCommandWithOutput(cmd)
	if err != nil {
		return 0, err
	}

	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, containers) {
			output := strings.TrimSpace(line)
			output = strings.TrimLeft(output, containers)
			output = strings.Trim(output, " ")
			containerCount, err := strconv.Atoi(output)
			if err != nil {
				return 0, err
			}
			return containerCount, nil
		}
	}
	return 0, fmt.Errorf("couldn't find the Container count in the output")
}

// FakeContext creates directories that can be used as a build context
type FakeContext struct {
	Dir string
}

// Add a file at a path, creating directories where necessary
func (f *FakeContext) Add(file, content string) error {
	return f.addFile(file, []byte(content))
}

func (f *FakeContext) addFile(file string, content []byte) error {
	filepath := path.Join(f.Dir, file)
	dirpath := path.Dir(filepath)
	if dirpath != "." {
		if err := os.MkdirAll(dirpath, 0755); err != nil {
			return err
		}
	}
	return ioutil.WriteFile(filepath, content, 0644)

}

// Delete a file at a path
func (f *FakeContext) Delete(file string) error {
	filepath := path.Join(f.Dir, file)
	return os.RemoveAll(filepath)
}

// Close deletes the context
func (f *FakeContext) Close() error {
	return os.RemoveAll(f.Dir)
}

func fakeContextFromNewTempDir() (*FakeContext, error) {
	tmp, err := ioutil.TempDir("", "fake-context")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(tmp, 0755); err != nil {
		return nil, err
	}
	return fakeContextFromDir(tmp), nil
}

func fakeContextFromDir(dir string) *FakeContext {
	return &FakeContext{dir}
}

func fakeContextWithFiles(files map[string]string) (*FakeContext, error) {
	ctx, err := fakeContextFromNewTempDir()
	if err != nil {
		return nil, err
	}
	for file, content := range files {
		if err := ctx.Add(file, content); err != nil {
			ctx.Close()
			return nil, err
		}
	}
	return ctx, nil
}

func fakeContextAddDockerfile(ctx *FakeContext, dockerfile string) error {
	if err := ctx.Add("Dockerfile", dockerfile); err != nil {
		ctx.Close()
		return err
	}
	return nil
}

func fakeContext(dockerfile string, files map[string]string) (*FakeContext, error) {
	ctx, err := fakeContextWithFiles(files)
	if err != nil {
		return nil, err
	}
	if err := fakeContextAddDockerfile(ctx, dockerfile); err != nil {
		return nil, err
	}
	return ctx, nil
}

// FakeStorage is a static file server. It might be running locally or remotely
// on test host.
type FakeStorage interface {
	Close() error
	URL() string
	CtxDir() string
}

func fakeBinaryStorage(archives map[string]*bytes.Buffer) (FakeStorage, error) {
	ctx, err := fakeContextFromNewTempDir()
	if err != nil {
		return nil, err
	}
	for name, content := range archives {
		if err := ctx.addFile(name, content.Bytes()); err != nil {
			return nil, err
		}
	}
	return fakeStorageWithContext(ctx)
}

// fakeStorage returns either a local or remote (at daemon machine) file server
func fakeStorage(files map[string]string) (FakeStorage, error) {
	ctx, err := fakeContextWithFiles(files)
	if err != nil {
		return nil, err
	}
	return fakeStorageWithContext(ctx)
}

// fakeStorageWithContext returns either a local or remote (at daemon machine) file server
func fakeStorageWithContext(ctx *FakeContext) (FakeStorage, error) {
	if isLocalDaemon {
		return newLocalFakeStorage(ctx)
	}
	return newRemoteFileServer(ctx)
}

// localFileStorage is a file storage on the running machine
type localFileStorage struct {
	*FakeContext
	*httptest.Server
}

func (s *localFileStorage) URL() string {
	return s.Server.URL
}

func (s *localFileStorage) CtxDir() string {
	return s.FakeContext.Dir
}

func (s *localFileStorage) Close() error {
	defer s.Server.Close()
	return s.FakeContext.Close()
}

func newLocalFakeStorage(ctx *FakeContext) (*localFileStorage, error) {
	handler := http.FileServer(http.Dir(ctx.Dir))
	server := httptest.NewServer(handler)
	return &localFileStorage{
		FakeContext: ctx,
		Server:      server,
	}, nil
}

// remoteFileServer is a containerized static file server started on the remote
// testing machine to be used in URL-accepting docker build functionality.
type remoteFileServer struct {
	host      string // hostname/port web server is listening to on docker host e.g. 0.0.0.0:43712
	container string
	image     string
	ctx       *FakeContext
}

func (f *remoteFileServer) URL() string {
	u := url.URL{
		Scheme: "http",
		Host:   f.host}
	return u.String()
}

func (f *remoteFileServer) CtxDir() string {
	return f.ctx.Dir
}

func (f *remoteFileServer) Close() error {
	defer func() {
		if f.ctx != nil {
			f.ctx.Close()
		}
		if f.image != "" {
			deleteImages(f.image)
		}
	}()
	if f.container == "" {
		return nil
	}
	return deleteContainer(f.container)
}

func newRemoteFileServer(ctx *FakeContext) (*remoteFileServer, error) {
	var (
		image     = fmt.Sprintf("fileserver-img-%s", strings.ToLower(stringutils.GenerateRandomAlphaOnlyString(10)))
		container = fmt.Sprintf("fileserver-cnt-%s", strings.ToLower(stringutils.GenerateRandomAlphaOnlyString(10)))
	)

	// Build the image
	if err := fakeContextAddDockerfile(ctx, `FROM httpserver
COPY . /static`); err != nil {
		return nil, fmt.Errorf("Cannot add Dockerfile to context: %v", err)
	}
	if _, err := buildImageFromContext(image, ctx, false); err != nil {
		return nil, fmt.Errorf("failed building file storage container image: %v", err)
	}

	// Start the container
	runCmd := exec.Command(dockerBinary, "run", "-d", "-P", "--name", container, image)
	if out, ec, err := runCommandWithOutput(runCmd); err != nil {
		return nil, fmt.Errorf("failed to start file storage container. ec=%v\nout=%s\nerr=%v", ec, out, err)
	}

	// Find out the system assigned port
	out, _, err := runCommandWithOutput(exec.Command(dockerBinary, "port", container, "80/tcp"))
	if err != nil {
		return nil, fmt.Errorf("failed to find container port: err=%v\nout=%s", err, out)
	}

	fileserverHostPort := strings.Trim(out, "\n")
	_, port, err := net.SplitHostPort(fileserverHostPort)
	if err != nil {
		return nil, fmt.Errorf("unable to parse file server host:port: %v", err)
	}

	dockerHostURL, err := url.Parse(daemonHost())
	if err != nil {
		return nil, fmt.Errorf("unable to parse daemon host URL: %v", err)
	}

	host, _, err := net.SplitHostPort(dockerHostURL.Host)
	if err != nil {
		return nil, fmt.Errorf("unable to parse docker daemon host:port: %v", err)
	}

	return &remoteFileServer{
		container: container,
		image:     image,
		host:      fmt.Sprintf("%s:%s", host, port),
		ctx:       ctx}, nil
}

func inspectFieldAndMarshall(c *check.C, name, field string, output interface{}) {
	str := inspectFieldJSON(c, name, field)
	err := json.Unmarshal([]byte(str), output)
	if c != nil {
		c.Assert(err, check.IsNil, check.Commentf("failed to unmarshal: %v", err))
	}
}

func inspectFilter(name, filter string) (string, error) {
	format := fmt.Sprintf("{{%s}}", filter)
	inspectCmd := exec.Command(dockerBinary, "inspect", "-f", format, name)
	out, exitCode, err := runCommandWithOutput(inspectCmd)
	if err != nil || exitCode != 0 {
		return "", fmt.Errorf("failed to inspect %s: %s", name, out)
	}
	return strings.TrimSpace(out), nil
}

func inspectFieldWithError(name, field string) (string, error) {
	return inspectFilter(name, fmt.Sprintf(".%s", field))
}

func inspectField(c *check.C, name, field string) string {
	out, err := inspectFilter(name, fmt.Sprintf(".%s", field))
	if c != nil {
		c.Assert(err, check.IsNil)
	}
	return out
}

func inspectFieldJSON(c *check.C, name, field string) string {
	out, err := inspectFilter(name, fmt.Sprintf("json .%s", field))
	if c != nil {
		c.Assert(err, check.IsNil)
	}
	return out
}

func inspectFieldMap(c *check.C, name, path, field string) string {
	out, err := inspectFilter(name, fmt.Sprintf("index .%s %q", path, field))
	if c != nil {
		c.Assert(err, check.IsNil)
	}
	return out
}

func inspectMountSourceField(name, destination string) (string, error) {
	m, err := inspectMountPoint(name, destination)
	if err != nil {
		return "", err
	}
	return m.Source, nil
}

func inspectMountPoint(name, destination string) (types.MountPoint, error) {
	out, err := inspectFilter(name, "json .Mounts")
	if err != nil {
		return types.MountPoint{}, err
	}

	return inspectMountPointJSON(out, destination)
}

var errMountNotFound = errors.New("mount point not found")

func inspectMountPointJSON(j, destination string) (types.MountPoint, error) {
	var mp []types.MountPoint
	if err := unmarshalJSON([]byte(j), &mp); err != nil {
		return types.MountPoint{}, err
	}

	var m *types.MountPoint
	for _, c := range mp {
		if c.Destination == destination {
			m = &c
			break
		}
	}

	if m == nil {
		return types.MountPoint{}, errMountNotFound
	}

	return *m, nil
}

func getIDByName(name string) (string, error) {
	return inspectFieldWithError(name, "Id")
}

// getContainerState returns the exit code of the container
// and true if it's running
// the exit code should be ignored if it's running
func getContainerState(c *check.C, id string) (int, bool, error) {
	var (
		exitStatus int
		running    bool
	)
	out, exitCode := dockerCmd(c, "inspect", "--format={{.State.Running}} {{.State.ExitCode}}", id)
	if exitCode != 0 {
		return 0, false, fmt.Errorf("%q doesn't exist: %s", id, out)
	}

	out = strings.Trim(out, "\n")
	splitOutput := strings.Split(out, " ")
	if len(splitOutput) != 2 {
		return 0, false, fmt.Errorf("failed to get container state: output is broken")
	}
	if splitOutput[0] == "true" {
		running = true
	}
	if n, err := strconv.Atoi(splitOutput[1]); err == nil {
		exitStatus = n
	} else {
		return 0, false, fmt.Errorf("failed to get container state: couldn't parse integer")
	}

	return exitStatus, running, nil
}

func buildImageCmd(name, dockerfile string, useCache bool, buildFlags ...string) *exec.Cmd {
	args := []string{"build", "-t", name}
	if !useCache {
		args = append(args, "--no-cache")
	}
	args = append(args, buildFlags...)
	args = append(args, "-")
	buildCmd := exec.Command(dockerBinary, args...)
	buildCmd.Stdin = strings.NewReader(dockerfile)
	return buildCmd
}

func buildImageWithOut(name, dockerfile string, useCache bool, buildFlags ...string) (string, string, error) {
	buildCmd := buildImageCmd(name, dockerfile, useCache, buildFlags...)
	out, exitCode, err := runCommandWithOutput(buildCmd)
	if err != nil || exitCode != 0 {
		return "", out, fmt.Errorf("failed to build the image: %s", out)
	}
	id, err := getIDByName(name)
	if err != nil {
		return "", out, err
	}
	return id, out, nil
}

func buildImageWithStdoutStderr(name, dockerfile string, useCache bool, buildFlags ...string) (string, string, string, error) {
	buildCmd := buildImageCmd(name, dockerfile, useCache, buildFlags...)
	stdout, stderr, exitCode, err := runCommandWithStdoutStderr(buildCmd)
	if err != nil || exitCode != 0 {
		return "", stdout, stderr, fmt.Errorf("failed to build the image: %s", stdout)
	}
	id, err := getIDByName(name)
	if err != nil {
		return "", stdout, stderr, err
	}
	return id, stdout, stderr, nil
}

func buildImage(name, dockerfile string, useCache bool, buildFlags ...string) (string, error) {
	id, _, err := buildImageWithOut(name, dockerfile, useCache, buildFlags...)
	return id, err
}

func buildImageFromContext(name string, ctx *FakeContext, useCache bool, buildFlags ...string) (string, error) {
	id, _, err := buildImageFromContextWithOut(name, ctx, useCache, buildFlags...)
	if err != nil {
		return "", err
	}
	return id, nil
}

func buildImageFromContextWithOut(name string, ctx *FakeContext, useCache bool, buildFlags ...string) (string, string, error) {
	args := []string{"build", "-t", name}
	if !useCache {
		args = append(args, "--no-cache")
	}
	args = append(args, buildFlags...)
	args = append(args, ".")
	buildCmd := exec.Command(dockerBinary, args...)
	buildCmd.Dir = ctx.Dir
	out, exitCode, err := runCommandWithOutput(buildCmd)
	if err != nil || exitCode != 0 {
		return "", "", fmt.Errorf("failed to build the image: %s", out)
	}
	id, err := getIDByName(name)
	if err != nil {
		return "", "", err
	}
	return id, out, nil
}

func buildImageFromContextWithStdoutStderr(name string, ctx *FakeContext, useCache bool, buildFlags ...string) (string, string, string, error) {
	args := []string{"build", "-t", name}
	if !useCache {
		args = append(args, "--no-cache")
	}
	args = append(args, buildFlags...)
	args = append(args, ".")
	buildCmd := exec.Command(dockerBinary, args...)
	buildCmd.Dir = ctx.Dir

	stdout, stderr, exitCode, err := runCommandWithStdoutStderr(buildCmd)
	if err != nil || exitCode != 0 {
		return "", stdout, stderr, fmt.Errorf("failed to build the image: %s", stdout)
	}
	id, err := getIDByName(name)
	if err != nil {
		return "", stdout, stderr, err
	}
	return id, stdout, stderr, nil
}

func buildImageFromGitWithStdoutStderr(name string, ctx *fakeGit, useCache bool, buildFlags ...string) (string, string, string, error) {
	args := []string{"build", "-t", name}
	if !useCache {
		args = append(args, "--no-cache")
	}
	args = append(args, buildFlags...)
	args = append(args, ctx.RepoURL)
	buildCmd := exec.Command(dockerBinary, args...)

	stdout, stderr, exitCode, err := runCommandWithStdoutStderr(buildCmd)
	if err != nil || exitCode != 0 {
		return "", stdout, stderr, fmt.Errorf("failed to build the image: %s", stdout)
	}
	id, err := getIDByName(name)
	if err != nil {
		return "", stdout, stderr, err
	}
	return id, stdout, stderr, nil
}

func buildImageFromPath(name, path string, useCache bool, buildFlags ...string) (string, error) {
	args := []string{"build", "-t", name}
	if !useCache {
		args = append(args, "--no-cache")
	}
	args = append(args, buildFlags...)
	args = append(args, path)
	buildCmd := exec.Command(dockerBinary, args...)
	out, exitCode, err := runCommandWithOutput(buildCmd)
	if err != nil || exitCode != 0 {
		return "", fmt.Errorf("failed to build the image: %s", out)
	}
	return getIDByName(name)
}

type gitServer interface {
	URL() string
	Close() error
}

type localGitServer struct {
	*httptest.Server
}

func (r *localGitServer) Close() error {
	r.Server.Close()
	return nil
}

func (r *localGitServer) URL() string {
	return r.Server.URL
}

type fakeGit struct {
	root    string
	server  gitServer
	RepoURL string
}

func (g *fakeGit) Close() {
	g.server.Close()
	os.RemoveAll(g.root)
}

func newFakeGit(name string, files map[string]string, enforceLocalServer bool) (*fakeGit, error) {
	ctx, err := fakeContextWithFiles(files)
	if err != nil {
		return nil, err
	}
	defer ctx.Close()
	curdir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	defer os.Chdir(curdir)

	if output, err := exec.Command("git", "init", ctx.Dir).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("error trying to init repo: %s (%s)", err, output)
	}
	err = os.Chdir(ctx.Dir)
	if err != nil {
		return nil, err
	}
	if output, err := exec.Command("git", "config", "user.name", "Fake User").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("error trying to set 'user.name': %s (%s)", err, output)
	}
	if output, err := exec.Command("git", "config", "user.email", "fake.user@example.com").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("error trying to set 'user.email': %s (%s)", err, output)
	}
	if output, err := exec.Command("git", "add", "*").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("error trying to add files to repo: %s (%s)", err, output)
	}
	if output, err := exec.Command("git", "commit", "-a", "-m", "Initial commit").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("error trying to commit to repo: %s (%s)", err, output)
	}

	root, err := ioutil.TempDir("", "docker-test-git-repo")
	if err != nil {
		return nil, err
	}
	repoPath := filepath.Join(root, name+".git")
	if output, err := exec.Command("git", "clone", "--bare", ctx.Dir, repoPath).CombinedOutput(); err != nil {
		os.RemoveAll(root)
		return nil, fmt.Errorf("error trying to clone --bare: %s (%s)", err, output)
	}
	err = os.Chdir(repoPath)
	if err != nil {
		os.RemoveAll(root)
		return nil, err
	}
	if output, err := exec.Command("git", "update-server-info").CombinedOutput(); err != nil {
		os.RemoveAll(root)
		return nil, fmt.Errorf("error trying to git update-server-info: %s (%s)", err, output)
	}
	err = os.Chdir(curdir)
	if err != nil {
		os.RemoveAll(root)
		return nil, err
	}

	var server gitServer
	if !enforceLocalServer {
		// use fakeStorage server, which might be local or remote (at test daemon)
		server, err = fakeStorageWithContext(fakeContextFromDir(root))
		if err != nil {
			return nil, fmt.Errorf("cannot start fake storage: %v", err)
		}
	} else {
		// always start a local http server on CLI test machine
		httpServer := httptest.NewServer(http.FileServer(http.Dir(root)))
		server = &localGitServer{httpServer}
	}
	return &fakeGit{
		root:    root,
		server:  server,
		RepoURL: fmt.Sprintf("%s/%s.git", server.URL(), name),
	}, nil
}

// Write `content` to the file at path `dst`, creating it if necessary,
// as well as any missing directories.
// The file is truncated if it already exists.
// Fail the test when error occurs.
func writeFile(dst, content string, c *check.C) {
	// Create subdirectories if necessary
	c.Assert(os.MkdirAll(path.Dir(dst), 0700), check.IsNil)
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0700)
	c.Assert(err, check.IsNil)
	defer f.Close()
	// Write content (truncate if it exists)
	_, err = io.Copy(f, strings.NewReader(content))
	c.Assert(err, check.IsNil)
}

// Return the contents of file at path `src`.
// Fail the test when error occurs.
func readFile(src string, c *check.C) (content string) {
	data, err := ioutil.ReadFile(src)
	c.Assert(err, check.IsNil)

	return string(data)
}

func containerStorageFile(containerID, basename string) string {
	return filepath.Join(containerStoragePath, containerID, basename)
}

// docker commands that use this function must be run with the '-d' switch.
func runCommandAndReadContainerFile(filename string, cmd *exec.Cmd) ([]byte, error) {
	out, _, err := runCommandWithOutput(cmd)
	if err != nil {
		return nil, fmt.Errorf("%v: %q", err, out)
	}

	contID := strings.TrimSpace(out)

	if err := waitRun(contID); err != nil {
		return nil, fmt.Errorf("%v: %q", contID, err)
	}

	return readContainerFile(contID, filename)
}

func readContainerFile(containerID, filename string) ([]byte, error) {
	f, err := os.Open(containerStorageFile(containerID, filename))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	content, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return content, nil
}

func readContainerFileWithExec(containerID, filename string) ([]byte, error) {
	out, _, err := runCommandWithOutput(exec.Command(dockerBinary, "exec", containerID, "cat", filename))
	return []byte(out), err
}

// daemonTime provides the current time on the daemon host
func daemonTime(c *check.C) time.Time {
	if isLocalDaemon {
		return time.Now()
	}

	status, body, err := sockRequest("GET", "/info", nil)
	c.Assert(err, check.IsNil)
	c.Assert(status, check.Equals, http.StatusOK)

	type infoJSON struct {
		SystemTime string
	}
	var info infoJSON
	err = json.Unmarshal(body, &info)
	c.Assert(err, check.IsNil, check.Commentf("unable to unmarshal GET /info response"))

	dt, err := time.Parse(time.RFC3339Nano, info.SystemTime)
	c.Assert(err, check.IsNil, check.Commentf("invalid time format in GET /info response"))
	return dt
}

func setupRegistry(c *check.C, schema1, auth bool) *testRegistryV2 {
	reg, err := newTestRegistryV2(c, schema1, auth)
	c.Assert(err, check.IsNil)

	// Wait for registry to be ready to serve requests.
	for i := 0; i != 50; i++ {
		if err = reg.Ping(); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	c.Assert(err, check.IsNil, check.Commentf("Timeout waiting for test registry to become available: %v", err))
	return reg
}

func setupNotary(c *check.C) *testNotary {
	ts, err := newTestNotary(c)
	c.Assert(err, check.IsNil)

	return ts
}

// appendBaseEnv appends the minimum set of environment variables to exec the
// docker cli binary for testing with correct configuration to the given env
// list.
func appendBaseEnv(isTLS bool, env ...string) []string {
	preserveList := []string{
		// preserve remote test host
		"DOCKER_HOST",

		// windows: requires preserving SystemRoot, otherwise dial tcp fails
		// with "GetAddrInfoW: A non-recoverable error occurred during a database lookup."
		"SystemRoot",
	}
	if isTLS {
		preserveList = append(preserveList, "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")
	}

	for _, key := range preserveList {
		if val := os.Getenv(key); val != "" {
			env = append(env, fmt.Sprintf("%s=%s", key, val))
		}
	}
	return env
}

func createTmpFile(c *check.C, content string) string {
	f, err := ioutil.TempFile("", "testfile")
	c.Assert(err, check.IsNil)

	filename := f.Name()

	err = ioutil.WriteFile(filename, []byte(content), 0644)
	c.Assert(err, check.IsNil)

	return filename
}

func buildImageWithOutInDamon(socket string, name, dockerfile string, useCache bool) (string, error) {
	args := []string{"--host", socket}
	buildCmd := buildImageCmdArgs(args, name, dockerfile, useCache)
	out, exitCode, err := runCommandWithOutput(buildCmd)
	if err != nil || exitCode != 0 {
		return out, fmt.Errorf("failed to build the image: %s, error: %v", out, err)
	}
	return out, nil
}

func buildImageCmdArgs(args []string, name, dockerfile string, useCache bool) *exec.Cmd {
	args = append(args, []string{"-D", "build", "-t", name}...)
	if !useCache {
		args = append(args, "--no-cache")
	}
	args = append(args, "-")
	buildCmd := exec.Command(dockerBinary, args...)
	buildCmd.Stdin = strings.NewReader(dockerfile)
	return buildCmd

}

func waitForContainer(contID string, args ...string) error {
	args = append([]string{"run", "--name", contID}, args...)
	cmd := exec.Command(dockerBinary, args...)
	if _, err := runCommand(cmd); err != nil {
		return err
	}

	if err := waitRun(contID); err != nil {
		return err
	}

	return nil
}

// waitRun will wait for the specified container to be running, maximum 5 seconds.
func waitRun(contID string) error {
	return waitInspect(contID, "{{.State.Running}}", "true", 5*time.Second)
}

// waitExited will wait for the specified container to state exit, subject
// to a maximum time limit in seconds supplied by the caller
func waitExited(contID string, duration time.Duration) error {
	return waitInspect(contID, "{{.State.Status}}", "exited", duration)
}

// waitInspect will wait for the specified container to have the specified string
// in the inspect output. It will wait until the specified timeout (in seconds)
// is reached.
func waitInspect(name, expr, expected string, timeout time.Duration) error {
	return waitInspectWithArgs(name, expr, expected, timeout)
}

func waitInspectWithArgs(name, expr, expected string, timeout time.Duration, arg ...string) error {
	after := time.After(timeout)

	args := append(arg, "inspect", "-f", expr, name)
	for {
		cmd := exec.Command(dockerBinary, args...)
		out, _, err := runCommandWithOutput(cmd)
		if err != nil {
			if !strings.Contains(out, "No such") {
				return fmt.Errorf("error executing docker inspect: %v\n%s", err, out)
			}
			select {
			case <-after:
				return err
			default:
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}

		out = strings.TrimSpace(out)
		if out == expected {
			break
		}

		select {
		case <-after:
			return fmt.Errorf("condition \"%q == %q\" not true in time", out, expected)
		default:
		}

		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

func getInspectBody(c *check.C, version, id string) []byte {
	endpoint := fmt.Sprintf("/%s/containers/%s/json", version, id)
	status, body, err := sockRequest("GET", endpoint, nil)
	c.Assert(err, check.IsNil)
	c.Assert(status, check.Equals, http.StatusOK)
	return body
}

// Run a long running idle task in a background container using the
// system-specific default image and command.
func runSleepingContainer(c *check.C, extraArgs ...string) (string, int) {
	return runSleepingContainerInImage(c, defaultSleepImage, extraArgs...)
}

// Run a long running idle task in a background container using the specified
// image and the system-specific command.
func runSleepingContainerInImage(c *check.C, image string, extraArgs ...string) (string, int) {
	args := []string{"run", "-d"}
	args = append(args, extraArgs...)
	args = append(args, image)
	args = append(args, defaultSleepCommand...)
	return dockerCmd(c, args...)
}

func getRootUIDGID() (int, int, error) {
	uidgid := strings.Split(filepath.Base(dockerBasePath), ".")
	if len(uidgid) == 1 {
		//user namespace remapping is not turned on; return 0
		return 0, 0, nil
	}
	uid, err := strconv.Atoi(uidgid[0])
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(uidgid[1])
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

// minimalBaseImage returns the name of the minimal base image for the current
// daemon platform.
func minimalBaseImage() string {
	if daemonPlatform == "windows" {
		return WindowsBaseImage
	}
	return "scratch"
}
