package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	volumetypes "github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/integration-cli/checker"
	"github.com/docker/docker/integration-cli/daemon"
	"github.com/docker/docker/integration-cli/registry"
	"github.com/docker/docker/integration-cli/request"
	"github.com/docker/docker/opts"
	"github.com/docker/docker/pkg/stringutils"
	icmd "github.com/docker/docker/pkg/testutil/cmd"
	"github.com/go-check/check"
)

func daemonHost() string {
	daemonURLStr := "unix://" + opts.DefaultUnixSocket
	if daemonHostVar := os.Getenv("DOCKER_HOST"); daemonHostVar != "" {
		daemonURLStr = daemonHostVar
	}
	return daemonURLStr
}

// FIXME(vdemeester) move this away are remove ignoreNoSuchContainer bool
func deleteContainer(ignoreNoSuchContainer bool, container ...string) error {
	result := icmd.RunCommand(dockerBinary, append([]string{"rm", "-fv"}, container...)...)
	if ignoreNoSuchContainer && result.Error != nil {
		// If the error is "No such container: ..." this means the container doesn't exists anymore,
		// we can safely ignore that one.
		if strings.Contains(result.Stderr(), "No such container") {
			return nil
		}
	}
	return result.Compare(icmd.Success)
}

func getAllContainers() (string, error) {
	getContainersCmd := exec.Command(dockerBinary, "ps", "-q", "-a")
	out, exitCode, err := runCommandWithOutput(getContainersCmd)
	if exitCode != 0 && err == nil {
		err = fmt.Errorf("failed to get a list of containers: %v\n", out)
	}

	return out, err
}

func deleteAllContainers(c *check.C) {
	containers, err := getAllContainers()
	c.Assert(err, checker.IsNil, check.Commentf("containers: %v", containers))

	if containers != "" {
		err = deleteContainer(true, strings.Split(strings.TrimSpace(containers), "\n")...)
		c.Assert(err, checker.IsNil)
	}
}

func deleteAllNetworks(c *check.C) {
	networks, err := getAllNetworks()
	c.Assert(err, check.IsNil)
	var errs []string
	for _, n := range networks {
		if n.Name == "bridge" || n.Name == "none" || n.Name == "host" {
			continue
		}
		if testEnv.DaemonPlatform() == "windows" && strings.ToLower(n.Name) == "nat" {
			// nat is a pre-defined network on Windows and cannot be removed
			continue
		}
		status, b, err := request.SockRequest("DELETE", "/networks/"+n.Name, nil, daemonHost())
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if status != http.StatusNoContent {
			errs = append(errs, fmt.Sprintf("error deleting network %s: %s", n.Name, string(b)))
		}
	}
	c.Assert(errs, checker.HasLen, 0, check.Commentf(strings.Join(errs, "\n")))
}

func getAllNetworks() ([]types.NetworkResource, error) {
	var networks []types.NetworkResource
	_, b, err := request.SockRequest("GET", "/networks", nil, daemonHost())
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &networks); err != nil {
		return nil, err
	}
	return networks, nil
}

func deleteAllPlugins(c *check.C) {
	plugins, err := getAllPlugins()
	c.Assert(err, checker.IsNil)
	var errs []string
	for _, p := range plugins {
		pluginName := p.Name
		status, b, err := request.SockRequest("DELETE", "/plugins/"+pluginName+"?force=1", nil, daemonHost())
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if status != http.StatusOK {
			errs = append(errs, fmt.Sprintf("error deleting plugin %s: %s", p.Name, string(b)))
		}
	}
	c.Assert(errs, checker.HasLen, 0, check.Commentf(strings.Join(errs, "\n")))
}

func getAllPlugins() (types.PluginsListResponse, error) {
	var plugins types.PluginsListResponse
	_, b, err := request.SockRequest("GET", "/plugins", nil, daemonHost())
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &plugins); err != nil {
		return nil, err
	}
	return plugins, nil
}

func deleteAllVolumes(c *check.C) {
	volumes, err := getAllVolumes()
	c.Assert(err, checker.IsNil)
	var errs []string
	for _, v := range volumes {
		status, b, err := request.SockRequest("DELETE", "/volumes/"+v.Name, nil, daemonHost())
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if status != http.StatusNoContent {
			errs = append(errs, fmt.Sprintf("error deleting volume %s: %s", v.Name, string(b)))
		}
	}
	c.Assert(errs, checker.HasLen, 0, check.Commentf(strings.Join(errs, "\n")))
}

func getAllVolumes() ([]*types.Volume, error) {
	var volumes volumetypes.VolumesListOKBody
	_, b, err := request.SockRequest("GET", "/volumes", nil, daemonHost())
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &volumes); err != nil {
		return nil, err
	}
	return volumes.Volumes, nil
}

func deleteAllImages(c *check.C) {
	cmd := exec.Command(dockerBinary, "images", "--digests")
	cmd.Env = appendBaseEnv(true)
	out, err := cmd.CombinedOutput()
	c.Assert(err, checker.IsNil)
	lines := strings.Split(string(out), "\n")[1:]
	imgMap := map[string]struct{}{}
	for _, l := range lines {
		if l == "" {
			continue
		}
		fields := strings.Fields(l)
		imgTag := fields[0] + ":" + fields[1]
		if _, ok := protectedImages[imgTag]; !ok {
			if fields[0] == "<none>" || fields[1] == "<none>" {
				if fields[2] != "<none>" {
					imgMap[fields[0]+"@"+fields[2]] = struct{}{}
				} else {
					imgMap[fields[3]] = struct{}{}
				}
				// continue
			} else {
				imgMap[imgTag] = struct{}{}
			}
		}
	}
	if len(imgMap) != 0 {
		imgs := make([]string, 0, len(imgMap))
		for k := range imgMap {
			imgs = append(imgs, k)
		}
		dockerCmd(c, append([]string{"rmi", "-f"}, imgs...)...)
	}
}

func getPausedContainers() ([]string, error) {
	getPausedContainersCmd := exec.Command(dockerBinary, "ps", "-f", "status=paused", "-q", "-a")
	out, exitCode, err := runCommandWithOutput(getPausedContainersCmd)
	if exitCode != 0 && err == nil {
		err = fmt.Errorf("failed to get a list of paused containers: %v\n", out)
	}
	if err != nil {
		return nil, err
	}

	return strings.Fields(out), nil
}

func unpauseContainer(c *check.C, container string) {
	dockerCmd(c, "unpause", container)
}

func unpauseAllContainers(c *check.C) {
	containers, err := getPausedContainers()
	c.Assert(err, checker.IsNil, check.Commentf("containers: %v", containers))
	for _, value := range containers {
		unpauseContainer(c, value)
	}
}

func deleteImages(images ...string) error {
	args := []string{dockerBinary, "rmi", "-f"}
	return icmd.RunCmd(icmd.Cmd{Command: append(args, images...)}).Error
}

func dockerCmdWithError(args ...string) (string, int, error) {
	if err := validateArgs(args...); err != nil {
		return "", 0, err
	}
	result := icmd.RunCommand(dockerBinary, args...)
	if result.Error != nil {
		return result.Combined(), result.ExitCode, result.Compare(icmd.Success)
	}
	return result.Combined(), result.ExitCode, result.Error
}

func dockerCmdWithStdoutStderr(c *check.C, args ...string) (string, string, int) {
	if err := validateArgs(args...); err != nil {
		c.Fatalf(err.Error())
	}

	result := icmd.RunCommand(dockerBinary, args...)
	c.Assert(result, icmd.Matches, icmd.Success)
	return result.Stdout(), result.Stderr(), result.ExitCode
}

func dockerCmd(c *check.C, args ...string) (string, int) {
	if err := validateArgs(args...); err != nil {
		c.Fatalf(err.Error())
	}
	result := icmd.RunCommand(dockerBinary, args...)
	c.Assert(result, icmd.Matches, icmd.Success)
	return result.Combined(), result.ExitCode
}

func dockerCmdWithResult(args ...string) *icmd.Result {
	return icmd.RunCommand(dockerBinary, args...)
}

func binaryWithArgs(args ...string) []string {
	return append([]string{dockerBinary}, args...)
}

// execute a docker command with a timeout
func dockerCmdWithTimeout(timeout time.Duration, args ...string) *icmd.Result {
	if err := validateArgs(args...); err != nil {
		return &icmd.Result{Error: err}
	}
	return icmd.RunCmd(icmd.Cmd{Command: binaryWithArgs(args...), Timeout: timeout})
}

// execute a docker command in a directory
func dockerCmdInDir(c *check.C, path string, args ...string) (string, int, error) {
	if err := validateArgs(args...); err != nil {
		c.Fatalf(err.Error())
	}
	result := icmd.RunCmd(icmd.Cmd{Command: binaryWithArgs(args...), Dir: path})
	return result.Combined(), result.ExitCode, result.Error
}

// validateArgs is a checker to ensure tests are not running commands which are
// not supported on platforms. Specifically on Windows this is 'busybox top'.
func validateArgs(args ...string) error {
	if testEnv.DaemonPlatform() != "windows" {
		return nil
	}
	foundBusybox := -1
	for key, value := range args {
		if strings.ToLower(value) == "busybox" {
			foundBusybox = key
		}
		if (foundBusybox != -1) && (key == foundBusybox+1) && (strings.ToLower(value) == "top") {
			return errors.New("cannot use 'busybox top' in tests on Windows. Use runSleepingContainer()")
		}
	}
	return nil
}

func findContainerIP(c *check.C, id string, network string) string {
	out, _ := dockerCmd(c, "inspect", fmt.Sprintf("--format='{{ .NetworkSettings.Networks.%s.IPAddress }}'", network), id)
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
	fp := filepath.Join(f.Dir, filepath.FromSlash(file))
	dirpath := filepath.Dir(fp)
	if dirpath != "." {
		if err := os.MkdirAll(dirpath, 0755); err != nil {
			return err
		}
	}
	return ioutil.WriteFile(fp, content, 0644)

}

// Delete a file at a path
func (f *FakeContext) Delete(file string) error {
	fp := filepath.Join(f.Dir, filepath.FromSlash(file))
	return os.RemoveAll(fp)
}

// Close deletes the context
func (f *FakeContext) Close() error {
	return os.RemoveAll(f.Dir)
}

func fakeContextFromNewTempDir(c *check.C) *FakeContext {
	tmp, err := ioutil.TempDir("", "fake-context")
	c.Assert(err, checker.IsNil)
	if err := os.Chmod(tmp, 0755); err != nil {
		c.Fatal(err)
	}
	return fakeContextFromDir(tmp)
}

func fakeContextFromDir(dir string) *FakeContext {
	return &FakeContext{dir}
}

func fakeContextWithFiles(c *check.C, files map[string]string) *FakeContext {
	ctx := fakeContextFromNewTempDir(c)
	for file, content := range files {
		if err := ctx.Add(file, content); err != nil {
			ctx.Close()
			c.Fatal(err)
		}
	}
	return ctx
}

func fakeContextAddDockerfile(c *check.C, ctx *FakeContext, dockerfile string) {
	if err := ctx.Add("Dockerfile", dockerfile); err != nil {
		ctx.Close()
		c.Fatal(err)
	}
}

func fakeContext(c *check.C, dockerfile string, files map[string]string) *FakeContext {
	ctx := fakeContextWithFiles(c, files)
	fakeContextAddDockerfile(c, ctx, dockerfile)
	return ctx
}

// FakeStorage is a static file server. It might be running locally or remotely
// on test host.
type FakeStorage interface {
	Close() error
	URL() string
	CtxDir() string
}

func fakeBinaryStorage(c *check.C, archives map[string]*bytes.Buffer) FakeStorage {
	ctx := fakeContextFromNewTempDir(c)
	for name, content := range archives {
		if err := ctx.addFile(name, content.Bytes()); err != nil {
			c.Fatal(err)
		}
	}
	return fakeStorageWithContext(c, ctx)
}

// fakeStorage returns either a local or remote (at daemon machine) file server
func fakeStorage(c *check.C, files map[string]string) FakeStorage {
	ctx := fakeContextWithFiles(c, files)
	return fakeStorageWithContext(c, ctx)
}

// fakeStorageWithContext returns either a local or remote (at daemon machine) file server
func fakeStorageWithContext(c *check.C, ctx *FakeContext) FakeStorage {
	if testEnv.LocalDaemon() {
		return newLocalFakeStorage(c, ctx)
	}
	return newRemoteFileServer(c, ctx)
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

func newLocalFakeStorage(c *check.C, ctx *FakeContext) *localFileStorage {
	handler := http.FileServer(http.Dir(ctx.Dir))
	server := httptest.NewServer(handler)
	return &localFileStorage{
		FakeContext: ctx,
		Server:      server,
	}
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
	return deleteContainer(false, f.container)
}

func newRemoteFileServer(c *check.C, ctx *FakeContext) *remoteFileServer {
	var (
		image     = fmt.Sprintf("fileserver-img-%s", strings.ToLower(stringutils.GenerateRandomAlphaOnlyString(10)))
		container = fmt.Sprintf("fileserver-cnt-%s", strings.ToLower(stringutils.GenerateRandomAlphaOnlyString(10)))
	)

	c.Assert(ensureHTTPServerImage(), checker.IsNil)

	// Build the image
	fakeContextAddDockerfile(c, ctx, `FROM httpserver
COPY . /static`)
	buildImageSuccessfully(c, image, withoutCache, withExternalBuildContext(ctx))

	// Start the container
	dockerCmd(c, "run", "-d", "-P", "--name", container, image)

	// Find out the system assigned port
	out, _ := dockerCmd(c, "port", container, "80/tcp")
	fileserverHostPort := strings.Trim(out, "\n")
	_, port, err := net.SplitHostPort(fileserverHostPort)
	if err != nil {
		c.Fatalf("unable to parse file server host:port: %v", err)
	}

	dockerHostURL, err := url.Parse(daemonHost())
	if err != nil {
		c.Fatalf("unable to parse daemon host URL: %v", err)
	}

	host, _, err := net.SplitHostPort(dockerHostURL.Host)
	if err != nil {
		c.Fatalf("unable to parse docker daemon host:port: %v", err)
	}

	return &remoteFileServer{
		container: container,
		image:     image,
		host:      fmt.Sprintf("%s:%s", host, port),
		ctx:       ctx}
}

func inspectFieldAndUnmarshall(c *check.C, name, field string, output interface{}) {
	str := inspectFieldJSON(c, name, field)
	err := json.Unmarshal([]byte(str), output)
	if c != nil {
		c.Assert(err, check.IsNil, check.Commentf("failed to unmarshal: %v", err))
	}
}

func inspectFilter(name, filter string) (string, error) {
	format := fmt.Sprintf("{{%s}}", filter)
	result := icmd.RunCommand(dockerBinary, "inspect", "-f", format, name)
	if result.Error != nil || result.ExitCode != 0 {
		return "", fmt.Errorf("failed to inspect %s: %s", name, result.Combined())
	}
	return strings.TrimSpace(result.Combined()), nil
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
	if err := json.Unmarshal([]byte(j), &mp); err != nil {
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

func inspectImage(name, filter string) (string, error) {
	args := []string{"inspect", "--type", "image"}
	if filter != "" {
		format := fmt.Sprintf("{{%s}}", filter)
		args = append(args, "-f", format)
	}
	args = append(args, name)
	inspectCmd := exec.Command(dockerBinary, args...)
	out, exitCode, err := runCommandWithOutput(inspectCmd)
	if err != nil || exitCode != 0 {
		return "", fmt.Errorf("failed to inspect %s: %s", name, out)
	}
	return strings.TrimSpace(out), nil
}

func getIDByName(c *check.C, name string) string {
	id, err := inspectFieldWithError(name, "Id")
	c.Assert(err, checker.IsNil)
	return id
}

func buildImageSuccessfully(c *check.C, name string, cmdOperators ...func(*icmd.Cmd) func()) {
	buildImage(name, cmdOperators...).Assert(c, icmd.Success)
}

func buildImage(name string, cmdOperators ...func(*icmd.Cmd) func()) *icmd.Result {
	cmd := icmd.Command(dockerBinary, "build", "-t", name)
	for _, op := range cmdOperators {
		deferFn := op(&cmd)
		if deferFn != nil {
			defer deferFn()
		}
	}
	return icmd.RunCmd(cmd)
}

func withBuildContextPath(path string) func(*icmd.Cmd) func() {
	return func(cmd *icmd.Cmd) func() {
		cmd.Command = append(cmd.Command, path)
		return nil
	}
}

func withExternalBuildContext(ctx *FakeContext) func(*icmd.Cmd) func() {
	return func(cmd *icmd.Cmd) func() {
		cmd.Dir = ctx.Dir
		cmd.Command = append(cmd.Command, ".")
		return nil
	}
}

func withBuildContext(c *check.C, contextOperators ...func(*FakeContext) error) func(*icmd.Cmd) func() {
	ctx := fakeContextFromNewTempDir(c)
	for _, op := range contextOperators {
		if err := op(ctx); err != nil {
			c.Fatal(err)
		}
	}
	return func(cmd *icmd.Cmd) func() {
		cmd.Dir = ctx.Dir
		cmd.Command = append(cmd.Command, ".")
		return closeBuildContext(c, ctx)
	}
}

func withBuildFlags(flags ...string) func(*icmd.Cmd) func() {
	return func(cmd *icmd.Cmd) func() {
		cmd.Command = append(cmd.Command, flags...)
		return nil
	}
}

func withoutCache(cmd *icmd.Cmd) func() {
	cmd.Command = append(cmd.Command, "--no-cache")
	return nil
}

func withFile(name, content string) func(*FakeContext) error {
	return func(ctx *FakeContext) error {
		return ctx.Add(name, content)
	}
}

func closeBuildContext(c *check.C, ctx *FakeContext) func() {
	return func() {
		if err := ctx.Close(); err != nil {
			c.Fatal(err)
		}
	}
}

func withDockerfile(dockerfile string) func(*icmd.Cmd) func() {
	return func(cmd *icmd.Cmd) func() {
		cmd.Command = append(cmd.Command, "-")
		cmd.Stdin = strings.NewReader(dockerfile)
		return nil
	}
}

func trustedBuild(cmd *icmd.Cmd) func() {
	trustedCmd(cmd)
	return nil
}

func withEnvironmentVariales(envs ...string) func(cmd *icmd.Cmd) func() {
	return func(cmd *icmd.Cmd) func() {
		cmd.Env = envs
		return nil
	}
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

func newFakeGit(c *check.C, name string, files map[string]string, enforceLocalServer bool) *fakeGit {
	ctx := fakeContextWithFiles(c, files)
	defer ctx.Close()
	curdir, err := os.Getwd()
	if err != nil {
		c.Fatal(err)
	}
	defer os.Chdir(curdir)

	if output, err := exec.Command("git", "init", ctx.Dir).CombinedOutput(); err != nil {
		c.Fatalf("error trying to init repo: %s (%s)", err, output)
	}
	err = os.Chdir(ctx.Dir)
	if err != nil {
		c.Fatal(err)
	}
	if output, err := exec.Command("git", "config", "user.name", "Fake User").CombinedOutput(); err != nil {
		c.Fatalf("error trying to set 'user.name': %s (%s)", err, output)
	}
	if output, err := exec.Command("git", "config", "user.email", "fake.user@example.com").CombinedOutput(); err != nil {
		c.Fatalf("error trying to set 'user.email': %s (%s)", err, output)
	}
	if output, err := exec.Command("git", "add", "*").CombinedOutput(); err != nil {
		c.Fatalf("error trying to add files to repo: %s (%s)", err, output)
	}
	if output, err := exec.Command("git", "commit", "-a", "-m", "Initial commit").CombinedOutput(); err != nil {
		c.Fatalf("error trying to commit to repo: %s (%s)", err, output)
	}

	root, err := ioutil.TempDir("", "docker-test-git-repo")
	if err != nil {
		c.Fatal(err)
	}
	repoPath := filepath.Join(root, name+".git")
	if output, err := exec.Command("git", "clone", "--bare", ctx.Dir, repoPath).CombinedOutput(); err != nil {
		os.RemoveAll(root)
		c.Fatalf("error trying to clone --bare: %s (%s)", err, output)
	}
	err = os.Chdir(repoPath)
	if err != nil {
		os.RemoveAll(root)
		c.Fatal(err)
	}
	if output, err := exec.Command("git", "update-server-info").CombinedOutput(); err != nil {
		os.RemoveAll(root)
		c.Fatalf("error trying to git update-server-info: %s (%s)", err, output)
	}
	err = os.Chdir(curdir)
	if err != nil {
		os.RemoveAll(root)
		c.Fatal(err)
	}

	var server gitServer
	if !enforceLocalServer {
		// use fakeStorage server, which might be local or remote (at test daemon)
		server = fakeStorageWithContext(c, fakeContextFromDir(root))
	} else {
		// always start a local http server on CLI test machine
		httpServer := httptest.NewServer(http.FileServer(http.Dir(root)))
		server = &localGitServer{httpServer}
	}
	return &fakeGit{
		root:    root,
		server:  server,
		RepoURL: fmt.Sprintf("%s/%s.git", server.URL(), name),
	}
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
	return filepath.Join(testEnv.ContainerStoragePath(), containerID, basename)
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
	if testEnv.LocalDaemon() {
		return time.Now()
	}

	status, body, err := request.SockRequest("GET", "/info", nil, daemonHost())
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

// daemonUnixTime returns the current time on the daemon host with nanoseconds precision.
// It return the time formatted how the client sends timestamps to the server.
func daemonUnixTime(c *check.C) string {
	return parseEventTime(daemonTime(c))
}

func parseEventTime(t time.Time) string {
	return fmt.Sprintf("%d.%09d", t.Unix(), int64(t.Nanosecond()))
}

func setupRegistry(c *check.C, schema1 bool, auth, tokenURL string) *registry.V2 {
	reg, err := registry.NewV2(schema1, auth, tokenURL, privateRegistryURL)
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

		// testing help text requires the $PATH to dockerd is set
		"PATH",
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

func waitForContainer(contID string, args ...string) error {
	args = append([]string{dockerBinary, "run", "--name", contID}, args...)
	result := icmd.RunCmd(icmd.Cmd{Command: args})
	if result.Error != nil {
		return result.Error
	}
	return waitRun(contID)
}

// waitRestart will wait for the specified container to restart once
func waitRestart(contID string, duration time.Duration) error {
	return waitInspect(contID, "{{.RestartCount}}", "1", duration)
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
	return daemon.WaitInspectWithArgs(dockerBinary, name, expr, expected, timeout, arg...)
}

func getInspectBody(c *check.C, version, id string) []byte {
	endpoint := fmt.Sprintf("/%s/containers/%s/json", version, id)
	status, body, err := request.SockRequest("GET", endpoint, nil, daemonHost())
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
	args = append(args, sleepCommandForDaemonPlatform()...)
	return dockerCmd(c, args...)
}

// minimalBaseImage returns the name of the minimal base image for the current
// daemon platform.
func minimalBaseImage() string {
	return testEnv.MinimalBaseImage()
}

func getGoroutineNumber() (int, error) {
	i := struct {
		NGoroutines int
	}{}
	status, b, err := request.SockRequest("GET", "/info", nil, daemonHost())
	if err != nil {
		return 0, err
	}
	if status != http.StatusOK {
		return 0, fmt.Errorf("http status code: %d", status)
	}
	if err := json.Unmarshal(b, &i); err != nil {
		return 0, err
	}
	return i.NGoroutines, nil
}

func waitForGoroutines(expected int) error {
	t := time.After(30 * time.Second)
	for {
		select {
		case <-t:
			n, err := getGoroutineNumber()
			if err != nil {
				return err
			}
			if n > expected {
				return fmt.Errorf("leaked goroutines: expected less than or equal to %d, got: %d", expected, n)
			}
		default:
			n, err := getGoroutineNumber()
			if err != nil {
				return err
			}
			if n <= expected {
				return nil
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
}

// getErrorMessage returns the error message from an error API response
func getErrorMessage(c *check.C, body []byte) string {
	var resp types.ErrorResponse
	c.Assert(json.Unmarshal(body, &resp), check.IsNil)
	return strings.TrimSpace(resp.Message)
}

func waitAndAssert(c *check.C, timeout time.Duration, f checkF, checker check.Checker, args ...interface{}) {
	after := time.After(timeout)
	for {
		v, comment := f(c)
		assert, _ := checker.Check(append([]interface{}{v}, args...), checker.Info().Params)
		select {
		case <-after:
			assert = true
		default:
		}
		if assert {
			if comment != nil {
				args = append(args, comment)
			}
			c.Assert(v, checker, args...)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

type checkF func(*check.C) (interface{}, check.CommentInterface)
type reducer func(...interface{}) interface{}

func reducedCheck(r reducer, funcs ...checkF) checkF {
	return func(c *check.C) (interface{}, check.CommentInterface) {
		var values []interface{}
		var comments []string
		for _, f := range funcs {
			v, comment := f(c)
			values = append(values, v)
			if comment != nil {
				comments = append(comments, comment.CheckCommentString())
			}
		}
		return r(values...), check.Commentf("%v", strings.Join(comments, ", "))
	}
}

func sumAsIntegers(vals ...interface{}) interface{} {
	var s int
	for _, v := range vals {
		s += v.(int)
	}
	return s
}
