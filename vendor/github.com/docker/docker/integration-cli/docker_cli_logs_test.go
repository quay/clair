package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/docker/docker/pkg/integration/checker"
	"github.com/docker/docker/pkg/jsonlog"
	"github.com/go-check/check"
)

// This used to work, it test a log of PageSize-1 (gh#4851)
func (s *DockerSuite) TestLogsContainerSmallerThanPage(c *check.C) {
	testLen := 32767
	out, _ := dockerCmd(c, "run", "-d", "busybox", "sh", "-c", fmt.Sprintf("for i in $(seq 1 %d); do echo -n =; done; echo", testLen))

	id := strings.TrimSpace(out)
	dockerCmd(c, "wait", id)

	out, _ = dockerCmd(c, "logs", id)

	c.Assert(out, checker.HasLen, testLen+1)
}

// Regression test: When going over the PageSize, it used to panic (gh#4851)
func (s *DockerSuite) TestLogsContainerBiggerThanPage(c *check.C) {
	testLen := 32768
	out, _ := dockerCmd(c, "run", "-d", "busybox", "sh", "-c", fmt.Sprintf("for i in $(seq 1 %d); do echo -n =; done; echo", testLen))

	id := strings.TrimSpace(out)
	dockerCmd(c, "wait", id)

	out, _ = dockerCmd(c, "logs", id)

	c.Assert(out, checker.HasLen, testLen+1)
}

// Regression test: When going much over the PageSize, it used to block (gh#4851)
func (s *DockerSuite) TestLogsContainerMuchBiggerThanPage(c *check.C) {
	testLen := 33000
	out, _ := dockerCmd(c, "run", "-d", "busybox", "sh", "-c", fmt.Sprintf("for i in $(seq 1 %d); do echo -n =; done; echo", testLen))

	id := strings.TrimSpace(out)
	dockerCmd(c, "wait", id)

	out, _ = dockerCmd(c, "logs", id)

	c.Assert(out, checker.HasLen, testLen+1)
}

func (s *DockerSuite) TestLogsTimestamps(c *check.C) {
	testLen := 100
	out, _ := dockerCmd(c, "run", "-d", "busybox", "sh", "-c", fmt.Sprintf("for i in $(seq 1 %d); do echo =; done;", testLen))

	id := strings.TrimSpace(out)
	dockerCmd(c, "wait", id)

	out, _ = dockerCmd(c, "logs", "-t", id)

	lines := strings.Split(out, "\n")

	c.Assert(lines, checker.HasLen, testLen+1)

	ts := regexp.MustCompile(`^.* `)

	for _, l := range lines {
		if l != "" {
			_, err := time.Parse(jsonlog.RFC3339NanoFixed+" ", ts.FindString(l))
			c.Assert(err, checker.IsNil, check.Commentf("Failed to parse timestamp from %v", l))
			// ensure we have padded 0's
			c.Assert(l[29], checker.Equals, uint8('Z'))
		}
	}
}

func (s *DockerSuite) TestLogsSeparateStderr(c *check.C) {
	msg := "stderr_log"
	out, _ := dockerCmd(c, "run", "-d", "busybox", "sh", "-c", fmt.Sprintf("echo %s 1>&2", msg))

	id := strings.TrimSpace(out)
	dockerCmd(c, "wait", id)

	stdout, stderr, _ := dockerCmdWithStdoutStderr(c, "logs", id)

	c.Assert(stdout, checker.Equals, "")

	stderr = strings.TrimSpace(stderr)

	c.Assert(stderr, checker.Equals, msg)
}

func (s *DockerSuite) TestLogsStderrInStdout(c *check.C) {
	// TODO Windows: Needs investigation why this fails. Obtained string includes
	// a bunch of ANSI escape sequences before the "stderr_log" message.
	testRequires(c, DaemonIsLinux)
	msg := "stderr_log"
	out, _ := dockerCmd(c, "run", "-d", "-t", "busybox", "sh", "-c", fmt.Sprintf("echo %s 1>&2", msg))

	id := strings.TrimSpace(out)
	dockerCmd(c, "wait", id)

	stdout, stderr, _ := dockerCmdWithStdoutStderr(c, "logs", id)
	c.Assert(stderr, checker.Equals, "")

	stdout = strings.TrimSpace(stdout)
	c.Assert(stdout, checker.Equals, msg)
}

func (s *DockerSuite) TestLogsTail(c *check.C) {
	testLen := 100
	out, _ := dockerCmd(c, "run", "-d", "busybox", "sh", "-c", fmt.Sprintf("for i in $(seq 1 %d); do echo =; done;", testLen))

	id := strings.TrimSpace(out)
	dockerCmd(c, "wait", id)

	out, _ = dockerCmd(c, "logs", "--tail", "5", id)

	lines := strings.Split(out, "\n")

	c.Assert(lines, checker.HasLen, 6)

	out, _ = dockerCmd(c, "logs", "--tail", "all", id)

	lines = strings.Split(out, "\n")

	c.Assert(lines, checker.HasLen, testLen+1)

	out, _, _ = dockerCmdWithStdoutStderr(c, "logs", "--tail", "random", id)

	lines = strings.Split(out, "\n")

	c.Assert(lines, checker.HasLen, testLen+1)
}

func (s *DockerSuite) TestLogsFollowStopped(c *check.C) {
	dockerCmd(c, "run", "--name=test", "busybox", "echo", "hello")
	id, err := getIDByName("test")
	c.Assert(err, check.IsNil)

	logsCmd := exec.Command(dockerBinary, "logs", "-f", id)
	c.Assert(logsCmd.Start(), checker.IsNil)

	errChan := make(chan error)
	go func() {
		errChan <- logsCmd.Wait()
		close(errChan)
	}()

	select {
	case err := <-errChan:
		c.Assert(err, checker.IsNil)
	case <-time.After(30 * time.Second):
		c.Fatal("Following logs is hanged")
	}
}

func (s *DockerSuite) TestLogsSince(c *check.C) {
	name := "testlogssince"
	dockerCmd(c, "run", "--name="+name, "busybox", "/bin/sh", "-c", "for i in $(seq 1 3); do sleep 2; echo log$i; done")
	out, _ := dockerCmd(c, "logs", "-t", name)

	log2Line := strings.Split(strings.Split(out, "\n")[1], " ")
	t, err := time.Parse(time.RFC3339Nano, log2Line[0]) // the timestamp log2 is written
	c.Assert(err, checker.IsNil)
	since := t.Unix() + 1 // add 1s so log1 & log2 doesn't show up
	out, _ = dockerCmd(c, "logs", "-t", fmt.Sprintf("--since=%v", since), name)

	// Skip 2 seconds
	unexpected := []string{"log1", "log2"}
	for _, v := range unexpected {
		c.Assert(out, checker.Not(checker.Contains), v, check.Commentf("unexpected log message returned, since=%v", since))
	}

	// Test to make sure a bad since format is caught by the client
	out, _, _ = dockerCmdWithError("logs", "-t", "--since=2006-01-02T15:04:0Z", name)
	c.Assert(out, checker.Contains, "cannot parse \"0Z\" as \"05\"", check.Commentf("bad since format passed to server"))

	// Test with default value specified and parameter omitted
	expected := []string{"log1", "log2", "log3"}
	for _, cmd := range []*exec.Cmd{
		exec.Command(dockerBinary, "logs", "-t", name),
		exec.Command(dockerBinary, "logs", "-t", "--since=0", name),
	} {
		out, _, err = runCommandWithOutput(cmd)
		c.Assert(err, checker.IsNil, check.Commentf("failed to log container: %s", out))
		for _, v := range expected {
			c.Assert(out, checker.Contains, v)
		}
	}
}

func (s *DockerSuite) TestLogsSinceFutureFollow(c *check.C) {
	// TODO Windows: Flakey on TP4. Enable for next technical preview.
	testRequires(c, DaemonIsLinux)
	name := "testlogssincefuturefollow"
	out, _ := dockerCmd(c, "run", "-d", "--name", name, "busybox", "/bin/sh", "-c", `for i in $(seq 1 5); do echo log$i; sleep 1; done`)

	// Extract one timestamp from the log file to give us a starting point for
	// our `--since` argument. Because the log producer runs in the background,
	// we need to check repeatedly for some output to be produced.
	var timestamp string
	for i := 0; i != 100 && timestamp == ""; i++ {
		if out, _ = dockerCmd(c, "logs", "-t", name); out == "" {
			time.Sleep(time.Millisecond * 100) // Retry
		} else {
			timestamp = strings.Split(strings.Split(out, "\n")[0], " ")[0]
		}
	}

	c.Assert(timestamp, checker.Not(checker.Equals), "")
	t, err := time.Parse(time.RFC3339Nano, timestamp)
	c.Assert(err, check.IsNil)

	since := t.Unix() + 2
	out, _ = dockerCmd(c, "logs", "-t", "-f", fmt.Sprintf("--since=%v", since), name)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	c.Assert(lines, checker.Not(checker.HasLen), 0)
	for _, v := range lines {
		ts, err := time.Parse(time.RFC3339Nano, strings.Split(v, " ")[0])
		c.Assert(err, checker.IsNil, check.Commentf("cannot parse timestamp output from log: '%v'", v))
		c.Assert(ts.Unix() >= since, checker.Equals, true, check.Commentf("earlier log found. since=%v logdate=%v", since, ts))
	}
}

// Regression test for #8832
func (s *DockerSuite) TestLogsFollowSlowStdoutConsumer(c *check.C) {
	// TODO Windows: Consider enabling post-TP4. Too expensive to run on TP4
	testRequires(c, DaemonIsLinux)
	out, _ := dockerCmd(c, "run", "-d", "busybox", "/bin/sh", "-c", `usleep 600000;yes X | head -c 200000`)

	id := strings.TrimSpace(out)

	stopSlowRead := make(chan bool)

	go func() {
		exec.Command(dockerBinary, "wait", id).Run()
		stopSlowRead <- true
	}()

	logCmd := exec.Command(dockerBinary, "logs", "-f", id)
	stdout, err := logCmd.StdoutPipe()
	c.Assert(err, checker.IsNil)
	c.Assert(logCmd.Start(), checker.IsNil)

	// First read slowly
	bytes1, err := consumeWithSpeed(stdout, 10, 50*time.Millisecond, stopSlowRead)
	c.Assert(err, checker.IsNil)

	// After the container has finished we can continue reading fast
	bytes2, err := consumeWithSpeed(stdout, 32*1024, 0, nil)
	c.Assert(err, checker.IsNil)

	actual := bytes1 + bytes2
	expected := 200000
	c.Assert(actual, checker.Equals, expected)
}

func (s *DockerSuite) TestLogsFollowGoroutinesWithStdout(c *check.C) {
	out, _ := dockerCmd(c, "run", "-d", "busybox", "/bin/sh", "-c", "while true; do echo hello; sleep 2; done")
	id := strings.TrimSpace(out)
	c.Assert(waitRun(id), checker.IsNil)

	type info struct {
		NGoroutines int
	}
	getNGoroutines := func() int {
		var i info
		status, b, err := sockRequest("GET", "/info", nil)
		c.Assert(err, checker.IsNil)
		c.Assert(status, checker.Equals, 200)
		c.Assert(json.Unmarshal(b, &i), checker.IsNil)
		return i.NGoroutines
	}

	nroutines := getNGoroutines()

	cmd := exec.Command(dockerBinary, "logs", "-f", id)
	r, w := io.Pipe()
	cmd.Stdout = w
	c.Assert(cmd.Start(), checker.IsNil)

	// Make sure pipe is written to
	chErr := make(chan error)
	go func() {
		b := make([]byte, 1)
		_, err := r.Read(b)
		chErr <- err
	}()
	c.Assert(<-chErr, checker.IsNil)
	c.Assert(cmd.Process.Kill(), checker.IsNil)

	// NGoroutines is not updated right away, so we need to wait before failing
	t := time.After(30 * time.Second)
	for {
		select {
		case <-t:
			n := getNGoroutines()
			c.Assert(n <= nroutines, checker.Equals, true, check.Commentf("leaked goroutines: expected less than or equal to %d, got: %d", nroutines, n))

		default:
			if n := getNGoroutines(); n <= nroutines {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func (s *DockerSuite) TestLogsFollowGoroutinesNoOutput(c *check.C) {
	out, _ := dockerCmd(c, "run", "-d", "busybox", "/bin/sh", "-c", "while true; do sleep 2; done")
	id := strings.TrimSpace(out)
	c.Assert(waitRun(id), checker.IsNil)

	type info struct {
		NGoroutines int
	}
	getNGoroutines := func() int {
		var i info
		status, b, err := sockRequest("GET", "/info", nil)
		c.Assert(err, checker.IsNil)
		c.Assert(status, checker.Equals, 200)
		c.Assert(json.Unmarshal(b, &i), checker.IsNil)
		return i.NGoroutines
	}

	nroutines := getNGoroutines()

	cmd := exec.Command(dockerBinary, "logs", "-f", id)
	c.Assert(cmd.Start(), checker.IsNil)
	time.Sleep(200 * time.Millisecond)
	c.Assert(cmd.Process.Kill(), checker.IsNil)

	// NGoroutines is not updated right away, so we need to wait before failing
	t := time.After(30 * time.Second)
	for {
		select {
		case <-t:
			n := getNGoroutines()
			c.Assert(n <= nroutines, checker.Equals, true, check.Commentf("leaked goroutines: expected less than or equal to %d, got: %d", nroutines, n))

		default:
			if n := getNGoroutines(); n <= nroutines {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func (s *DockerSuite) TestLogsCLIContainerNotFound(c *check.C) {
	name := "testlogsnocontainer"
	out, _, _ := dockerCmdWithError("logs", name)
	message := fmt.Sprintf("Error: No such container: %s\n", name)
	c.Assert(out, checker.Equals, message)
}
