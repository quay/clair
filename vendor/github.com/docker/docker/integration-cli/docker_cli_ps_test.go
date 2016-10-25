package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/pkg/integration/checker"
	"github.com/docker/docker/pkg/stringid"
	"github.com/go-check/check"
)

func (s *DockerSuite) TestPsListContainersBase(c *check.C) {
	out, _ := runSleepingContainer(c, "-d")
	firstID := strings.TrimSpace(out)

	out, _ = runSleepingContainer(c, "-d")
	secondID := strings.TrimSpace(out)

	// not long running
	out, _ = dockerCmd(c, "run", "-d", "busybox", "true")
	thirdID := strings.TrimSpace(out)

	out, _ = runSleepingContainer(c, "-d")
	fourthID := strings.TrimSpace(out)

	// make sure the second is running
	c.Assert(waitRun(secondID), checker.IsNil)

	// make sure third one is not running
	dockerCmd(c, "wait", thirdID)

	// make sure the forth is running
	c.Assert(waitRun(fourthID), checker.IsNil)

	// all
	out, _ = dockerCmd(c, "ps", "-a")
	c.Assert(assertContainerList(out, []string{fourthID, thirdID, secondID, firstID}), checker.Equals, true, check.Commentf("ALL: Container list is not in the correct order: \n%s", out))

	// running
	out, _ = dockerCmd(c, "ps")
	c.Assert(assertContainerList(out, []string{fourthID, secondID, firstID}), checker.Equals, true, check.Commentf("RUNNING: Container list is not in the correct order: \n%s", out))

	// limit
	out, _ = dockerCmd(c, "ps", "-n=2", "-a")
	expected := []string{fourthID, thirdID}
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("LIMIT & ALL: Container list is not in the correct order: \n%s", out))

	out, _ = dockerCmd(c, "ps", "-n=2")
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("LIMIT: Container list is not in the correct order: \n%s", out))

	// filter since
	out, _ = dockerCmd(c, "ps", "-f", "since="+firstID, "-a")
	expected = []string{fourthID, thirdID, secondID}
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("SINCE filter & ALL: Container list is not in the correct order: \n%s", out))

	out, _ = dockerCmd(c, "ps", "-f", "since="+firstID)
	expected = []string{fourthID, secondID}
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("SINCE filter: Container list is not in the correct order: \n%s", out))

	out, _ = dockerCmd(c, "ps", "-f", "since="+thirdID)
	expected = []string{fourthID}
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("SINCE filter: Container list is not in the correct order: \n%s", out))

	// filter before
	out, _ = dockerCmd(c, "ps", "-f", "before="+fourthID, "-a")
	expected = []string{thirdID, secondID, firstID}
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("BEFORE filter & ALL: Container list is not in the correct order: \n%s", out))

	out, _ = dockerCmd(c, "ps", "-f", "before="+fourthID)
	expected = []string{secondID, firstID}
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("BEFORE filter: Container list is not in the correct order: \n%s", out))

	out, _ = dockerCmd(c, "ps", "-f", "before="+thirdID)
	expected = []string{secondID, firstID}
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("SINCE filter: Container list is not in the correct order: \n%s", out))

	// filter since & before
	out, _ = dockerCmd(c, "ps", "-f", "since="+firstID, "-f", "before="+fourthID, "-a")
	expected = []string{thirdID, secondID}
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("SINCE filter, BEFORE filter & ALL: Container list is not in the correct order: \n%s", out))

	out, _ = dockerCmd(c, "ps", "-f", "since="+firstID, "-f", "before="+fourthID)
	expected = []string{secondID}
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("SINCE filter, BEFORE filter: Container list is not in the correct order: \n%s", out))

	// filter since & limit
	out, _ = dockerCmd(c, "ps", "-f", "since="+firstID, "-n=2", "-a")
	expected = []string{fourthID, thirdID}

	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("SINCE filter, LIMIT & ALL: Container list is not in the correct order: \n%s", out))

	out, _ = dockerCmd(c, "ps", "-f", "since="+firstID, "-n=2")
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("SINCE filter, LIMIT: Container list is not in the correct order: \n%s", out))

	// filter before & limit
	out, _ = dockerCmd(c, "ps", "-f", "before="+fourthID, "-n=1", "-a")
	expected = []string{thirdID}
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("BEFORE filter, LIMIT & ALL: Container list is not in the correct order: \n%s", out))

	out, _ = dockerCmd(c, "ps", "-f", "before="+fourthID, "-n=1")
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("BEFORE filter, LIMIT: Container list is not in the correct order: \n%s", out))

	// filter since & filter before & limit
	out, _ = dockerCmd(c, "ps", "-f", "since="+firstID, "-f", "before="+fourthID, "-n=1", "-a")
	expected = []string{thirdID}
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("SINCE filter, BEFORE filter, LIMIT & ALL: Container list is not in the correct order: \n%s", out))

	out, _ = dockerCmd(c, "ps", "-f", "since="+firstID, "-f", "before="+fourthID, "-n=1")
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("SINCE filter, BEFORE filter, LIMIT: Container list is not in the correct order: \n%s", out))

}

// FIXME remove this for 1.12 as --since and --before are deprecated
func (s *DockerSuite) TestPsListContainersDeprecatedSinceAndBefore(c *check.C) {
	out, _ := runSleepingContainer(c, "-d")
	firstID := strings.TrimSpace(out)

	out, _ = runSleepingContainer(c, "-d")
	secondID := strings.TrimSpace(out)

	// not long running
	out, _ = dockerCmd(c, "run", "-d", "busybox", "true")
	thirdID := strings.TrimSpace(out)

	out, _ = runSleepingContainer(c, "-d")
	fourthID := strings.TrimSpace(out)

	// make sure the second is running
	c.Assert(waitRun(secondID), checker.IsNil)

	// make sure third one is not running
	dockerCmd(c, "wait", thirdID)

	// make sure the forth is running
	c.Assert(waitRun(fourthID), checker.IsNil)

	// since
	out, _ = dockerCmd(c, "ps", "--since="+firstID, "-a")
	expected := []string{fourthID, thirdID, secondID}
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("SINCE & ALL: Container list is not in the correct order: %v \n%s", expected, out))

	out, _ = dockerCmd(c, "ps", "--since="+firstID)
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("SINCE: Container list is not in the correct order: %v \n%s", expected, out))

	// before
	out, _ = dockerCmd(c, "ps", "--before="+thirdID, "-a")
	expected = []string{secondID, firstID}
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("BEFORE & ALL: Container list is not in the correct order: %v \n%s", expected, out))

	out, _ = dockerCmd(c, "ps", "--before="+thirdID)
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("BEFORE: Container list is not in the correct order: %v \n%s", expected, out))

	// since & before
	out, _ = dockerCmd(c, "ps", "--since="+firstID, "--before="+fourthID, "-a")
	expected = []string{thirdID, secondID}
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("SINCE, BEFORE & ALL: Container list is not in the correct order: %v \n%s", expected, out))

	out, _ = dockerCmd(c, "ps", "--since="+firstID, "--before="+fourthID)
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("SINCE, BEFORE: Container list is not in the correct order: %v \n%s", expected, out))

	// since & limit
	out, _ = dockerCmd(c, "ps", "--since="+firstID, "-n=2", "-a")
	expected = []string{fourthID, thirdID}
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("SINCE, LIMIT & ALL: Container list is not in the correct order: %v \n%s", expected, out))

	out, _ = dockerCmd(c, "ps", "--since="+firstID, "-n=2")
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("SINCE, LIMIT: Container list is not in the correct order: %v \n%s", expected, out))

	// before & limit
	out, _ = dockerCmd(c, "ps", "--before="+fourthID, "-n=1", "-a")
	expected = []string{thirdID}
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("BEFORE, LIMIT & ALL: Container list is not in the correct order: %v \n%s", expected, out))

	out, _ = dockerCmd(c, "ps", "--before="+fourthID, "-n=1")
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("BEFORE, LIMIT: Container list is not in the correct order: %v \n%s", expected, out))

	// since & before & limit
	out, _ = dockerCmd(c, "ps", "--since="+firstID, "--before="+fourthID, "-n=1", "-a")
	expected = []string{thirdID}
	c.Assert(assertContainerList(out, expected), checker.Equals, true, check.Commentf("SINCE, BEFORE, LIMIT & ALL: Container list is not in the correct order: %v \n%s", expected, out))

}

func assertContainerList(out string, expected []string) bool {
	lines := strings.Split(strings.Trim(out, "\n "), "\n")
	// FIXME remove this for 1.12 as --since and --before are deprecated
	// This is here to remove potential Warning: lines (printed out with deprecated flags)
	for i := 0; i < 2; i++ {
		if strings.Contains(lines[0], "Warning:") {
			lines = lines[1:]
		}
	}

	if len(lines)-1 != len(expected) {
		return false
	}

	containerIDIndex := strings.Index(lines[0], "CONTAINER ID")
	for i := 0; i < len(expected); i++ {
		foundID := lines[i+1][containerIDIndex : containerIDIndex+12]
		if foundID != expected[i][:12] {
			return false
		}
	}

	return true
}

func (s *DockerSuite) TestPsListContainersSize(c *check.C) {
	// Problematic on Windows as it doesn't report the size correctly @swernli
	testRequires(c, DaemonIsLinux)
	dockerCmd(c, "run", "-d", "busybox")

	baseOut, _ := dockerCmd(c, "ps", "-s", "-n=1")
	baseLines := strings.Split(strings.Trim(baseOut, "\n "), "\n")
	baseSizeIndex := strings.Index(baseLines[0], "SIZE")
	baseFoundsize := baseLines[1][baseSizeIndex:]
	baseBytes, err := strconv.Atoi(strings.Split(baseFoundsize, " ")[0])
	c.Assert(err, checker.IsNil)

	name := "test_size"
	dockerCmd(c, "run", "--name", name, "busybox", "sh", "-c", "echo 1 > test")
	id, err := getIDByName(name)
	c.Assert(err, checker.IsNil)

	runCmd := exec.Command(dockerBinary, "ps", "-s", "-n=1")
	var out string

	wait := make(chan struct{})
	go func() {
		out, _, err = runCommandWithOutput(runCmd)
		close(wait)
	}()
	select {
	case <-wait:
	case <-time.After(3 * time.Second):
		c.Fatalf("Calling \"docker ps -s\" timed out!")
	}
	c.Assert(err, checker.IsNil)
	lines := strings.Split(strings.Trim(out, "\n "), "\n")
	c.Assert(lines, checker.HasLen, 2, check.Commentf("Expected 2 lines for 'ps -s -n=1' output, got %d", len(lines)))
	sizeIndex := strings.Index(lines[0], "SIZE")
	idIndex := strings.Index(lines[0], "CONTAINER ID")
	foundID := lines[1][idIndex : idIndex+12]
	c.Assert(foundID, checker.Equals, id[:12], check.Commentf("Expected id %s, got %s", id[:12], foundID))
	expectedSize := fmt.Sprintf("%d B", (2 + baseBytes))
	foundSize := lines[1][sizeIndex:]
	c.Assert(foundSize, checker.Contains, expectedSize, check.Commentf("Expected size %q, got %q", expectedSize, foundSize))
}

func (s *DockerSuite) TestPsListContainersFilterStatus(c *check.C) {
	// start exited container
	out, _ := dockerCmd(c, "run", "-d", "busybox")
	firstID := strings.TrimSpace(out)

	// make sure the exited container is not running
	dockerCmd(c, "wait", firstID)

	// start running container
	out, _ = dockerCmd(c, "run", "-itd", "busybox")
	secondID := strings.TrimSpace(out)

	// filter containers by exited
	out, _ = dockerCmd(c, "ps", "--no-trunc", "-q", "--filter=status=exited")
	containerOut := strings.TrimSpace(out)
	c.Assert(containerOut, checker.Equals, firstID)

	out, _ = dockerCmd(c, "ps", "-a", "--no-trunc", "-q", "--filter=status=running")
	containerOut = strings.TrimSpace(out)
	c.Assert(containerOut, checker.Equals, secondID)

	out, _, _ = dockerCmdWithTimeout(time.Second*60, "ps", "-a", "-q", "--filter=status=rubbish")
	c.Assert(out, checker.Contains, "Unrecognised filter value for status", check.Commentf("Expected error response due to invalid status filter output: %q", out))

	// Windows doesn't support pausing of containers
	if daemonPlatform != "windows" {
		// pause running container
		out, _ = dockerCmd(c, "run", "-itd", "busybox")
		pausedID := strings.TrimSpace(out)
		dockerCmd(c, "pause", pausedID)
		// make sure the container is unpaused to let the daemon stop it properly
		defer func() { dockerCmd(c, "unpause", pausedID) }()

		out, _ = dockerCmd(c, "ps", "--no-trunc", "-q", "--filter=status=paused")
		containerOut = strings.TrimSpace(out)
		c.Assert(containerOut, checker.Equals, pausedID)
	}
}

func (s *DockerSuite) TestPsListContainersFilterID(c *check.C) {
	// start container
	out, _ := dockerCmd(c, "run", "-d", "busybox")
	firstID := strings.TrimSpace(out)

	// start another container
	runSleepingContainer(c)

	// filter containers by id
	out, _ = dockerCmd(c, "ps", "-a", "-q", "--filter=id="+firstID)
	containerOut := strings.TrimSpace(out)
	c.Assert(containerOut, checker.Equals, firstID[:12], check.Commentf("Expected id %s, got %s for exited filter, output: %q", firstID[:12], containerOut, out))

}

func (s *DockerSuite) TestPsListContainersFilterName(c *check.C) {
	// start container
	dockerCmd(c, "run", "--name=a_name_to_match", "busybox")
	id, err := getIDByName("a_name_to_match")
	c.Assert(err, check.IsNil)

	// start another container
	runSleepingContainer(c, "--name=b_name_to_match")

	// filter containers by name
	out, _ := dockerCmd(c, "ps", "-a", "-q", "--filter=name=a_name_to_match")
	containerOut := strings.TrimSpace(out)
	c.Assert(containerOut, checker.Equals, id[:12], check.Commentf("Expected id %s, got %s for exited filter, output: %q", id[:12], containerOut, out))
}

// Test for the ancestor filter for ps.
// There is also the same test but with image:tag@digest in docker_cli_by_digest_test.go
//
// What the test setups :
// - Create 2 image based on busybox using the same repository but different tags
// - Create an image based on the previous image (images_ps_filter_test2)
// - Run containers for each of those image (busybox, images_ps_filter_test1, images_ps_filter_test2)
// - Filter them out :P
func (s *DockerSuite) TestPsListContainersFilterAncestorImage(c *check.C) {
	// Build images
	imageName1 := "images_ps_filter_test1"
	imageID1, err := buildImage(imageName1,
		`FROM busybox
		 LABEL match me 1`, true)
	c.Assert(err, checker.IsNil)

	imageName1Tagged := "images_ps_filter_test1:tag"
	imageID1Tagged, err := buildImage(imageName1Tagged,
		`FROM busybox
		 LABEL match me 1 tagged`, true)
	c.Assert(err, checker.IsNil)

	imageName2 := "images_ps_filter_test2"
	imageID2, err := buildImage(imageName2,
		fmt.Sprintf(`FROM %s
		 LABEL match me 2`, imageName1), true)
	c.Assert(err, checker.IsNil)

	// start containers
	dockerCmd(c, "run", "--name=first", "busybox", "echo", "hello")
	firstID, err := getIDByName("first")
	c.Assert(err, check.IsNil)

	// start another container
	dockerCmd(c, "run", "--name=second", "busybox", "echo", "hello")
	secondID, err := getIDByName("second")
	c.Assert(err, check.IsNil)

	// start third container
	dockerCmd(c, "run", "--name=third", imageName1, "echo", "hello")
	thirdID, err := getIDByName("third")
	c.Assert(err, check.IsNil)

	// start fourth container
	dockerCmd(c, "run", "--name=fourth", imageName1Tagged, "echo", "hello")
	fourthID, err := getIDByName("fourth")
	c.Assert(err, check.IsNil)

	// start fifth container
	dockerCmd(c, "run", "--name=fifth", imageName2, "echo", "hello")
	fifthID, err := getIDByName("fifth")
	c.Assert(err, check.IsNil)

	var filterTestSuite = []struct {
		filterName  string
		expectedIDs []string
	}{
		// non existent stuff
		{"nonexistent", []string{}},
		{"nonexistent:tag", []string{}},
		// image
		{"busybox", []string{firstID, secondID, thirdID, fourthID, fifthID}},
		{imageName1, []string{thirdID, fifthID}},
		{imageName2, []string{fifthID}},
		// image:tag
		{fmt.Sprintf("%s:latest", imageName1), []string{thirdID, fifthID}},
		{imageName1Tagged, []string{fourthID}},
		// short-id
		{stringid.TruncateID(imageID1), []string{thirdID, fifthID}},
		{stringid.TruncateID(imageID2), []string{fifthID}},
		// full-id
		{imageID1, []string{thirdID, fifthID}},
		{imageID1Tagged, []string{fourthID}},
		{imageID2, []string{fifthID}},
	}

	var out string
	for _, filter := range filterTestSuite {
		out, _ = dockerCmd(c, "ps", "-a", "-q", "--no-trunc", "--filter=ancestor="+filter.filterName)
		checkPsAncestorFilterOutput(c, out, filter.filterName, filter.expectedIDs)
	}

	// Multiple ancestor filter
	out, _ = dockerCmd(c, "ps", "-a", "-q", "--no-trunc", "--filter=ancestor="+imageName2, "--filter=ancestor="+imageName1Tagged)
	checkPsAncestorFilterOutput(c, out, imageName2+","+imageName1Tagged, []string{fourthID, fifthID})
}

func checkPsAncestorFilterOutput(c *check.C, out string, filterName string, expectedIDs []string) {
	actualIDs := []string{}
	if out != "" {
		actualIDs = strings.Split(out[:len(out)-1], "\n")
	}
	sort.Strings(actualIDs)
	sort.Strings(expectedIDs)

	c.Assert(actualIDs, checker.HasLen, len(expectedIDs), check.Commentf("Expected filtered container(s) for %s ancestor filter to be %v:%v, got %v:%v", filterName, len(expectedIDs), expectedIDs, len(actualIDs), actualIDs))
	if len(expectedIDs) > 0 {
		same := true
		for i := range expectedIDs {
			if actualIDs[i] != expectedIDs[i] {
				c.Logf("%s, %s", actualIDs[i], expectedIDs[i])
				same = false
				break
			}
		}
		c.Assert(same, checker.Equals, true, check.Commentf("Expected filtered container(s) for %s ancestor filter to be %v, got %v", filterName, expectedIDs, actualIDs))
	}
}

func (s *DockerSuite) TestPsListContainersFilterLabel(c *check.C) {
	// start container
	dockerCmd(c, "run", "--name=first", "-l", "match=me", "-l", "second=tag", "busybox")
	firstID, err := getIDByName("first")
	c.Assert(err, check.IsNil)

	// start another container
	dockerCmd(c, "run", "--name=second", "-l", "match=me too", "busybox")
	secondID, err := getIDByName("second")
	c.Assert(err, check.IsNil)

	// start third container
	dockerCmd(c, "run", "--name=third", "-l", "nomatch=me", "busybox")
	thirdID, err := getIDByName("third")
	c.Assert(err, check.IsNil)

	// filter containers by exact match
	out, _ := dockerCmd(c, "ps", "-a", "-q", "--no-trunc", "--filter=label=match=me")
	containerOut := strings.TrimSpace(out)
	c.Assert(containerOut, checker.Equals, firstID, check.Commentf("Expected id %s, got %s for exited filter, output: %q", firstID, containerOut, out))

	// filter containers by two labels
	out, _ = dockerCmd(c, "ps", "-a", "-q", "--no-trunc", "--filter=label=match=me", "--filter=label=second=tag")
	containerOut = strings.TrimSpace(out)
	c.Assert(containerOut, checker.Equals, firstID, check.Commentf("Expected id %s, got %s for exited filter, output: %q", firstID, containerOut, out))

	// filter containers by two labels, but expect not found because of AND behavior
	out, _ = dockerCmd(c, "ps", "-a", "-q", "--no-trunc", "--filter=label=match=me", "--filter=label=second=tag-no")
	containerOut = strings.TrimSpace(out)
	c.Assert(containerOut, checker.Equals, "", check.Commentf("Expected nothing, got %s for exited filter, output: %q", containerOut, out))

	// filter containers by exact key
	out, _ = dockerCmd(c, "ps", "-a", "-q", "--no-trunc", "--filter=label=match")
	containerOut = strings.TrimSpace(out)
	c.Assert(containerOut, checker.Contains, firstID)
	c.Assert(containerOut, checker.Contains, secondID)
	c.Assert(containerOut, checker.Not(checker.Contains), thirdID)
}

func (s *DockerSuite) TestPsListContainersFilterExited(c *check.C) {
	runSleepingContainer(c, "--name=sleep")

	dockerCmd(c, "run", "--name", "zero1", "busybox", "true")
	firstZero, err := getIDByName("zero1")
	c.Assert(err, checker.IsNil)

	dockerCmd(c, "run", "--name", "zero2", "busybox", "true")
	secondZero, err := getIDByName("zero2")
	c.Assert(err, checker.IsNil)

	out, _, err := dockerCmdWithError("run", "--name", "nonzero1", "busybox", "false")
	c.Assert(err, checker.NotNil, check.Commentf("Should fail.", out, err))

	firstNonZero, err := getIDByName("nonzero1")
	c.Assert(err, checker.IsNil)

	out, _, err = dockerCmdWithError("run", "--name", "nonzero2", "busybox", "false")
	c.Assert(err, checker.NotNil, check.Commentf("Should fail.", out, err))
	secondNonZero, err := getIDByName("nonzero2")
	c.Assert(err, checker.IsNil)

	// filter containers by exited=0
	out, _ = dockerCmd(c, "ps", "-a", "-q", "--no-trunc", "--filter=exited=0")
	ids := strings.Split(strings.TrimSpace(out), "\n")
	c.Assert(ids, checker.HasLen, 2, check.Commentf("Should be 2 zero exited containers got %d: %s", len(ids), out))
	c.Assert(ids[0], checker.Equals, secondZero, check.Commentf("First in list should be %q, got %q", secondZero, ids[0]))
	c.Assert(ids[1], checker.Equals, firstZero, check.Commentf("Second in list should be %q, got %q", firstZero, ids[1]))

	out, _ = dockerCmd(c, "ps", "-a", "-q", "--no-trunc", "--filter=exited=1")
	ids = strings.Split(strings.TrimSpace(out), "\n")
	c.Assert(ids, checker.HasLen, 2, check.Commentf("Should be 2 zero exited containers got %d", len(ids)))
	c.Assert(ids[0], checker.Equals, secondNonZero, check.Commentf("First in list should be %q, got %q", secondNonZero, ids[0]))
	c.Assert(ids[1], checker.Equals, firstNonZero, check.Commentf("Second in list should be %q, got %q", firstNonZero, ids[1]))

}

func (s *DockerSuite) TestPsRightTagName(c *check.C) {
	// TODO Investigate further why this fails on Windows to Windows CI
	testRequires(c, DaemonIsLinux)
	tag := "asybox:shmatest"
	dockerCmd(c, "tag", "busybox", tag)

	var id1 string
	out, _ := runSleepingContainer(c)
	id1 = strings.TrimSpace(string(out))

	var id2 string
	out, _ = runSleepingContainerInImage(c, tag)
	id2 = strings.TrimSpace(string(out))

	var imageID string
	out = inspectField(c, "busybox", "Id")
	imageID = strings.TrimSpace(string(out))

	var id3 string
	out, _ = runSleepingContainerInImage(c, imageID)
	id3 = strings.TrimSpace(string(out))

	out, _ = dockerCmd(c, "ps", "--no-trunc")
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	// skip header
	lines = lines[1:]
	c.Assert(lines, checker.HasLen, 3, check.Commentf("There should be 3 running container, got %d", len(lines)))
	for _, line := range lines {
		f := strings.Fields(line)
		switch f[0] {
		case id1:
			c.Assert(f[1], checker.Equals, "busybox", check.Commentf("Expected %s tag for id %s, got %s", "busybox", id1, f[1]))
		case id2:
			c.Assert(f[1], checker.Equals, tag, check.Commentf("Expected %s tag for id %s, got %s", tag, id2, f[1]))
		case id3:
			c.Assert(f[1], checker.Equals, imageID, check.Commentf("Expected %s imageID for id %s, got %s", tag, id3, f[1]))
		default:
			c.Fatalf("Unexpected id %s, expected %s and %s and %s", f[0], id1, id2, id3)
		}
	}
}

func (s *DockerSuite) TestPsLinkedWithNoTrunc(c *check.C) {
	// Problematic on Windows as it doesn't support links as of Jan 2016
	testRequires(c, DaemonIsLinux)
	runSleepingContainer(c, "--name=first")
	runSleepingContainer(c, "--name=second", "--link=first:first")

	out, _ := dockerCmd(c, "ps", "--no-trunc")
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	// strip header
	lines = lines[1:]
	expected := []string{"second", "first,second/first"}
	var names []string
	for _, l := range lines {
		fields := strings.Fields(l)
		names = append(names, fields[len(fields)-1])
	}
	c.Assert(expected, checker.DeepEquals, names, check.Commentf("Expected array: %v, got: %v", expected, names))
}

func (s *DockerSuite) TestPsGroupPortRange(c *check.C) {
	// Problematic on Windows as it doesn't support port ranges as of Jan 2016
	testRequires(c, DaemonIsLinux)
	portRange := "3800-3900"
	dockerCmd(c, "run", "-d", "--name", "porttest", "-p", portRange+":"+portRange, "busybox", "top")

	out, _ := dockerCmd(c, "ps")

	c.Assert(string(out), checker.Contains, portRange, check.Commentf("docker ps output should have had the port range %q: %s", portRange, string(out)))

}

func (s *DockerSuite) TestPsWithSize(c *check.C) {
	// Problematic on Windows as it doesn't report the size correctly @swernli
	testRequires(c, DaemonIsLinux)
	dockerCmd(c, "run", "-d", "--name", "sizetest", "busybox", "top")

	out, _ := dockerCmd(c, "ps", "--size")
	c.Assert(out, checker.Contains, "virtual", check.Commentf("docker ps with --size should show virtual size of container"))
}

func (s *DockerSuite) TestPsListContainersFilterCreated(c *check.C) {
	// create a container
	out, _ := dockerCmd(c, "create", "busybox")
	cID := strings.TrimSpace(out)
	shortCID := cID[:12]

	// Make sure it DOESN'T show up w/o a '-a' for normal 'ps'
	out, _ = dockerCmd(c, "ps", "-q")
	c.Assert(out, checker.Not(checker.Contains), shortCID, check.Commentf("Should have not seen '%s' in ps output:\n%s", shortCID, out))

	// Make sure it DOES show up as 'Created' for 'ps -a'
	out, _ = dockerCmd(c, "ps", "-a")

	hits := 0
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, shortCID) {
			continue
		}
		hits++
		c.Assert(line, checker.Contains, "Created", check.Commentf("Missing 'Created' on '%s'", line))
	}

	c.Assert(hits, checker.Equals, 1, check.Commentf("Should have seen '%s' in ps -a output once:%d\n%s", shortCID, hits, out))

	// filter containers by 'create' - note, no -a needed
	out, _ = dockerCmd(c, "ps", "-q", "-f", "status=created")
	containerOut := strings.TrimSpace(out)
	c.Assert(cID, checker.HasPrefix, containerOut)
}

func (s *DockerSuite) TestPsFormatMultiNames(c *check.C) {
	// Problematic on Windows as it doesn't support link as of Jan 2016
	testRequires(c, DaemonIsLinux)
	//create 2 containers and link them
	dockerCmd(c, "run", "--name=child", "-d", "busybox", "top")
	dockerCmd(c, "run", "--name=parent", "--link=child:linkedone", "-d", "busybox", "top")

	//use the new format capabilities to only list the names and --no-trunc to get all names
	out, _ := dockerCmd(c, "ps", "--format", "{{.Names}}", "--no-trunc")
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	expected := []string{"parent", "child,parent/linkedone"}
	var names []string
	for _, l := range lines {
		names = append(names, l)
	}
	c.Assert(expected, checker.DeepEquals, names, check.Commentf("Expected array with non-truncated names: %v, got: %v", expected, names))

	//now list without turning off truncation and make sure we only get the non-link names
	out, _ = dockerCmd(c, "ps", "--format", "{{.Names}}")
	lines = strings.Split(strings.TrimSpace(string(out)), "\n")
	expected = []string{"parent", "child"}
	var truncNames []string
	for _, l := range lines {
		truncNames = append(truncNames, l)
	}
	c.Assert(expected, checker.DeepEquals, truncNames, check.Commentf("Expected array with truncated names: %v, got: %v", expected, truncNames))

}

func (s *DockerSuite) TestPsFormatHeaders(c *check.C) {
	// make sure no-container "docker ps" still prints the header row
	out, _ := dockerCmd(c, "ps", "--format", "table {{.ID}}")
	c.Assert(out, checker.Equals, "CONTAINER ID\n", check.Commentf(`Expected 'CONTAINER ID\n', got %v`, out))

	// verify that "docker ps" with a container still prints the header row also
	runSleepingContainer(c, "--name=test")
	out, _ = dockerCmd(c, "ps", "--format", "table {{.Names}}")
	c.Assert(out, checker.Equals, "NAMES\ntest\n", check.Commentf(`Expected 'NAMES\ntest\n', got %v`, out))
}

func (s *DockerSuite) TestPsDefaultFormatAndQuiet(c *check.C) {
	config := `{
		"psFormat": "default {{ .ID }}"
}`
	d, err := ioutil.TempDir("", "integration-cli-")
	c.Assert(err, checker.IsNil)
	defer os.RemoveAll(d)

	err = ioutil.WriteFile(filepath.Join(d, "config.json"), []byte(config), 0644)
	c.Assert(err, checker.IsNil)

	out, _ := runSleepingContainer(c, "--name=test")
	id := strings.TrimSpace(out)

	out, _ = dockerCmd(c, "--config", d, "ps", "-q")
	c.Assert(id, checker.HasPrefix, strings.TrimSpace(out), check.Commentf("Expected to print only the container id, got %v\n", out))
}

// Test for GitHub issue #12595
func (s *DockerSuite) TestPsImageIDAfterUpdate(c *check.C) {
	// TODO: Investigate why this fails on Windows to Windows CI further.
	testRequires(c, DaemonIsLinux)
	originalImageName := "busybox:TestPsImageIDAfterUpdate-original"
	updatedImageName := "busybox:TestPsImageIDAfterUpdate-updated"

	runCmd := exec.Command(dockerBinary, "tag", "busybox:latest", originalImageName)
	out, _, err := runCommandWithOutput(runCmd)
	c.Assert(err, checker.IsNil)

	originalImageID, err := getIDByName(originalImageName)
	c.Assert(err, checker.IsNil)

	runCmd = exec.Command(dockerBinary, append([]string{"run", "-d", originalImageName}, defaultSleepCommand...)...)
	out, _, err = runCommandWithOutput(runCmd)
	c.Assert(err, checker.IsNil)
	containerID := strings.TrimSpace(out)

	linesOut, err := exec.Command(dockerBinary, "ps", "--no-trunc").CombinedOutput()
	c.Assert(err, checker.IsNil)

	lines := strings.Split(strings.TrimSpace(string(linesOut)), "\n")
	// skip header
	lines = lines[1:]
	c.Assert(len(lines), checker.Equals, 1)

	for _, line := range lines {
		f := strings.Fields(line)
		c.Assert(f[1], checker.Equals, originalImageName)
	}

	runCmd = exec.Command(dockerBinary, "commit", containerID, updatedImageName)
	out, _, err = runCommandWithOutput(runCmd)
	c.Assert(err, checker.IsNil)

	runCmd = exec.Command(dockerBinary, "tag", "-f", updatedImageName, originalImageName)
	out, _, err = runCommandWithOutput(runCmd)
	c.Assert(err, checker.IsNil)

	linesOut, err = exec.Command(dockerBinary, "ps", "--no-trunc").CombinedOutput()
	c.Assert(err, checker.IsNil)

	lines = strings.Split(strings.TrimSpace(string(linesOut)), "\n")
	// skip header
	lines = lines[1:]
	c.Assert(len(lines), checker.Equals, 1)

	for _, line := range lines {
		f := strings.Fields(line)
		c.Assert(f[1], checker.Equals, originalImageID)
	}

}

func (s *DockerSuite) TestPsNotShowPortsOfStoppedContainer(c *check.C) {
	testRequires(c, DaemonIsLinux)
	dockerCmd(c, "run", "--name=foo", "-d", "-p", "5000:5000", "busybox", "top")
	c.Assert(waitRun("foo"), checker.IsNil)
	out, _ := dockerCmd(c, "ps")
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	expected := "0.0.0.0:5000->5000/tcp"
	fields := strings.Fields(lines[1])
	c.Assert(fields[len(fields)-2], checker.Equals, expected, check.Commentf("Expected: %v, got: %v", expected, fields[len(fields)-2]))

	dockerCmd(c, "kill", "foo")
	dockerCmd(c, "wait", "foo")
	out, _ = dockerCmd(c, "ps", "-l")
	lines = strings.Split(strings.TrimSpace(string(out)), "\n")
	fields = strings.Fields(lines[1])
	c.Assert(fields[len(fields)-2], checker.Not(checker.Equals), expected, check.Commentf("Should not got %v", expected))
}

func (s *DockerSuite) TestPsShowMounts(c *check.C) {
	prefix, slash := getPrefixAndSlashFromDaemonPlatform()

	mp := prefix + slash + "test"

	dockerCmd(c, "volume", "create", "--name", "ps-volume-test")
	runSleepingContainer(c, "--name=volume-test-1", "--volume", "ps-volume-test:"+mp)
	c.Assert(waitRun("volume-test-1"), checker.IsNil)
	runSleepingContainer(c, "--name=volume-test-2", "--volume", mp)
	c.Assert(waitRun("volume-test-2"), checker.IsNil)

	out, _ := dockerCmd(c, "ps", "--format", "{{.Names}} {{.Mounts}}")

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	c.Assert(lines, checker.HasLen, 2)

	fields := strings.Fields(lines[0])
	c.Assert(fields, checker.HasLen, 2)

	annonymounsVolumeID := fields[1]

	fields = strings.Fields(lines[1])
	c.Assert(fields[1], checker.Equals, "ps-volume-test")

	// filter by volume name
	out, _ = dockerCmd(c, "ps", "--format", "{{.Names}} {{.Mounts}}", "--filter", "volume=ps-volume-test")

	lines = strings.Split(strings.TrimSpace(string(out)), "\n")
	c.Assert(lines, checker.HasLen, 1)

	fields = strings.Fields(lines[0])
	c.Assert(fields[1], checker.Equals, "ps-volume-test")

	// empty results filtering by unknown volume
	out, _ = dockerCmd(c, "ps", "--format", "{{.Names}} {{.Mounts}}", "--filter", "volume=this-volume-should-not-exist")
	c.Assert(strings.TrimSpace(string(out)), checker.HasLen, 0)

	// filter by mount destination
	out, _ = dockerCmd(c, "ps", "--format", "{{.Names}} {{.Mounts}}", "--filter", "volume="+mp)

	lines = strings.Split(strings.TrimSpace(string(out)), "\n")
	c.Assert(lines, checker.HasLen, 2)

	fields = strings.Fields(lines[0])
	c.Assert(fields[1], checker.Equals, annonymounsVolumeID)
	fields = strings.Fields(lines[1])
	c.Assert(fields[1], checker.Equals, "ps-volume-test")

	// empty results filtering by unknown mount point
	out, _ = dockerCmd(c, "ps", "--format", "{{.Names}} {{.Mounts}}", "--filter", "volume="+prefix+slash+"this-path-was-never-mounted")
	c.Assert(strings.TrimSpace(string(out)), checker.HasLen, 0)
}
