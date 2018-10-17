// Copyright 2018 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gitutil

import (
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func createTemporaryGitRepo(t *testing.T) string {
	// create temporary folder
	path, err := ioutil.TempDir(os.TempDir(), "1b750a87bbfc")
	require.Nil(t, err)

	// initialize git
	cmd := exec.Command("git", "init", path)
	out, err := cmd.CombinedOutput()
	require.Nil(t, err, "Failed to initialize temporary git repo, output=%s", string(out))
	return path
}

func createEmptyCommit(t *testing.T, repoPath string) {
	cmd := exec.Command("git", "commit", "-m", "\"init\"", "--allow-empty")
	cmd.Dir = repoPath
	out, err := cmd.CombinedOutput()
	require.Nil(t, err, "Failed to submit first empty git commit, output=%s", string(out))
}

func getHeadCommitRev(t *testing.T, repoPath string) string {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = repoPath
	out, err := cmd.CombinedOutput()
	require.Nil(t, err, "Failed to get head revision, output=%s", string(out))
	return strings.TrimSuffix(string(out), "\n")
}

func TestCloneOrPull(t *testing.T) {
	remote := createTemporaryGitRepo(t)
	createEmptyCommit(t, remote)
	expectedHead := getHeadCommitRev(t, remote)
	t.Log(expectedHead)
	repoPath := ""
	tempDirPrefix := "9c2d4181"
	path, head, err := CloneOrPull(remote, repoPath, tempDirPrefix)
	require.Nil(t, err)
	_, err = os.Stat(path)
	require.Nil(t, err, "Expect generated repo to exist")
	require.Equal(t, expectedHead, head)

	// create second empty commit to try pull
	createEmptyCommit(t, remote)
	expectedHead = getHeadCommitRev(t, remote)
	t.Log(expectedHead)
	newPath, newHead, err := CloneOrPull(remote, path, tempDirPrefix)
	require.Nil(t, err)
	_, err = os.Stat(path)
	require.Nil(t, err, "Expect generated repo to exist")
	require.Equal(t, path, newPath, "No new path should be created when pulling")
	require.Equal(t, expectedHead, newHead)
}
