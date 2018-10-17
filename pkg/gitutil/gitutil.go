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

// Package gitutil implements an easy way to update a git repository to a local
// temporary directory.
package gitutil

import (
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
)

// ErrFailedClone is returned when a git clone is unsuccessful.
var ErrFailedClone = errors.New("failed to clone git repository")

// ErrFailedRevParse is returned when a git rev-parse is unsuccessful.
var ErrFailedRevParse = errors.New("failed to rev-parse git repository")

// ErrFailedPull is returned when a git pull is unsuccessful.
var ErrFailedPull = errors.New("failed to pull git repository")

// pull performs a git pull on the provided path and returns the commit SHA
// for the HEAD reference.
func pull(path string) (head string, err error) {
	// Prepare a command to pull the repository.
	cmd := exec.Command("git", "pull")
	cmd.Dir = path

	// Execute the command.
	var commandOutput []byte
	commandOutput, err = cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"path":   path,
			"output": string(commandOutput),
		}).Error("failed to git rev-parse repository")
		err = ErrFailedPull
		return
	}

	return revParseHead(path)
}

// CloneOrPull performs a git pull if there is a git repository located at
// repoPath. Otherwise, it performs a git clone to that path.
//
// If repoPath is left empty, a temporary directory is generated with the
// provided prefix and returned.
func CloneOrPull(remote, repoPath, tempDirPrefix string) (path, head string, err error) {
	// Create a temporary directory if the path is unspecified.
	if repoPath == "" {
		path, err = ioutil.TempDir(os.TempDir(), tempDirPrefix)
		if err != nil {
			return
		}
	} else {
		path = repoPath
	}

	if _, pathExists := os.Stat(path); repoPath == "" || os.IsNotExist(pathExists) {
		head, err = clone(remote, path)
		return
	}

	head, err = pull(path)
	return
}

// clone performs a git clone to the provided path and returns the commit SHA
// for the HEAD reference.
func clone(remote, path string) (head string, err error) {
	// Handle an invalid path.
	if path == "" {
		log.WithField("remote", remote).Error("attempted to git clone repository to empty path")
		err = ErrFailedClone
		return
	}

	// Prepare a command to clone the repository.
	cmd := exec.Command("git", "clone", remote, ".")
	cmd.Dir = path

	// Execute the command.
	var commandOutput []byte
	commandOutput, err = cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"remote": remote,
			"path":   path,
			"output": string(commandOutput),
		}).Error("failed to git clone repository")

		err = os.RemoveAll(path)
		if err != nil {
			log.WithError(err).WithField("path", path).Warn("failed to remove directory of failed clone")
		}
		err = ErrFailedClone
		return
	}

	return revParseHead(path)
}

// revParseHead performs a git rev-parse HEAD on the provided path and returns
// the commit SHA for the HEAD reference.
func revParseHead(path string) (head string, err error) {
	// Handle an invalid path.
	if path == "" {
		log.Error("attempted to rev-parse repository with empty path")
		err = ErrFailedRevParse
		return
	}

	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = path

	var commandOutput []byte
	commandOutput, err = cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"path":   path,
			"output": string(commandOutput),
		}).Error("failed to git rev-parse repository")
		err = ErrFailedRevParse
		return
	}

	head = strings.TrimSpace(string(commandOutput))
	return
}
