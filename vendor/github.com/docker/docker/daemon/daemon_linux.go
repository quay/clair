package daemon

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/mount"
)

func (daemon *Daemon) cleanupMountsByID(id string) error {
	logrus.Debugf("Cleaning up old mountid %s: start.", id)
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	defer f.Close()

	return daemon.cleanupMountsFromReaderByID(f, id, mount.Unmount)
}

func (daemon *Daemon) cleanupMountsFromReaderByID(reader io.Reader, id string, unmount func(target string) error) error {
	if daemon.root == "" {
		return nil
	}
	var errors []string

	regexps := getCleanPatterns(id)
	sc := bufio.NewScanner(reader)
	for sc.Scan() {
		if fields := strings.Fields(sc.Text()); len(fields) >= 4 {
			if mnt := fields[4]; strings.HasPrefix(mnt, daemon.root) {
				for _, p := range regexps {
					if p.MatchString(mnt) {
						if err := unmount(mnt); err != nil {
							logrus.Error(err)
							errors = append(errors, err.Error())
						}
					}
				}
			}
		}
	}

	if err := sc.Err(); err != nil {
		return err
	}

	if len(errors) > 0 {
		return fmt.Errorf("Error cleaning up mounts:\n%v", strings.Join(errors, "\n"))
	}

	logrus.Debugf("Cleaning up old mountid %v: done.", id)
	return nil
}

// cleanupMounts umounts shm/mqueue mounts for old containers
func (daemon *Daemon) cleanupMounts() error {
	return daemon.cleanupMountsByID("")
}

func getCleanPatterns(id string) (regexps []*regexp.Regexp) {
	var patterns []string
	if id == "" {
		id = "[0-9a-f]{64}"
		patterns = append(patterns, "containers/"+id+"/shm")
	}
	patterns = append(patterns, "aufs/mnt/"+id+"$", "overlay/"+id+"/merged$", "zfs/graph/"+id+"$")
	for _, p := range patterns {
		r, err := regexp.Compile(p)
		if err == nil {
			regexps = append(regexps, r)
		}
	}
	return
}
