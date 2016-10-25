package daemon

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/mount"
)

// cleanupMounts umounts shm/mqueue mounts for old containers
func (daemon *Daemon) cleanupMounts() error {
	logrus.Debugf("Cleaning up old container shm/mqueue/rootfs mounts: start.")
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	defer f.Close()

	return daemon.cleanupMountsFromReader(f, mount.Unmount)
}

func (daemon *Daemon) cleanupMountsFromReader(reader io.Reader, unmount func(target string) error) error {
	if daemon.repository == "" {
		return nil
	}
	sc := bufio.NewScanner(reader)
	var errors []string
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if strings.HasPrefix(fields[4], daemon.root) {
			logrus.Debugf("Mount base: %v", fields[4])
			mnt := fields[4]
			mountBase := filepath.Base(mnt)
			if mountBase == "mqueue" || mountBase == "shm" || mountBase == "merged" {
				logrus.Debugf("Unmounting %v", mnt)
				if err := unmount(mnt); err != nil {
					logrus.Error(err)
					errors = append(errors, err.Error())
				}
			}
		}
	}

	if err := sc.Err(); err != nil {
		return err
	}

	if len(errors) > 0 {
		return fmt.Errorf("Error cleaningup mounts:\n%v", strings.Join(errors, "\n"))
	}

	logrus.Debugf("Cleaning up old container shm/mqueue/rootfs mounts: done.")
	return nil
}
