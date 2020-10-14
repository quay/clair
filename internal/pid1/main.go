// Package pid1 does magic when a binary is run as pid 1.
//
// Due to the multitude of ways to run a container, an in-container init process
// is not always needed. This package attempts to autodetect cases when it is,
// and provide bare-bones functionality. When imported, the package's init
// function may hijacks the process, re-exec the binary, and run a minimal
// process reaper. This means that any child processes will be cleaned up
// correctly.
//
// If the environment variable NO_INIT is set to a non-empty value, this package
// will not hijack the process even if it is pid 1.
//
// Using this package will break systemd's fd passing protocol.
package pid1

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

const (
	exitReadlink = 127 + iota

	// Cribbed from systemd.exec(5)
	exitExec = 203
)

// Init hijacks the current process if it's pid 1.
func init() {
	if os.Getpid() != 1 || os.Getenv(`NO_INIT`) != "" {
		return
	}
	fmt.Fprintln(os.Stderr, "pid1: becoming a dumb init")

	bin, err := os.Readlink(`/proc/self/exe`)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(exitReadlink)
	}

	cmd := exec.Command(bin, os.Args[1:]...)
	cmd.Args[0] = os.Args[0] // Copy over the name the binary was called with.
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// We spawn the process, and then let the general child reaper handle it
	// instead of calling cmd.Wait. Doing both may result in spurious errors
	// when the command exits immediately.
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(exitExec)
	}
	os.Exit(reap(cmd.Process.Pid))
}

// Reap spawns two goroutines, one to proxy signals to the child and one to
// handle wait4(2) calls.
//
// The returnedt in is the exit code of the specified pid.
func reap(pid int) int {
	// AFAICT, there's no way to get the current signal mask, so create one
	// channel for all signals that ignores SIGCHLD after receive and one that
	// only receives SIGCHLD.
	//
	// The "4" below is just a guess at a good value for the channels. Signal
	// handlers can't block, so the go stdlib will do non-blocking sends
	// regardless.
	//
	// In the case of the "all" channel, signals may get dropped but Clair isn't
	// a signal-heavy program. In the worst case, it may miss an actionable
	// signal like TERM and the orchestration layer will be forced to wait and
	// then send KILL. Using two separate goroutines should mean that non-CHLD
	// signals get forwarded promptly.
	// In the case of the "chld" channel, the processing loop calls wait4(2) in
	// a loop on every signal received, meaning a dropped signal means tying up
	// resources until another child gets re-parented.
	all := make(chan os.Signal, 4)
	chld := make(chan os.Signal, 4)
	done := make(chan int)
	signal.Notify(all)
	signal.Notify(chld, syscall.SIGCHLD)

	go func() {
		for sig := range all {
			if sig == syscall.SIGCHLD {
				continue
			}
			syscall.Kill(pid, sig.(syscall.Signal))
		}
	}()

	go func() {
		for range chld {
			// Always call in a loop, in case a signal got dropped in either the
			// channel or the delivery to our process.
			for {
				var status syscall.WaitStatus
				id, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
				switch {
				case err != nil: // If id < 0, err will be populated.
					panic(fmt.Sprintf("pid1: failed to wait4(): %v", err))
				case id == pid: // If the golden child exited, send the status back.
					done <- status.ExitStatus()
					close(done)
				case id == 0: // No state change.
					break
				default:
				}
			}
		}
	}()

	return <-done
}
