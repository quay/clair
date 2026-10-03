package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Notify sends information back to a supervisor process.
//
// # Linux
//
// The supervisor is assumed to be systemd, and this function implements the
// sd_notify(3) protocol. Some messages require an additional argument.
func notify(args ...any) error {
	const key = `NOTIFY_SOCKET`

	sockpath, ok := os.LookupEnv(key)
	if !ok {
		return nil
	}
	sock, err := net.ResolveUnixAddr("unix", sockpath)
	if err != nil {
		return err
	}
	conn, err := net.DialUnix("unix", nil, sock)
	if err != nil {
		return err
	}
	defer conn.Close()
	rc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var ctlErr error
	err = rc.Control(func(fd uintptr) {
		const szTgt = 8 * 1026 * 1026 // 8 MiB

		_, ctlErr = unix.FcntlInt(fd, unix.F_SETFD, unix.FD_CLOEXEC)
		if ctlErr != nil {
			return
		}

		var sz int
		sz, ctlErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
		if ctlErr != nil {
			return
		}
		if sz < szTgt {
			ctlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, szTgt)
			if ctlErr != nil {
				return
			}
		}
	})
	if err := errors.Join(err, ctlErr); err != nil {
		return err
	}

	// build message
	var buf bytes.Buffer
	var oob []byte
	for i := 0; i < len(args); i++ {
		var fdname string
		msg := args[i].(notifyMsg)
		switch msg {
		case msgReady:
			buf.WriteString("READY=1\n")
		case msgReloading:
			buf.WriteString("RELOADING=1\n")
		case msgStopping:
			buf.WriteString("STOPPING=1\n")
		case msgStatus:
			buf.WriteString("STATUS=")
			i++
			s := args[i].(string)
			buf.WriteString(strings.TrimSpace(s))
			buf.WriteByte('\n')
		case msgSocketAPI:
			fdname = "api"
		case msgSocketIntrospection:
			fdname = "introspection"
		default:
			panic(fmt.Sprintf("programmer error: unknown msg kind: %v", msg))
		}
		if fdname != "" {
			if oob != nil {
				panic("programmer error: sending multiple file descriptors")
			}
			buf.WriteString("FDSTORE=1\n")
			buf.WriteString("FDNAME=")
			buf.WriteString(fdname)
			buf.WriteByte('\n')
			i++
			oob = unix.UnixRights(args[i].(int))
		}
	}

	_, _, err = conn.WriteMsgUnix(buf.Bytes(), oob, sock)
	return err
}
