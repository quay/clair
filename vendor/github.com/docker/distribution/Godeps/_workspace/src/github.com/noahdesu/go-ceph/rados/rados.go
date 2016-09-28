package rados

// #cgo LDFLAGS: -lrados
// #include <stdlib.h>
// #include <rados/librados.h>
import "C"

import (
	"fmt"
	"unsafe"
)

type RadosError int

func (e RadosError) Error() string {
	return fmt.Sprintf("rados: ret=%d", e)
}

// Version returns the major, minor, and patch components of the version of
// the RADOS library linked against.
func Version() (int, int, int) {
	var c_major, c_minor, c_patch C.int
	C.rados_version(&c_major, &c_minor, &c_patch)
	return int(c_major), int(c_minor), int(c_patch)
}

// NewConn creates a new connection object. It returns the connection and an
// error, if any.
func NewConn() (*Conn, error) {
	conn := &Conn{}
	ret := C.rados_create(&conn.cluster, nil)

	if ret == 0 {
		return conn, nil
	} else {
		return nil, RadosError(int(ret))
	}
}

// NewConnWithUser creates a new connection object with a custom username.
// It returns the connection and an error, if any.
func NewConnWithUser(user string) (*Conn, error) {
	c_user := C.CString(user)
	defer C.free(unsafe.Pointer(c_user))

	conn := &Conn{}
	ret := C.rados_create(&conn.cluster, c_user)

	if ret == 0 {
		return conn, nil
	} else {
		return nil, RadosError(int(ret))
	}
}
