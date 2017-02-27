// Package untar provides helper function to easily extract contents of a tar
// stream to a file system directory.
//
// Useful for cases where you'd want a replacement for external call to `tar x`.
// It differs from `tar x` call by not setting proper times on symlinks itself.
// Extended attributes are not supported.
//
// It's tested on OS X and Linux amd64 and is enough to unpack linux root
// filesystem to a useable state.
package untar

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Untar extracts each item from a tar stream and saves it into file system
// directory. It stops on first error it encounters; if extracted over existing
// file system tree, matching files would be overwritten. If destination
// directory does not exist, it will be created.
//
// Note that permissions on unpacked data would be set with current umask taken
// into account; if you expect to get exact permissions, call syscall.Umask(0)
// beforehand. This function does not call it itself as this changes umask
// process-wide, so it's safer to do this explicitly.
//
// Owner/group of extracted files are set only if run as root (os.Getuid() == 0)
// and are only set as numeric values, user/group names are not taken into
// account.
func Untar(f io.Reader, dst string) error {
	isRoot := os.Getuid() == 0
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		switch err {
		case nil:
		case io.EOF:
			return nil
		default:
			return err
		}
		name := filepath.Join(dst, filepath.Clean(hdr.Name))
		mode := hdr.FileInfo().Mode()
	ProcessHeader:
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			err = writeFile(name, mode, tr)
		case tar.TypeDir:
			err = os.MkdirAll(name, mode)
		case tar.TypeLink:
			err = os.Link(filepath.Join(dst, filepath.Clean(hdr.Linkname)), name)
		case tar.TypeSymlink:
			err = os.Symlink(filepath.Clean(hdr.Linkname), name)
		case tar.TypeFifo:
			err = unix.Mkfifo(name, syscallMode(mode))
		case tar.TypeChar, tar.TypeBlock:
			err = unix.Mknod(name, syscallMode(mode), devNo(hdr.Devmajor, hdr.Devminor))
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			continue
		default:
			return fmt.Errorf("unsupported header type flag for %[2]q: %#[1]x (%[1]q)", hdr.Typeflag, hdr.Name)
		}
		if err != nil {
			if os.IsExist(err) {
				// if file already exists, try to remove it and
				// re-process — this is for everything except
				// directories and regular files
				if os.Remove(name) == nil {
					goto ProcessHeader
				}
			}
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeRegA, tar.TypeDir, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			if !hdr.AccessTime.IsZero() || !hdr.ModTime.IsZero() {
				now := time.Now()
				atime, mtime := hdr.AccessTime, hdr.ModTime
				// fix times that don't fit unix epoch
				if atime.UnixNano() < 0 {
					atime = now
				}
				if mtime.UnixNano() < 0 {
					mtime = now
				}
				if err := os.Chtimes(name, atime, mtime); err != nil {
					return err
				}
			}
			if isRoot {
				if err := os.Chown(name, hdr.Uid, hdr.Gid); err != nil {
					return err
				}
				// group change resets special attributes like
				// setgid, restore them
				if mode&os.ModeSetgid != 0 || mode&os.ModeSetuid != 0 {
					if err := os.Chmod(name, mode); err != nil {
						return err
					}
				}
			}
		}
	}
}

func writeFile(name string, fm os.FileMode, rd io.Reader) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fm)
	if err != nil {
		return err
	}
	defer f.Close()
	bufp := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufp)
	if _, err := io.CopyBuffer(f, rd, *bufp); err != nil {
		return err
	}
	return f.Close()
}

// syscallMode returns the syscall-specific mode bits from Go's portable mode bits.
func syscallMode(i os.FileMode) (o uint32) {
	o |= uint32(i.Perm())
	if i&os.ModeSetuid != 0 {
		o |= unix.S_ISUID
	}
	if i&os.ModeSetgid != 0 {
		o |= unix.S_ISGID
	}
	if i&os.ModeSticky != 0 {
		o |= unix.S_ISVTX
	}
	if i&os.ModeNamedPipe != 0 {
		o |= unix.S_IFIFO
	}
	if i&os.ModeDevice != 0 {
		switch i & os.ModeCharDevice {
		case 0:
			o |= unix.S_IFBLK
		default:
			o |= unix.S_IFCHR
		}
	}
	return
}

var copyBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 512*1024)
		return &b
	},
}
