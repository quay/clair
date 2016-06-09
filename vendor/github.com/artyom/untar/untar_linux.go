// +build linux

package untar

func devNo(major, minor int64) int { return int((major << 8) + minor) }
