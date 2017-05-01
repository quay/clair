// +build darwin

package untar

func devNo(major, minor int64) int { return int((major << 24) + minor) }
