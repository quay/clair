package xnet

import (
	"errors"
	"fmt"
	"net"
)

//IPv4 returns IPv4 of given interface
func IPv4(i net.Interface) (string, error) {
	addrs, err := i.Addrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		var ip net.IP
		ip, _, err = net.ParseCIDR(addr.String())
		if err != nil {
			continue
		}
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}
	return "", errors.New("Interface does not have an IPv4 address")
}

//InterfaceFilter func returns true if interface match
type InterfaceFilter func(net.Interface) bool

//IsBroadcast check if interface has flag net.FlagBroadcast
func IsBroadcast(i net.Interface) bool {
	return i.Flags&net.FlagBroadcast == net.FlagBroadcast
}

//HasAddr check if interface contains Addr
func HasAddr(i net.Interface) bool {
	addrs, err := i.Addrs()
	return err == nil && len(addrs) > 0
}

//Filter returns interfaces matching InterfaceFilter
func Filter(interfaces []net.Interface, f InterfaceFilter) []net.Interface {
	finterfaces := make([]net.Interface, 0)
	for _, in := range interfaces {
		if f(in) {
			finterfaces = append(finterfaces, in)
		}
	}
	return finterfaces
}

//First returns first interface matching InterfaceFilter
func First(interfaces []net.Interface, f InterfaceFilter) (net.Interface, error) {
	for _, in := range interfaces {
		if f(in) {
			return in, nil
		}
	}
	return net.Interface{}, fmt.Errorf("interface not found")
}
