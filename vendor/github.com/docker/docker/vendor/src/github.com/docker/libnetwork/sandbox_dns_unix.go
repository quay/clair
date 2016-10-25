// +build !windows

package libnetwork

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/etchosts"
	"github.com/docker/libnetwork/netutils"
	"github.com/docker/libnetwork/resolvconf"
	"github.com/docker/libnetwork/types"
)

const (
	defaultPrefix = "/var/lib/docker/network/files"
	dirPerm       = 0755
	filePerm      = 0644
)

func (sb *sandbox) startResolver() {
	sb.resolverOnce.Do(func() {
		var err error
		sb.resolver = NewResolver(sb)
		defer func() {
			if err != nil {
				sb.resolver = nil
			}
		}()

		err = sb.rebuildDNS()
		if err != nil {
			log.Errorf("Updating resolv.conf failed for container %s, %q", sb.ContainerID(), err)
			return
		}
		sb.resolver.SetExtServers(sb.extDNS)

		sb.osSbox.InvokeFunc(sb.resolver.SetupFunc())
		if err = sb.resolver.Start(); err != nil {
			log.Errorf("Resolver Setup/Start failed for container %s, %q", sb.ContainerID(), err)
		}
	})
}

func (sb *sandbox) setupResolutionFiles() error {
	if err := sb.buildHostsFile(); err != nil {
		return err
	}

	if err := sb.updateParentHosts(); err != nil {
		return err
	}

	if err := sb.setupDNS(); err != nil {
		return err
	}

	return nil
}

func (sb *sandbox) buildHostsFile() error {
	if sb.config.hostsPath == "" {
		sb.config.hostsPath = defaultPrefix + "/" + sb.id + "/hosts"
	}

	dir, _ := filepath.Split(sb.config.hostsPath)
	if err := createBasePath(dir); err != nil {
		return err
	}

	// This is for the host mode networking
	if sb.config.originHostsPath != "" {
		if err := copyFile(sb.config.originHostsPath, sb.config.hostsPath); err != nil && !os.IsNotExist(err) {
			return types.InternalErrorf("could not copy source hosts file %s to %s: %v", sb.config.originHostsPath, sb.config.hostsPath, err)
		}
		return nil
	}

	extraContent := make([]etchosts.Record, 0, len(sb.config.extraHosts))
	for _, extraHost := range sb.config.extraHosts {
		extraContent = append(extraContent, etchosts.Record{Hosts: extraHost.name, IP: extraHost.IP})
	}

	return etchosts.Build(sb.config.hostsPath, "", sb.config.hostName, sb.config.domainName, extraContent)
}

func (sb *sandbox) updateHostsFile(ifaceIP string) error {
	var mhost string

	if sb.config.originHostsPath != "" {
		return nil
	}

	if sb.config.domainName != "" {
		mhost = fmt.Sprintf("%s.%s %s", sb.config.hostName, sb.config.domainName,
			sb.config.hostName)
	} else {
		mhost = sb.config.hostName
	}

	extraContent := []etchosts.Record{{Hosts: mhost, IP: ifaceIP}}

	sb.addHostsEntries(extraContent)
	return nil
}

func (sb *sandbox) addHostsEntries(recs []etchosts.Record) {
	if err := etchosts.Add(sb.config.hostsPath, recs); err != nil {
		log.Warnf("Failed adding service host entries to the running container: %v", err)
	}
}

func (sb *sandbox) deleteHostsEntries(recs []etchosts.Record) {
	if err := etchosts.Delete(sb.config.hostsPath, recs); err != nil {
		log.Warnf("Failed deleting service host entries to the running container: %v", err)
	}
}

func (sb *sandbox) updateParentHosts() error {
	var pSb Sandbox

	for _, update := range sb.config.parentUpdates {
		sb.controller.WalkSandboxes(SandboxContainerWalker(&pSb, update.cid))
		if pSb == nil {
			continue
		}
		if err := etchosts.Update(pSb.(*sandbox).config.hostsPath, update.ip, update.name); err != nil {
			return err
		}
	}

	return nil
}

func (sb *sandbox) setupDNS() error {
	var newRC *resolvconf.File

	if sb.config.resolvConfPath == "" {
		sb.config.resolvConfPath = defaultPrefix + "/" + sb.id + "/resolv.conf"
	}

	sb.config.resolvConfHashFile = sb.config.resolvConfPath + ".hash"

	dir, _ := filepath.Split(sb.config.resolvConfPath)
	if err := createBasePath(dir); err != nil {
		return err
	}

	// This is for the host mode networking
	if sb.config.originResolvConfPath != "" {
		if err := copyFile(sb.config.originResolvConfPath, sb.config.resolvConfPath); err != nil {
			return fmt.Errorf("could not copy source resolv.conf file %s to %s: %v", sb.config.originResolvConfPath, sb.config.resolvConfPath, err)
		}
		return nil
	}

	currRC, err := resolvconf.Get()
	if err != nil {
		return err
	}

	if len(sb.config.dnsList) > 0 || len(sb.config.dnsSearchList) > 0 || len(sb.config.dnsOptionsList) > 0 {
		var (
			err            error
			dnsList        = resolvconf.GetNameservers(currRC.Content, netutils.IP)
			dnsSearchList  = resolvconf.GetSearchDomains(currRC.Content)
			dnsOptionsList = resolvconf.GetOptions(currRC.Content)
		)
		if len(sb.config.dnsList) > 0 {
			dnsList = sb.config.dnsList
		}
		if len(sb.config.dnsSearchList) > 0 {
			dnsSearchList = sb.config.dnsSearchList
		}
		if len(sb.config.dnsOptionsList) > 0 {
			dnsOptionsList = sb.config.dnsOptionsList
		}
		newRC, err = resolvconf.Build(sb.config.resolvConfPath, dnsList, dnsSearchList, dnsOptionsList)
		if err != nil {
			return err
		}
	} else {
		// Replace any localhost/127.* (at this point we have no info about ipv6, pass it as true)
		if newRC, err = resolvconf.FilterResolvDNS(currRC.Content, true); err != nil {
			return err
		}
		// No contention on container resolv.conf file at sandbox creation
		if err := ioutil.WriteFile(sb.config.resolvConfPath, newRC.Content, filePerm); err != nil {
			return types.InternalErrorf("failed to write unhaltered resolv.conf file content when setting up dns for sandbox %s: %v", sb.ID(), err)
		}
	}

	// Write hash
	if err := ioutil.WriteFile(sb.config.resolvConfHashFile, []byte(newRC.Hash), filePerm); err != nil {
		return types.InternalErrorf("failed to write resolv.conf hash file when setting up dns for sandbox %s: %v", sb.ID(), err)
	}

	return nil
}

func (sb *sandbox) updateDNS(ipv6Enabled bool) error {
	var (
		currHash string
		hashFile = sb.config.resolvConfHashFile
	)

	// This is for the host mode networking
	if sb.config.originResolvConfPath != "" {
		return nil
	}

	if len(sb.config.dnsList) > 0 || len(sb.config.dnsSearchList) > 0 || len(sb.config.dnsOptionsList) > 0 {
		return nil
	}

	currRC, err := resolvconf.GetSpecific(sb.config.resolvConfPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else {
		h, err := ioutil.ReadFile(hashFile)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
		} else {
			currHash = string(h)
		}
	}

	if currHash != "" && currHash != currRC.Hash {
		// Seems the user has changed the container resolv.conf since the last time
		// we checked so return without doing anything.
		log.Infof("Skipping update of resolv.conf file with ipv6Enabled: %t because file was touched by user", ipv6Enabled)
		return nil
	}

	// replace any localhost/127.* and remove IPv6 nameservers if IPv6 disabled.
	newRC, err := resolvconf.FilterResolvDNS(currRC.Content, ipv6Enabled)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(sb.config.resolvConfPath, newRC.Content, 0644)
	if err != nil {
		return err
	}

	// write the new hash in a temp file and rename it to make the update atomic
	dir := path.Dir(sb.config.resolvConfPath)
	tmpHashFile, err := ioutil.TempFile(dir, "hash")
	if err != nil {
		return err
	}
	if err = ioutil.WriteFile(tmpHashFile.Name(), []byte(newRC.Hash), filePerm); err != nil {
		return err
	}
	return os.Rename(tmpHashFile.Name(), hashFile)
}

// Embedded DNS server has to be enabled for this sandbox. Rebuild the container's
// resolv.conf by doing the follwing
// - Save the external name servers in resolv.conf in the sandbox
// - Add only the embedded server's IP to container's resolv.conf
// - If the embedded server needs any resolv.conf options add it to the current list
func (sb *sandbox) rebuildDNS() error {
	currRC, err := resolvconf.GetSpecific(sb.config.resolvConfPath)
	if err != nil {
		return err
	}

	// localhost entries have already been filtered out from the list
	// retain only the v4 servers in sb for forwarding the DNS queries
	sb.extDNS = resolvconf.GetNameservers(currRC.Content, netutils.IPv4)

	var (
		dnsList        = []string{sb.resolver.NameServer()}
		dnsOptionsList = resolvconf.GetOptions(currRC.Content)
		dnsSearchList  = resolvconf.GetSearchDomains(currRC.Content)
	)

	// external v6 DNS servers has to be listed in resolv.conf
	dnsList = append(dnsList, resolvconf.GetNameservers(currRC.Content, netutils.IPv6)...)

	// Resolver returns the options in the format resolv.conf expects
	dnsOptionsList = append(dnsOptionsList, sb.resolver.ResolverOptions()...)

	_, err = resolvconf.Build(sb.config.resolvConfPath, dnsList, dnsSearchList, dnsOptionsList)
	return err
}

func createBasePath(dir string) error {
	return os.MkdirAll(dir, dirPerm)
}

func createFile(path string) error {
	var f *os.File

	dir, _ := filepath.Split(path)
	err := createBasePath(dir)
	if err != nil {
		return err
	}

	f, err = os.Create(path)
	if err == nil {
		f.Close()
	}

	return err
}

func copyFile(src, dst string) error {
	sBytes, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(dst, sBytes, filePerm)
}
