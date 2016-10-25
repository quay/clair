package etchosts

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"sync"
)

// Record Structure for a single host record
type Record struct {
	Hosts string
	IP    string
}

// WriteTo writes record to file and returns bytes written or error
func (r Record) WriteTo(w io.Writer) (int64, error) {
	n, err := fmt.Fprintf(w, "%s\t%s\n", r.IP, r.Hosts)
	return int64(n), err
}

var (
	// Default hosts config records slice
	defaultContent = []Record{
		{Hosts: "localhost", IP: "127.0.0.1"},
		{Hosts: "localhost ip6-localhost ip6-loopback", IP: "::1"},
		{Hosts: "ip6-localnet", IP: "fe00::0"},
		{Hosts: "ip6-mcastprefix", IP: "ff00::0"},
		{Hosts: "ip6-allnodes", IP: "ff02::1"},
		{Hosts: "ip6-allrouters", IP: "ff02::2"},
	}

	// A cache of path level locks for synchronizing /etc/hosts
	// updates on a file level
	pathMap = make(map[string]*sync.Mutex)

	// A package level mutex to synchronize the cache itself
	pathMutex sync.Mutex
)

func pathLock(path string) func() {
	pathMutex.Lock()
	defer pathMutex.Unlock()

	pl, ok := pathMap[path]
	if !ok {
		pl = &sync.Mutex{}
		pathMap[path] = pl
	}

	pl.Lock()
	return func() {
		pl.Unlock()
	}
}

// Drop drops the path string from the path cache
func Drop(path string) {
	pathMutex.Lock()
	defer pathMutex.Unlock()

	delete(pathMap, path)
}

// Build function
// path is path to host file string required
// IP, hostname, and domainname set main record leave empty for no master record
// extraContent is an array of extra host records.
func Build(path, IP, hostname, domainname string, extraContent []Record) error {
	defer pathLock(path)()

	content := bytes.NewBuffer(nil)
	if IP != "" {
		//set main record
		var mainRec Record
		mainRec.IP = IP
		if domainname != "" {
			mainRec.Hosts = fmt.Sprintf("%s.%s %s", hostname, domainname, hostname)
		} else {
			mainRec.Hosts = hostname
		}
		if _, err := mainRec.WriteTo(content); err != nil {
			return err
		}
	}
	// Write defaultContent slice to buffer
	for _, r := range defaultContent {
		if _, err := r.WriteTo(content); err != nil {
			return err
		}
	}
	// Write extra content from function arguments
	for _, r := range extraContent {
		if _, err := r.WriteTo(content); err != nil {
			return err
		}
	}

	return ioutil.WriteFile(path, content.Bytes(), 0644)
}

// Add adds an arbitrary number of Records to an already existing /etc/hosts file
func Add(path string, recs []Record) error {
	defer pathLock(path)()

	if len(recs) == 0 {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}

	content := bytes.NewBuffer(nil)

	_, err = content.ReadFrom(f)
	if err != nil {
		return err
	}

	for _, r := range recs {
		if _, err := r.WriteTo(content); err != nil {
			return err
		}
	}

	return ioutil.WriteFile(path, content.Bytes(), 0644)
}

// Delete deletes an arbitrary number of Records already existing in /etc/hosts file
func Delete(path string, recs []Record) error {
	defer pathLock(path)()

	if len(recs) == 0 {
		return nil
	}
	old, err := os.Open(path)
	if err != nil {
		return err
	}

	var buf bytes.Buffer

	s := bufio.NewScanner(old)
	eol := []byte{'\n'}
loop:
	for s.Scan() {
		b := s.Bytes()
		if b[0] == '#' {
			buf.Write(b)
			buf.Write(eol)
			continue
		}
		for _, r := range recs {
			if bytes.HasSuffix(b, []byte("\t"+r.Hosts)) {
				continue loop
			}
		}
		buf.Write(b)
		buf.Write(eol)
	}
	old.Close()
	if err := s.Err(); err != nil {
		return err
	}
	return ioutil.WriteFile(path, buf.Bytes(), 0644)
}

// Update all IP addresses where hostname matches.
// path is path to host file
// IP is new IP address
// hostname is hostname to search for to replace IP
func Update(path, IP, hostname string) error {
	defer pathLock(path)()

	old, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	var re = regexp.MustCompile(fmt.Sprintf("(\\S*)(\\t%s)(\\s|\\.)", regexp.QuoteMeta(hostname)))
	return ioutil.WriteFile(path, re.ReplaceAll(old, []byte(IP+"$2"+"$3")), 0644)
}
