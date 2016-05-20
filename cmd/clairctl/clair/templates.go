// Code generated by go-bindata.
// sources:
// templates/analysis-template.html
// DO NOT EDIT!

package clair

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _templatesAnalysisTemplateHtml = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xdc\x5c\x7d\x6f\xdb\xb8\x19\xff\x3f\x9f\x82\xe7\xf4\xe0\xb4\x8b\xe4\xd8\x49\xd3\xd4\xb5\x3d\x74\x69\x83\x1b\x90\xf5\x86\xb5\x2b\x30\x14\xc5\x81\xb6\x68\x99\x88\x2c\x6a\x12\x9d\x97\x05\xfe\xee\x7b\x48\xbd\x58\x22\x29\x89\x72\x12\x0c\x98\x7a\xa9\x1d\x89\xfc\x3d\x6f\x7c\xde\x28\xf6\x26\xbf\x7c\xfa\xfd\xf2\xdb\xbf\xfe\xfe\x19\xad\xf8\x3a\x98\x1d\x4c\xc4\x07\x0a\x70\xe8\x4f\x7b\x24\xec\xcd\x0e\xe0\x0e\xc1\xde\xec\x00\xc1\x35\xe1\x94\x07\x64\x76\x19\x60\x1a\xa3\x4b\x16\xf2\x98\x05\x28\x26\x11\x8b\x39\x1a\xa3\xc7\x47\xf7\xaf\x6b\xec\x93\x2f\x78\x4d\xb6\xdb\xc9\x20\x1d\x7c\x90\xce\x0c\x68\x78\x83\x56\x31\x59\x4e\xfb\x2b\xce\xa3\x64\x3c\x18\x2c\x01\x20\x71\x7d\xc6\xfc\x80\xe0\x88\x26\xee\x82\xad\x07\x8b\x24\xf9\xf3\x12\xaf\x69\xf0\x30\xfd\x3d\x22\xe1\x9f\xbe\xe2\x30\x19\x9f\x9d\x9c\x1c\x9f\xa7\x3f\x94\xe3\x80\x2e\x8e\xcf\x8a\x6f\xa7\xe5\x6f\x7d\xe0\x26\x98\xf6\x13\xfe\x10\x90\x64\x45\x08\xef\x23\xfe\x10\x91\x69\x9f\x93\x7b\x2e\xb0\xfb\xb3\x12\x3b\x62\x6c\x6f\x37\xb6\x97\xf2\xd7\xcb\xf9\x5b\xe3\xfb\x85\x17\xba\x73\xc6\x78\xc2\x63\x1c\x89\x5f\x04\x8b\x82\x6f\x07\xdf\x91\x84\xad\xc9\xe0\xcc\x3d\x77\x87\x02\xb9\x72\xdb\x5d\x53\x18\x9b\x24\xbd\x5c\x7c\x49\x25\xa5\x2d\xae\x39\xf3\x1e\xd0\x63\xf1\xab\xb8\xe4\xf4\x54\xf2\x31\xea\x0b\xd9\x91\x90\xbd\x7f\x8c\x12\xf8\x70\x12\x12\xd3\xe5\x87\xca\x8c\x35\x8e\x7d\x1a\x8e\xd1\x49\xf5\x76\x84\x3d\x8f\x86\xbe\x76\x7f\x8e\x17\x37\x7e\xcc\x36\xa1\x37\x46\xfe\x8a\x25\xfc\x6e\x45\x39\x31\xce\x75\xe6\x8c\x73\xb6\x1e\xa3\x11\x59\xef\x06\x6c\x8b\x6f\x83\x37\xe8\xdb\x43\xc4\x7c\x50\xca\xea\x01\xbd\x19\x14\x0f\x8a\x2f\x2e\x98\xd4\x33\x49\x98\xd0\xff\x90\x31\x1a\xba\x67\xb5\xc8\x7e\xc0\xe6\x58\x2c\xc1\x07\xb6\xe1\x66\xf0\x05\x20\x61\x1a\x92\x58\xa1\xb0\x13\xbd\x2c\xfc\xd6\x84\x00\xfc\xc5\x4b\x7a\x3f\xc6\x4b\xae\xc1\x08\x78\x12\xf2\x31\xea\xf5\xaa\xea\xf1\x68\x12\x01\x5f\x63\x34\x0f\xd8\xe2\xa6\xfa\x4c\x22\xc2\x13\xc6\x57\xcd\xa4\x63\x76\xa7\xd0\x2b\x0c\x89\x9c\xd1\x49\x74\xdf\x3a\xdd\xc8\xf4\x73\xf0\xf6\x63\x11\xe0\x24\x79\x33\xed\x2d\x58\xe0\xf4\x7e\xd6\x6b\xb7\xca\xa6\xb8\x96\x01\xc3\xa0\xb1\x80\x2c\xb9\xb2\xec\xd8\xbd\x30\xba\x9c\x38\x67\xb1\x47\x62\x58\x5d\x2d\x32\x0a\xf2\xe7\x0a\xf5\x3b\xea\xf1\xd5\x18\xbd\x3d\xf9\xb5\x79\x6e\x84\x43\x12\x28\x73\x61\x55\x15\xcc\x0f\x61\xe1\x95\x57\x55\xca\xa3\xe4\x2b\xc6\x1e\xdd\x24\x63\x74\xa6\x0a\x57\x76\x1d\x83\xd7\x48\x11\x57\xd8\x03\xcb\x20\x50\x0c\x1a\xc2\xcf\x08\x7e\x0e\xc9\x48\xfc\xb1\xe1\x77\x35\x32\xae\x09\x87\xb3\xa8\xce\xc1\x0b\x27\x75\x2b\x5e\x5a\x92\x27\x1f\x90\xb0\x80\x7a\x92\x2b\x1f\xbc\x26\x81\xa7\xcc\x82\xa7\x31\xac\x05\xee\x2c\x56\x34\x50\x1d\x39\xe3\x2d\x87\x37\xba\x1a\xa8\xfc\x37\x08\x01\xb0\x4c\x8d\x1e\x8c\xa3\xc8\x59\xa5\xcf\x1f\x6b\x55\x7d\x38\x1a\xbe\x3f\xbf\x3a\x55\xd6\x32\x0b\x58\x6c\x34\xc3\xce\x8d\x84\x11\xb2\x9f\x9a\xd8\x38\x3c\x17\x36\xd2\x9e\x57\x2c\x09\xde\x28\x8c\x29\x46\x1e\x8e\xce\x4f\x47\xa7\x17\x0a\x18\x4b\x28\xa7\x0c\x28\x42\x22\xc1\x9c\xde\x92\x66\xad\x96\x64\x5e\x0d\xeb\x42\xc0\x07\x3d\x64\xde\x11\xea\xaf\x84\x6f\x89\x0f\x12\x57\x47\x88\xc4\xe6\x40\x76\x0a\x93\x25\x8b\xc1\x18\x9b\x28\x22\xf1\x02\x27\x16\xbc\x50\x91\xbf\xeb\x7c\x5c\xd7\x8d\xa4\x04\x89\xd6\x07\x36\x17\x10\x1e\x55\x4e\x32\xc3\x18\x55\x55\xb6\x6a\xec\xcf\xf1\xd1\xe8\xed\xdb\x63\xb4\xfb\xcb\xbd\x78\x6d\xb9\x82\x0f\x3f\x5f\x7e\xbe\xba\x1a\xda\x4a\xa7\xf9\x55\x29\x09\x69\x6e\xd3\xac\x6d\x13\xa1\x64\xb3\x06\xcb\xa9\xa9\x1c\x8a\x0b\x02\x96\x4e\x71\xdc\xf3\xda\x4c\x97\x55\x4e\x46\x07\xc9\x9e\xd5\x07\x85\xf6\x4c\x21\xd3\x73\x6d\xaa\xc1\x1b\xce\x54\xff\xb9\x77\xb2\x28\xfb\xfe\x5c\x33\x7f\x99\xf6\x69\x0d\x6d\x90\xe9\xab\x28\x74\x10\x5b\x22\xbe\x22\x28\xe5\xc0\x28\x5f\xfa\xc8\x0d\x99\x47\xd4\x25\xd8\xe0\x56\xe2\x2a\x12\x1d\x0d\xa5\xa2\x0d\xf9\x2e\xd7\xfd\x48\x8b\xe4\x99\x7c\xfa\x83\x5c\x31\x23\x3b\xad\xa6\x8c\xbb\x1e\x53\x4d\xd4\xc6\xfd\x1e\xac\x29\xd9\x49\x1f\x50\x9f\x7b\xcb\x25\x5f\x8c\x1f\x3e\xa8\x59\xb1\x1a\xef\xf2\xbc\x25\x3d\xf4\xe4\x18\xa5\xff\xb9\xa3\x92\x6f\xa6\xbc\x94\x1d\xd2\xe8\xce\x30\xa5\x6c\xf6\x16\x3d\xba\x9f\xc8\x12\x6a\xae\xa1\x49\x9f\x65\x11\xe6\x01\x2e\x5b\xba\x0d\xf5\x32\x06\x4b\x2c\xa0\x94\x6c\x81\x3d\x24\x17\x43\x32\x6c\x09\x98\x65\xe0\xdf\xc0\x84\xad\xa0\x9f\xdf\x0f\x3f\x9f\x9f\xda\x83\xfe\x8d\x80\x79\xd7\xad\xb0\x57\x57\x1f\xdf\x8d\xce\xed\x61\xaf\xa1\xda\x6c\xc3\xbc\xf8\xcb\xe5\xe9\xd9\x47\x7b\xcc\x2f\xc4\x87\xe8\x48\xe7\x81\xd1\x03\x2a\xd0\xa7\xef\xce\xde\x9d\x5d\xd9\x43\xff\x33\xbc\x09\xd9\x5d\xf8\xdc\xb8\x50\xd2\xb0\x68\x13\xd5\x95\xcc\x21\x0b\x89\xd1\x19\xa1\xa5\xd4\x4a\x88\xc2\xc1\xf1\x1c\xbc\x60\xa3\x17\x83\x69\xca\x1a\x9e\x94\x2b\x55\x71\x29\x65\x93\x9e\x61\xb3\x01\xc2\x8f\xc7\xc8\x19\xbe\xd5\x06\xa4\x4f\x46\xcf\x54\x9e\x36\xb8\xb9\x14\xb4\xa8\x95\x0c\x65\x52\x73\xbd\x2c\x23\x8b\x1a\x28\xf2\x6a\x58\x2d\xbe\x65\x5d\xb1\x0b\x42\xe2\x8f\xac\x67\x22\x1c\x43\x95\xd1\xd5\xc4\xcd\x0d\x5d\xbf\xdf\xcd\x98\x32\xdb\xe9\x96\x4c\xed\xf0\xb6\xc6\xc0\xb9\xfd\x34\xb5\x35\xb5\x68\xd9\x82\x3b\x31\x67\x0b\xb5\x95\x4f\xf5\x9f\xcd\x19\x4a\xa3\xca\x7a\xb7\xde\x56\xe5\xb2\xb9\xac\xdf\xba\xef\x46\x10\xb9\x8b\x91\xd9\xb4\xb3\x61\xe6\x04\x2a\x54\x35\xd9\xff\x9f\x5b\x46\xac\x7b\xf9\x57\xbb\x65\x34\x6f\xfc\x9f\x58\x09\xcd\x40\x17\xb7\x8a\x91\xd8\x2d\x89\xa1\xc6\x00\xf7\x5c\x51\xcf\x23\xa1\xa1\x2f\xd8\x0d\x21\x41\x40\xa3\x84\x26\xd6\x94\xc7\x2b\x31\xd9\x14\xf1\x59\x84\x17\x94\x83\x55\xdc\x8b\xce\x68\x8d\xf1\xde\x60\x65\x51\xfc\xe6\x36\x1d\x5e\x68\xb6\xca\x8c\xe4\xd1\x75\xb5\x8e\xaa\xd4\xbe\x73\x1c\x27\xe6\x6a\x17\x9e\x38\x73\xbf\x8e\x9d\xfa\x42\xb6\xa8\x09\x35\x86\x72\x5e\xcf\xeb\xf3\x93\x5d\x57\x2a\x59\xc3\x5d\x76\x93\xac\x5c\x53\xf3\x0b\x6d\xaf\x40\x5c\xa9\x43\x36\x6c\x54\x6a\x65\x54\x0a\x56\x2d\x88\xdb\x4a\xf6\x4c\xc4\xa2\xcc\x7c\x52\x85\x99\x83\x15\xd5\xe5\x13\x0b\xcb\x1c\x4f\x16\x95\x4f\xac\x27\x73\xac\xac\x96\x7c\x62\x19\x99\xa3\x5d\x6b\x1b\x96\x9d\xab\xc7\x1c\xaa\x54\x39\x3e\xb1\xb8\xcb\x11\xf3\x82\x71\x2f\x38\xf0\xd9\xdb\x4d\x10\x92\x18\xcf\x69\x00\xe6\x24\x35\xee\xdb\xd0\x8c\x8b\x68\x01\xf1\xbd\x4b\x37\x6d\xdc\xd5\x4d\x29\xb8\x0a\x3b\xc7\xfa\x88\x25\xc1\x7c\x13\x03\xa7\x33\xb4\x51\x17\x5f\x87\x37\x02\x4d\x4c\x34\x91\x08\x68\xc2\xf3\x0c\x53\x2d\x9b\x4d\x88\x19\x92\x6a\x9d\x27\x6d\xee\x64\x98\xf5\xdb\x93\xd5\xbc\x7a\x78\x79\xf5\xe9\xe2\xd3\xa5\x15\xe6\x1f\x7f\xc8\x77\x56\x75\x7b\x62\x43\xf3\x4e\xce\x0e\x46\x5d\x4c\x46\x9c\xac\x0a\x19\x89\x8d\x21\xf4\x0b\x5d\x0b\x9d\xe3\xb6\x42\xb7\x8c\xac\x6e\x37\x69\xfb\xc1\x17\xea\xc6\x56\x3e\x22\xce\xf6\x1e\xdc\x9a\xf7\x3a\xf5\x92\xec\x5a\xf4\x10\xaf\xf5\x22\x4e\x6a\xda\x22\x78\x6a\xb0\xbb\x1e\xbd\x1e\xd7\x2a\x8c\x6a\xc8\x69\x93\xde\x80\x6a\x13\x50\x35\xd4\xbc\x4b\x6f\xc0\xb5\x09\xad\x1a\xae\x6c\xd3\x1b\x40\x6d\x82\xac\x06\x5a\xee\xd3\x1b\xb0\x6d\xc2\xad\x86\x5d\x34\xea\x7b\x01\x43\xe0\x85\xea\x82\xd4\x95\x4b\xf2\x59\xf6\x61\xf6\xc9\xc5\x26\x4e\x04\x8d\x88\x51\x7d\x27\xda\xec\xb0\xe2\xaa\x8f\x3c\x6a\x94\x68\x92\x43\x5c\x86\x50\x6b\xd2\x9b\x41\x92\xac\x42\x6d\x4a\xf5\x16\x51\x50\x22\xba\x8b\x80\x25\xc4\x2b\x45\x6c\xab\x0d\x8e\x86\x9d\x6c\x47\x54\xf3\x75\x28\xcb\x80\x68\x3b\x16\xbb\x24\xa7\xd7\xa8\xcd\x9b\xcd\x95\xcd\x10\xcd\x52\x95\xed\xe6\xb6\x68\x55\x61\xde\xb4\xa7\xdc\xf6\xee\x42\x48\x06\x4c\x74\xa5\xd2\xb1\xa7\xed\xb0\x73\xad\x77\x8b\xa5\x66\xbf\xb1\x1a\xd6\x7a\xdf\xd6\x37\x6a\x99\xaa\x63\x13\x65\x3b\x3d\xe4\xd9\xc1\xac\x8f\x8e\x05\xb6\x01\x3e\xcf\x12\xed\xf8\x56\xb9\xc2\x40\x41\x64\x0b\x0b\x74\x9b\x9c\x61\x40\x4f\xb3\x86\x05\xbe\x4d\xee\x30\xe0\x43\xf6\xb0\x00\xb7\xc9\x21\x06\xf0\x5d\x16\xb1\xa0\x61\x93\x4b\x0c\x34\xb2\x6c\xf2\x4c\x04\xf2\xc6\xd7\x31\xbd\x01\x7b\x91\x68\xd6\xea\x63\x82\x98\xe3\xd1\x98\x2c\xb2\xde\x9c\xdd\x39\x31\x81\x3c\x90\x68\x9b\xb5\x15\x6f\x3e\x55\xb9\xa8\xdf\x8b\xb1\xd0\xc4\x3e\xa1\x31\x8f\x48\x17\x4d\xbb\xce\x9a\xcc\xb6\xcc\x3c\x4f\x4f\x6e\x44\x7e\xae\x06\xdd\x08\xfe\x1c\xdd\xba\x11\xf8\x79\x5a\x77\x23\xf4\x33\xf4\xf1\x46\xdc\xe7\x6b\xea\x8d\xf0\x7b\x77\xf8\x93\x41\x76\xea\x6e\x32\x48\x8f\x30\x1e\x4c\xc4\xb9\xbb\xec\x04\xa0\xd8\xe6\x94\xc7\x9d\xc4\x69\xa7\xec\x38\x59\x6f\x77\x42\x6f\x92\x9d\xd4\xc8\x86\xec\xce\x6e\x94\xc6\xa4\xe3\x86\xc6\xf3\x90\x40\x73\x58\x42\x1b\xa4\x93\xb3\xe3\x80\x2a\x03\xbb\xf3\x0a\xf9\xb9\x34\x8d\xca\x68\x26\xcf\x56\xea\xa7\x2c\xe1\xc9\x41\x75\x6c\x92\x06\x99\x1c\x3c\x0b\xb7\x0a\x62\xce\x82\x7e\x57\x5c\x8f\x8f\x77\x94\xaf\xd0\x2b\xa5\xec\xbf\x04\x7d\x73\x34\x9e\x42\xdf\x26\xbe\x7d\x0c\x82\xef\xd5\x01\xdb\xad\x11\x6e\x12\xcd\x26\x49\x84\x0b\x96\xc4\xe1\xc0\x1e\xdc\x02\x89\x43\x7f\xf6\x8d\x71\xf0\x52\x21\x99\x91\x9e\x2b\x9f\x6f\xb7\xea\x56\x8d\x30\xaf\x9c\x0f\x5f\x00\x1b\x3e\x22\xb3\x30\xf5\x0f\x4a\x26\x28\x27\x25\x83\xaa\x76\x8a\xa1\x4b\xe4\x73\x74\x64\x66\x35\x55\x50\x2f\x5b\xb2\xbd\xd7\xe8\xa4\x46\x23\x2a\x79\x19\x98\xf3\x69\xb3\x7c\xc9\x8f\x51\xae\xa3\x3a\xdd\x28\x04\xc5\x82\x28\xb4\x52\x6b\xdd\x54\x10\x12\x7a\xa0\x54\x3b\x81\x76\x2e\xde\x55\xa6\xd2\xcc\x59\x29\x50\x58\x4b\x56\x9a\xff\x52\xc2\x41\x5c\xec\x2a\x95\x98\x32\x13\xf1\xd4\x5a\x0e\x31\xe3\xa5\x04\x48\x73\x46\x57\x19\xb2\x59\xb3\x2c\xe3\x58\x4b\x92\xcd\x7b\x29\x61\x44\x66\xed\x2a\x8a\x9c\x33\x93\x39\xd9\x5a\x0c\x39\xe7\xa5\x84\xc8\x6b\x8f\xae\x82\x14\xf3\x66\x45\xf5\x62\x2d\x50\x31\xf7\xa5\x84\xca\x4a\xb5\xae\x32\xe5\xd3\x66\x79\xa9\x67\x2d\x51\x3e\xb3\xb3\x40\x35\x69\xa0\x76\x6a\x99\xe7\x6a\x0d\xd2\x90\x0a\x6a\x05\x45\xb2\xec\x98\xf6\xb2\x56\xa2\x4e\xc8\x7f\x64\x84\x34\x61\x7f\xed\xb5\x89\x59\xbf\x6e\xf6\xa3\x5d\x5a\x3a\x7b\x10\x97\x9e\xb4\x1f\xe1\xcc\x09\xf7\x20\x9a\x45\xa1\xfd\xc8\x16\x21\x6c\x0f\xc2\x22\x90\xef\x47\x35\x4d\x01\x7b\x90\x2c\xe5\xc0\xfd\x28\x57\x92\xe8\x1e\x0c\xe4\xe5\xc5\x7e\xd4\x77\xc5\x49\x33\xe9\x86\x47\x75\x7e\x6d\x98\x02\xa1\x22\xad\x7f\xab\xb7\x0f\xea\x04\xac\x73\xf3\xc7\x47\xf4\x8a\x62\x59\xec\x1a\x08\x3f\x3e\xc6\x38\xf4\x09\x7a\x75\x73\xfc\xea\x56\x0c\x52\x37\xc8\x61\x6e\xd3\xb4\x5b\x93\x30\xb8\xa2\x74\x28\xf4\xbf\x8a\x1d\x02\xca\x1f\xb6\xdb\xfc\xdf\x26\x1d\x02\x5b\xae\x28\xfd\x11\xdc\x6b\x0f\x66\x1e\xe3\xcd\x2a\x2f\x8d\x95\x27\x26\x5a\xe2\xdd\x6c\x17\xb9\xdd\xbc\x01\xb1\x8b\xcc\x72\x76\x45\x24\xcb\x09\x57\xe9\xd6\x76\xe3\xf8\x9a\x47\x93\x01\x36\xd9\xd5\xbc\x94\x4c\xf7\x15\xdc\xec\xd7\xdd\xef\x4a\xa7\x95\x76\x7e\x6a\xeb\x66\x66\xad\xac\x78\xf1\xaf\x2d\x2c\x8c\x99\xbe\x31\x69\xcb\x48\xd4\x9b\xf6\x40\x6d\xd7\x38\xe1\xd7\xf2\x1d\x41\x6a\xa7\x5e\x05\xa5\x01\x44\x02\xad\x4e\x2b\xc3\xb3\x37\x17\x3d\xe4\x61\x8e\x1d\xce\x7c\x3f\x20\x8e\x7c\x62\xa6\x35\x33\xdc\x84\x4e\xf5\xb4\x85\x6a\x49\xd6\xfc\x85\x46\x0b\xa3\x72\xda\x26\x68\x1f\x24\x2e\x70\x9d\xd4\xfb\x12\xb0\x12\xf1\xbe\x5b\x79\xac\x91\x62\x40\x15\x3e\x2d\xd8\x2c\x26\xeb\x52\xe6\xea\xb5\x07\x41\xa8\x54\x43\x15\x01\xa1\xf0\x45\x24\xbb\x6d\xf9\xe8\x3b\x2c\x19\xb1\x44\xe5\x53\x71\x13\x39\xa8\xd2\x8b\x2f\x31\x5a\x62\x87\xdc\xc3\xaf\x6b\x2c\x56\xb3\xc3\x63\x0a\x6a\x12\xe6\xc6\xf0\xcd\x49\xf7\x19\xa7\x3d\x1e\x6f\x48\x2f\x6f\xb6\xed\xc5\x6d\xf6\x72\xf5\x2a\x6c\xe4\xda\xed\x2c\x18\x49\x6e\x82\x5c\x38\x25\x2a\x77\xd3\x70\xd9\xce\xca\xfb\x77\x50\x6c\x1e\xc8\xea\x03\x71\x23\x34\x36\x22\x17\x8e\x26\xde\xaa\x0a\xdf\x2a\x05\x7b\x63\x34\x6b\xa5\x93\xae\x88\x22\xb1\x00\x58\xcf\xb8\x64\xba\x23\xa7\xf1\x59\x9c\x0c\x48\x16\x31\x8d\x78\xbe\xca\x3a\xd9\xbb\x40\xc3\x59\x82\x13\x88\xd7\xe2\x1f\xe7\x8a\x90\xc5\x71\xec\x13\x3e\xed\xcd\x03\x1c\xde\x40\xc3\x0d\xf7\x3b\x6b\x61\x32\x08\x68\x97\xe5\x6a\x1b\x4d\xec\x71\x9b\x9a\x92\x7d\xc7\xb6\xf3\xd9\x96\x5e\xf7\xc8\xa6\xe6\xdb\xf3\x18\x0d\xd4\x12\xac\x18\x59\xf9\x5a\x29\xcc\xca\xc9\x74\x92\xae\xa0\x1d\xca\xd1\x72\x13\xca\xb1\x47\xaf\xf5\x97\xab\x09\x47\x69\x0a\x8a\x13\x34\x45\x1e\x5b\x6c\xd6\x04\xaa\xce\x7f\x6f\x48\xfc\xf0\x95\x04\x40\x84\xc5\x1f\x83\xe0\xa8\xff\x43\x4b\x57\x3f\xfb\xaf\xd5\x57\xfc\x61\xc2\x02\xe2\x06\xcc\x3f\xca\x41\x61\x48\x65\xcc\x92\xc5\xe8\xe8\x16\xc7\x88\x02\xb9\x7c\x90\x1b\x90\xd0\xe7\x2b\x88\xa6\xc3\x0f\xf0\x60\x36\x45\x27\xf0\xe9\x38\x2a\xbf\xe2\xca\xe7\xfc\xa0\x3f\x5d\x16\x2e\x02\xba\xb8\x01\xa4\x42\x44\x62\x9a\x23\x2e\xe2\xa6\x0e\xe0\xa6\x87\x7d\xbf\x88\xdd\x70\xe9\xc8\xd7\x34\xe1\x6e\x8a\x7a\xd4\x4f\xcf\x00\xa8\x82\x89\x6b\x5b\xbd\xb5\x5b\x55\xdb\xd7\x47\xd9\x70\x30\x4a\xa6\xfa\xc9\x20\xdd\x1c\x17\xbb\xe5\xe2\xff\x04\xf0\xdf\x00\x00\x00\xff\xff\x87\xab\x72\xed\x19\x40\x00\x00")

func templatesAnalysisTemplateHtmlBytes() ([]byte, error) {
	return bindataRead(
		_templatesAnalysisTemplateHtml,
		"templates/analysis-template.html",
	)
}

func templatesAnalysisTemplateHtml() (*asset, error) {
	bytes, err := templatesAnalysisTemplateHtmlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "templates/analysis-template.html", size: 16409, mode: os.FileMode(420), modTime: time.Unix(1463760760, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"templates/analysis-template.html": templatesAnalysisTemplateHtml,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}
var _bintree = &bintree{nil, map[string]*bintree{
	"templates": &bintree{nil, map[string]*bintree{
		"analysis-template.html": &bintree{templatesAnalysisTemplateHtml, map[string]*bintree{}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}

