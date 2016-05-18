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

var _templatesAnalysisTemplateHtml = []byte("\x1f\x8b\x08\x00\x00\x09\x6e\x88\x00\xff\xdc\x5c\xfd\x6f\xdb\x36\xfa\xff\xbd\x7f\x05\xa7\x7c\x07\xa7\xfb\x56\x72\xec\xa4\x59\xe6\xda\x3e\x74\x69\x83\x0d\xe8\x6d\xc3\x75\x37\xe0\x30\x0c\x03\x2d\xd1\x12\x11\x59\xd4\x49\x74\x93\x5c\xe0\xff\xfd\x1e\x52\xa4\x2c\x89\xd4\x8b\x1d\x1f\x0e\x38\x75\xa9\x1d\x91\xcf\xe7\x79\xe3\xf3\x42\x4a\xdd\xfc\xab\x0f\x3f\xdf\xfe\xfa\x8f\x5f\x3e\xa2\x88\x6f\xe2\xe5\xab\xb9\xf8\x40\x31\x4e\xc2\x85\x43\x12\x67\xf9\x0a\xee\x10\x1c\x2c\x5f\x21\xb8\xe6\x9c\xf2\x98\x2c\x6f\x63\x4c\x33\x74\xcb\x12\x9e\xb1\x18\x65\x24\x65\x19\x47\x33\xf4\xfc\xec\xfd\xb8\xc1\x21\xf9\x09\x6f\xc8\x6e\x37\x1f\x17\x93\x5f\x15\x94\x31\x4d\xee\x51\x94\x91\xf5\x62\x14\x71\x9e\xe6\xb3\xf1\x78\x0d\x00\xb9\x17\x32\x16\xc6\x04\xa7\x34\xf7\x7c\xb6\x19\xfb\x79\xfe\x97\x35\xde\xd0\xf8\x69\xf1\x73\x4a\x92\xff\xff\x8c\x93\x7c\x76\x75\x71\xf1\xe6\xba\xf8\xa1\x1c\xc7\xd4\x7f\x73\x55\x7e\xbb\xac\x7e\x1b\x81\x34\xf1\x62\x94\xf3\xa7\x98\xe4\x11\x21\x7c\x84\xf8\x53\x4a\x16\x23\x4e\x1e\xb9\xc0\x1e\x2d\x2b\xe2\x88\xb9\xce\x7e\xae\x53\xc8\xe7\x68\xf9\x36\xf8\xd1\x0f\x12\x6f\xc5\x18\xcf\x79\x86\x53\xf1\x8b\x10\x51\xc8\xed\xe2\x07\x92\xb3\x0d\x19\x5f\x79\xd7\xde\x44\x20\xd7\x6e\x7b\x1b\x0a\x73\xf3\xdc\xd1\xea\x4b\x2e\x05\x6f\x71\xad\x58\xf0\x84\x9e\xcb\x5f\xc5\x25\xc9\x0b\xcd\x67\x68\x24\x74\x47\x42\xf7\xd1\x1b\x94\xc3\x87\x9b\x93\x8c\xae\xdf\xd5\x28\x36\x38\x0b\x69\x32\x43\x17\xf5\xdb\x29\x0e\x02\x9a\x84\xc6\xfd\x15\xf6\xef\xc3\x8c\x6d\x93\x60\x86\xc2\x88\xe5\xfc\x21\xa2\x9c\x58\x69\xdd\x15\xe3\x9c\x6d\x66\x68\x4a\x36\xfb\x09\xbb\xf2\xdb\xf8\x1b\xf4\xeb\x53\xca\x42\x30\x4a\xf4\x84\xbe\x19\x97\x03\xe5\x17\x0f\x5c\x1a\xd8\x34\xcc\xe9\xbf\xc8\x0c\x4d\xbc\xab\x56\xe4\x30\x66\x2b\x2c\x96\xe0\x13\xdb\x72\x3b\xb8\x0f\x48\x98\x26\x24\x6b\x70\xd8\xab\x5e\x55\x7e\x67\x43\x00\xf9\xb2\x35\x7d\x9c\xe1\x35\x37\x60\x04\x3c\x49\xf8\x0c\x39\x4e\xdd\x3c\x01\xcd\x53\x90\x6b\x86\x56\x31\xf3\xef\xeb\x63\x12\x11\x46\x18\x8f\xba\x59\x67\xec\xa1\xc1\xaf\x74\x24\x72\xa7\x17\xe9\x63\x2f\xb9\x55\xe8\x53\xc8\xf6\xbb\x1f\xe3\x3c\xff\x66\xe1\xf8\x2c\x76\x9d\x3f\xda\xad\x5b\x17\x53\x5c\xeb\x98\x61\xb0\x58\x4c\xd6\xbc\xb1\xec\xd8\xa3\x70\xba\x24\x5c\xb1\x2c\x20\x19\xac\xae\x1e\x1d\x05\xfb\xeb\x06\xf7\x07\x1a\xf0\x68\x86\xde\x5e\x7c\xdd\x4d\x9b\xe2\x84\xc4\x0d\x5a\x58\x55\xa5\xf0\x13\x58\x78\xd5\x55\x55\xc8\x28\xe5\xca\x70\x40\xb7\xf9\x0c\x5d\x35\x95\xab\x86\x8e\x25\x6a\xa4\x8a\x11\x0e\xc0\x33\x08\x0c\x83\x26\xf0\x33\x85\x9f\x33\x32\x15\x7f\x86\xc8\x1b\x4d\xad\x6b\xc2\xe5\x2c\x6d\x0b\xf0\x32\x48\xbd\x5a\x94\x56\xf4\xd1\x13\x72\x16\xd3\x40\x4a\x15\x42\xd4\xe4\x30\xca\x06\xc8\x34\x83\xb5\xc0\x5d\x3f\xa2\x71\x33\x90\x95\x6c\x1a\xde\x1a\x6a\x60\xf2\x1f\x20\x05\xc0\x32\xb5\x46\x30\x4e\x53\x37\x2a\xc6\x9f\x5b\x4d\x7d\x36\x9d\x7c\x77\x7d\x77\xd9\x58\xcb\x2c\x66\x99\xd5\x0d\xfb\x30\x12\x4e\x50\x3f\x2d\xb9\x71\x72\x2d\x7c\x64\x8c\xd7\x3c\x09\xd1\x28\x9c\x29\x66\x9e\x4d\xaf\x2f\xa7\x97\x37\x0d\x30\x96\x53\x4e\x19\x70\x84\x42\x82\x39\xfd\x42\xba\xad\x5a\xd1\x39\x9a\xb4\xa5\x80\x77\x66\xca\x7c\x20\x34\x8c\x44\x6c\x89\x0f\x92\xd5\x67\x88\xc2\xe6\x42\x75\x4a\xf2\x35\xcb\xc0\x19\xdb\x34\x25\x99\x8f\xf3\x01\xb2\x50\x51\xbf\xdb\x62\xdc\xb4\x8d\xe4\x04\x85\x36\x04\x31\x7d\x48\x8f\x4d\x49\x94\x63\xac\xa6\xaa\x7a\x35\x0b\x57\xf8\x7c\xfa\xf6\xed\x1b\xb4\xff\xcb\xbb\x79\x3d\x70\x05\x9f\x7d\xbc\xfd\x78\x77\x37\x19\xaa\x9d\x11\x57\x95\x22\x64\x84\x4d\xb7\xb5\x6d\x8c\xf2\xed\x06\x3c\xd7\x2c\xe5\xd0\x5c\x10\xf0\x74\x81\xe3\x5d\xb7\x56\x3a\xd5\x39\x59\x03\x44\x8d\xb5\x27\x85\xfe\x4a\x21\xcb\x73\x6b\xa9\xc1\x5b\xce\x9a\xf1\xf3\xe8\xaa\x2c\xfb\xdd\xb5\xe1\xfe\x2a\xef\xcb\x16\xde\xa0\xd3\x67\xd1\xe8\x20\xb6\x46\x3c\x22\xa8\x90\xc0\xaa\x5f\x31\xe4\x25\x2c\x20\xcd\x25\xd8\x11\x56\xe2\x2a\x0b\x1d\x4d\xa4\xa1\x2d\xf5\x4e\xdb\x7e\x6a\x64\x72\xa5\x9f\x39\xa0\x0d\x33\x1d\x66\xd5\x42\x70\x2f\x60\x4d\x17\xf5\x49\x7f\x84\x68\x8d\xea\x64\x4e\x68\xaf\xbd\xd5\x96\x2f\xc3\x4f\xef\x9a\x55\xb1\x9e\xef\x74\xdd\x92\x11\x7a\xf1\x06\x15\xff\x79\xd3\x4a\x6c\x16\xb2\x54\x03\xd2\x1a\xce\x40\x52\x75\x7b\x8f\x1d\xbd\x0f\x64\x0d\x3d\xd7\xc4\x66\xcf\xaa\x0a\xab\x18\x57\x3d\xdd\x87\x7a\x9b\x81\x27\x7c\x68\x25\x7b\x60\xcf\xc8\xcd\x84\x4c\x7a\x12\x66\x15\xf8\x07\x70\x61\x2f\xe8\xc7\xef\x26\x1f\xaf\x2f\x87\x83\xfe\x95\x80\x7b\x37\xbd\xb0\x77\x77\xef\xbf\x9d\x5e\x0f\x87\xfd\x04\xdd\x66\x1f\xe6\xcd\xf7\xb7\x97\x57\xef\x87\x63\xfe\x44\x42\xc8\x8e\x74\x15\x5b\x23\xa0\x06\x7d\xf9\xed\xd5\xb7\x57\x77\xc3\xa1\xff\x9e\xdc\x27\xec\x21\x39\x35\x2e\xb4\x34\x2c\xdd\xa6\x6d\x2d\x73\xc2\x12\x62\x0d\x46\xd8\x52\x1a\x2d\x44\x19\xe0\x78\x05\x51\xb0\x35\x9b\xc1\xa2\x64\x4d\x2e\xaa\x9d\xaa\xb8\x1a\x6d\x93\x59\x61\xd5\x04\x11\xc7\x33\xe4\x4e\xde\x1a\x13\x8a\x91\xe9\x89\xda\xd3\x8e\x30\x97\x8a\x96\xbd\x92\xa5\x4d\xea\xee\x97\x65\x66\x69\x26\x0a\xdd\x0d\x37\x9b\x6f\xd9\x57\xec\x93\x90\xf8\x23\xfb\x99\x14\x67\xd0\x65\x1c\xea\xe2\xee\x0d\xdd\x68\x74\x98\x33\x65\xb5\x33\x3d\x59\xf8\xe1\x6d\x8b\x83\xb5\xff\x0c\xb3\x75\x6d\xd1\xd4\x82\xbb\xb0\x57\x8b\xe6\x56\xbe\xb0\xbf\xa2\x99\x48\xa7\xca\x7e\xb7\xdd\x57\xd5\xb6\xb9\x6a\xdf\xb6\xef\x56\x10\x79\x8a\xa1\x7c\x7a\xb0\x63\x56\x04\x3a\xd4\x66\xb1\xff\x1f\xf7\x8c\x58\xf7\xf2\xaf\x7e\xcf\x18\xd1\xf8\x5f\xf1\x12\x5a\x82\x2d\xbe\x34\x9c\xc4\xbe\x90\x0c\x7a\x0c\x08\xcf\x88\x06\x01\x49\x2c\xfb\x82\xfd\x14\x12\xc7\x34\xcd\x69\x3e\x98\xf3\x2c\x12\xc4\xb6\x8c\xcf\x52\xec\x53\x0e\x5e\xf1\x6e\x0e\x46\xeb\xcc\xf7\x16\x2f\x8b\xe6\x57\xfb\x74\x72\x63\xf8\x4a\x39\x29\xa0\x9b\x7a\x1f\x55\xeb\x7d\x57\x38\xcb\xed\xdd\x2e\x8c\xb8\xab\xb0\x4d\x9c\xf6\x46\xb6\xec\x09\x0d\x81\xb4\xac\xd7\xed\xf5\x69\xd8\xae\x54\x8a\x86\x0f\x39\x4d\x1a\x14\x9a\x46\x5c\x18\x67\x05\xe2\x2a\x02\xb2\xe3\xa0\xd2\x68\xa3\x0a\xb0\x7a\x43\xdc\xd7\xb2\x2b\x15\xcb\x36\xf3\x45\x1d\xa6\x06\x2b\xbb\xcb\x17\x36\x96\x1a\x4f\x36\x95\x2f\xec\x27\x35\x96\xea\x25\x5f\xd8\x46\x6a\xb4\x4f\xc6\x81\xe5\xc1\xdd\xa3\x86\xaa\x74\x8e\x2f\x6c\xee\x34\xa2\x6e\x18\x8f\x82\x83\x98\xfd\xb2\x8d\x13\x92\xe1\x15\x8d\xc1\x9d\xa4\x25\x7c\x3b\x36\xe3\x22\x5b\x40\x7e\x3f\x64\x37\x6d\x3d\xd5\x2d\x38\x78\x0d\x71\xde\x98\x33\xd6\x04\xf3\x6d\x06\x92\x2e\xd1\xb6\xb9\xf8\x0e\x78\x22\xd0\x25\x44\x17\x8b\x98\xe6\x5c\x57\x98\x7a\xdb\x6c\x43\x54\x48\x4d\xef\xbc\xe8\x70\x47\x61\xb6\x1f\x4f\xd6\xeb\xea\xd9\xed\xdd\x87\x9b\x0f\xb7\x83\x30\xff\xfc\x53\x3e\xb3\x6a\x3b\x13\x9b\xd8\x4f\x72\xf6\x30\xcd\xc5\x64\xc5\x51\x5d\xc8\x54\x1c\x0c\xa1\xaf\xe8\x46\xd8\x1c\xf7\x35\xba\x55\xe4\xe6\x71\x93\x71\x1e\x7c\xd3\x3c\xd8\xd2\x33\x32\x75\xf6\xe0\xb5\x3c\xd7\x69\xd7\x64\xbf\x45\x4f\xf0\xc6\x6c\xe2\xa4\xa5\x07\x24\x4f\x03\x76\xbf\x47\x6f\xc7\x1d\x94\x46\x0d\xe4\x62\x93\xde\x81\x3a\x24\xa1\x1a\xa8\x7a\x97\xde\x81\x3b\x24\xb5\x1a\xb8\x72\x9b\xde\x01\x3a\x24\xc9\x1a\xa0\xd5\x7d\x7a\x07\xf6\x90\x74\x6b\x60\x97\x1b\xf5\xa3\x80\x21\xf1\x42\x77\x41\xda\xda\x25\x39\xa6\x3e\xec\x31\xe9\x6f\xb3\x5c\xf0\x48\x19\x35\x4f\xa2\xed\x01\x2b\xae\xf6\xcc\xd3\xcc\x12\x5d\x7a\x88\xcb\x92\x6a\x6d\x76\xb3\x68\xa2\x3a\xd4\xae\x52\x3f\x20\x0b\x4a\x44\xcf\x8f\x59\x4e\x82\x4a\xc6\x1e\x74\xc0\xd1\x71\x92\xed\x8a\x6e\xbe\x0d\x65\x1d\x13\xe3\xc4\x62\x5f\xe4\xcc\x1e\xb5\xfb\xb0\xb9\x76\x18\x62\x78\xaa\x76\xdc\xdc\x97\xad\x6a\xc2\xdb\xce\x94\xfb\x9e\x5d\x08\xcd\x40\x88\x43\xb9\x1c\xb8\xa7\x3d\xe0\xe4\xda\xdc\x2d\x56\x36\xfb\x9d\xdd\xb0\xb1\xf7\xed\x7d\xa2\xa6\x4c\x9d\xd9\x38\x0f\xb3\x83\xae\x0e\x76\x7b\x1c\xd8\x60\x5b\xe0\x75\x95\xe8\xc7\x1f\x54\x2b\x2c\x1c\x44\xb5\x18\x80\x3e\xa4\x66\x58\xd0\x8b\xaa\x31\x00\x7f\x48\xed\xb0\xe0\x43\xf5\x18\x00\x3e\xa4\x86\x58\xc0\xf7\x55\x64\x00\x8f\x21\xb5\xc4\xc2\x43\x55\x93\x13\x31\xd0\x1b\x5f\xd7\xf6\x04\xec\x3f\x92\xcd\x7a\x63\x4c\x30\x73\x03\x9a\x11\x5f\xed\xcd\xd9\x83\x9b\x11\xa8\x03\xb9\x71\x58\x5b\x8b\xe6\xcb\xa6\x14\xed\x67\x31\x03\x2c\x71\x4c\x6a\xd4\x19\xe9\xa6\xeb\xd4\xd9\xd0\x79\xa8\x30\xa7\xd9\x93\x5b\x91\x4f\xb5\x41\xb7\x82\x9f\x62\xb7\x6e\x05\x3e\xcd\xd6\xdd\x0a\x7d\x82\x7d\xbc\x15\xf7\x74\x9b\x7a\x2b\xfc\xd1\x3b\xfc\xf9\x58\xbd\x75\x37\x1f\x17\xaf\x30\xbe\x9a\x8b\xf7\xee\xd4\x1b\x80\xe2\x98\x53\xbe\xee\x24\xde\x76\x52\xaf\x93\x39\xfb\x37\xf4\xe6\xea\x4d\x0d\x35\x65\xff\xee\x46\x65\x4e\x31\x6f\x62\x7d\x1f\x12\x78\x4e\x2a\x68\xe3\x82\x58\xbd\x0e\xd8\x14\x60\xff\xbe\x82\x7e\x2f\xcd\xe0\x32\x5d\xca\x77\x2b\xcd\xb7\x2c\x61\xe4\x55\x7d\x6e\x5e\x24\x19\x0d\xae\xd2\x6d\x03\x51\x8b\x60\xde\x15\xd7\xf3\xf3\x03\xe5\x11\xfa\xbf\x46\xdb\x7f\x0b\xf6\xe6\x68\xb6\x80\x7d\x9b\xf8\xf6\x3e\x8e\x7f\xab\x4f\xd8\xed\xac\x70\xf3\x74\x39\xcf\x53\x5c\x8a\x24\x5e\x0e\x74\xe0\x16\x68\x9c\x84\xcb\x5f\x19\x87\x28\x15\x9a\x59\xf9\x79\x72\x7c\xb7\x6b\x1e\xd5\x08\xf7\x4a\x7a\xf8\x02\xd8\xf0\x91\xda\x95\x69\x1f\xa8\xb8\xa0\x5a\x94\x2c\xa6\xda\x1b\x86\xae\x51\xc8\xed\x96\x29\x97\xea\x45\x8b\x1d\x9a\x4c\x65\x3a\x56\x44\xce\x52\x53\xcf\x90\xb6\x4c\x9b\x45\xd4\x4c\xe1\xfe\xd2\x06\xad\xbe\x2c\xc4\x26\x49\x00\x26\xec\x16\xbf\x12\xc8\x07\x69\xb0\xa7\x73\x96\x15\x8c\x7e\x3d\xf6\x93\x4f\xad\x8a\xc8\x75\x07\xe9\x00\x04\xce\x52\x50\xf5\x4b\x0d\xb3\x4e\x2d\xae\xca\xfa\x07\x49\x5c\xd0\x38\x4b\x45\xdb\x2f\x77\x31\xf1\xd4\xa2\xcb\x4a\x78\x90\xe0\x82\xc2\x59\x4a\xba\x7e\xa1\xc5\xb4\x53\x8b\x5c\x76\x06\x07\x89\xad\xa9\x9c\x65\x49\xdf\x2f\xbe\x9e\x7a\x6a\x15\x74\xdb\x74\x90\x06\x8a\xc8\x59\x6a\xea\x7e\xf9\xd5\xcc\x83\xc5\x6f\x49\xc4\xad\xa4\x55\x59\xeb\x5d\x40\x47\x32\x6e\x55\x10\xc9\xc2\xbf\x70\x54\x33\xdf\xa6\xdc\xdf\x14\xa3\xa2\xac\x39\x9a\x1c\x39\xbb\xdd\xd7\x4e\x9f\xa2\xed\xeb\xe3\x48\xee\xe5\xaa\x3a\x8e\xbd\x8c\xaa\x23\x59\xcb\x58\x3c\x8e\xad\xca\x42\x47\x32\x56\xb9\xeb\x38\xd6\x22\x65\x1f\xc9\x57\x24\xfa\xe3\x98\x56\x6a\xdd\x91\xbc\x2b\x15\xf2\x38\x11\x74\xc3\x70\x24\x7f\xdd\x66\xf4\x32\xef\x18\x6a\x8b\x72\x0b\x09\x24\x8e\xa2\x1f\x6d\xb6\xa9\x15\xb5\xda\x02\xfd\xf9\x39\xc3\x49\x48\x90\xf7\x19\x3a\xea\xfe\x56\x73\x8e\x6b\x76\x82\x4e\xf9\xb3\xd8\x62\x53\xfe\xb4\xdb\xe9\x7f\xdc\x73\xf6\xfc\x8c\x3c\xd1\x3b\x23\xb8\xd7\x9f\x8b\x02\xc6\xbb\x6d\x54\x99\x2b\x5f\x39\xe8\x49\x57\xcb\x7d\xc2\xf5\x74\x07\x3f\x2c\xb1\x4a\xea\x9a\x4a\x7d\x04\x5f\xb9\xae\x26\xfa\x51\x6c\x2e\x82\xad\x4f\xbe\x2f\xe9\x5c\x77\x18\xe9\x07\x92\xfb\x19\x4d\x85\x07\x07\x91\x2a\xb2\x4f\xe2\x7c\xba\x53\xc6\x96\xa1\xf9\x18\xdb\x16\x82\xb9\xde\x1a\xf4\xea\xd7\xfd\xef\x8d\x6d\x50\xb1\x2d\x6b\xee\xab\xec\x22\x54\x9d\x2a\xfe\x29\xc4\x80\x85\x52\x3c\xce\xe8\xdc\x39\x54\xd6\xb2\xb4\x4e\xdb\x6e\xa9\x84\xa6\xc1\xc2\x29\xd7\x89\x53\xe3\xd4\xc1\x48\x92\x47\x97\xb5\xe9\xea\xd1\x83\x83\x02\xcc\xb1\xcb\x59\x18\xc6\xc4\x95\x23\x55\x0e\xd5\x45\x19\x5d\xf6\x70\x50\x7e\xfe\x05\xf3\xa8\x77\x29\x36\x8d\xa5\x1f\x57\xf4\x68\x21\xc9\xb6\x71\xff\x24\x71\x95\xf6\xbd\x53\xe0\x1d\xd6\xad\x31\x88\x69\x43\xac\x01\x52\x95\xc4\xa6\x52\xda\xd4\xc3\x41\x24\x50\x99\x16\xca\xec\x54\x26\x06\x24\xf7\xce\x72\xe8\x37\x58\x35\x62\x4d\xcb\x51\x71\x13\xb9\xa8\xb6\xb3\x5e\x63\xb4\xc6\xae\xec\x1d\xbd\xcf\x1c\x04\x02\x33\xf8\x11\xf1\xef\x5d\x9f\x66\x7e\x4c\x20\x90\xe2\x1c\x1c\x4c\x1e\x81\x60\x83\x45\x80\xb8\x3c\xa3\x60\x39\x39\x26\x82\xcc\x41\x18\x6e\xb8\xc5\xf1\xe2\xc2\xe1\xd9\x96\x38\x7a\x8f\x3d\xdc\x30\xfd\x0b\xa2\x36\x7d\x1b\x6b\x0d\x1a\x35\xec\x40\x3b\x96\xab\x60\xd8\xc1\x44\xab\x3c\xfb\x45\xd1\x78\xf2\x0e\x4e\xd0\x19\xb8\xbd\x82\x74\x42\x63\x2b\x72\x19\xa1\xe2\x79\xaa\x08\xca\x4a\x95\xb2\xa6\xc4\x5e\x3e\xc5\xea\x29\x2b\x22\x80\x39\xd6\xe5\x75\x38\x72\x11\xfa\xa8\x5a\x1a\xd0\xa0\x1c\x60\x45\xc3\xaa\x32\x0b\xc4\x4f\xe2\x9f\xe5\x8a\x25\xc8\x71\x16\x12\xbe\x70\x56\x31\x4e\xee\x61\x63\x0e\xf7\x0f\xb6\xc2\x7c\x1c\xd3\x43\x57\x4f\xfb\xe6\xc5\xce\x61\x68\x76\x1a\x2e\xcb\x50\x19\xfa\x79\xf7\xf5\x07\x27\xdf\xc8\xb5\xdd\x5e\x65\x68\xdc\x6c\x0a\xcb\x99\xb5\xaf\x65\xab\x58\x19\x29\xbe\x17\x2b\x6d\x8f\x72\xbe\xde\x26\x72\xee\xf9\x6b\xf3\xf1\x6b\xce\x51\x51\xe3\xb2\x1c\x2d\x50\xc0\xfc\xed\x86\x40\x27\xfc\xcf\x2d\xc9\x9e\x3e\x93\x18\x98\xb0\xec\x7d\x1c\x9f\x8f\x7e\x37\xea\xe1\x1f\xa3\xd7\xcd\x97\x00\x92\x9c\xc5\xc4\x8b\x59\x78\xae\x41\x61\x4a\x6d\xce\x9a\x65\xe8\xfc\x0b\xce\x10\x05\x76\x7a\x92\x17\x93\x24\xe4\x11\x64\xe8\xc9\x3b\x18\x58\x2e\xd0\x05\x7c\xba\x6e\x53\x5e\x71\x69\x9a\xdf\xe9\x1f\x1e\x4b\xfc\x98\xfa\xf7\x80\x54\xaa\x48\x6c\x34\xe2\x22\x5e\x11\x28\x5e\xf1\x3a\xf0\x4f\xe2\xbc\x5c\x06\xfc\x27\x9a\x73\xaf\x40\x3d\x1f\x15\x6f\x09\x34\x15\x13\xd7\xae\x7e\x6b\xef\xed\xdd\xeb\x73\x35\x1d\x9c\xa2\x4c\x3f\x1f\x17\xc7\xe7\xe2\x3c\x5d\xfc\xbf\x02\xfe\x1d\x00\x00\xff\xff\x77\x27\x4f\xaf\x3b\x40\x00\x00")

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

	info := bindataFileInfo{name: "templates/analysis-template.html", size: 16443, mode: os.FileMode(420), modTime: time.Unix(1463551079, 0)}
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

