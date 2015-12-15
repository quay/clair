// Copyright 2015 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/ioutil"
	"strings"
)

var (
	// ErrCouldNotExtract occurs when an extraction fails.
	ErrCouldNotExtract = errors.New("utils: could not extract the archive")

	// ErrExtractedFileTooBig occurs when a file to extract is too big.
	ErrExtractedFileTooBig = errors.New("utils: could not extract one or more files from the archive: file too big")

	gzipHeader = []byte{0x1f, 0x8b}
)

// SelectivelyExtractArchive extracts the specified files and folders
// from targz data read from the given reader and store them in a map indexed by file paths
func SelectivelyExtractArchive(r io.Reader, prefix string, toExtract []string, maxFileSize int64) (map[string][]byte, error) {
	data := make(map[string][]byte)

	// Create a tar or tar/tar-gzip reader
	tr, err := getTarReader(r)
	if err != nil {
		return data, ErrCouldNotExtract
	}

	// For each element in the archive
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return data, ErrCouldNotExtract
		}

		// Get element filename
		filename := hdr.Name
		filename = strings.TrimPrefix(filename, "./")
		if prefix != "" {
			filename = strings.TrimPrefix(filename, prefix)
		}

		// Determine if we should extract the element
		toBeExtracted := false
		for _, s := range toExtract {
			if strings.HasPrefix(filename, s) {
				toBeExtracted = true
				break
			}
		}

		if toBeExtracted {
			// File size limit
			if maxFileSize > 0 && hdr.Size > maxFileSize {
				return data, ErrExtractedFileTooBig
			}

			// Extract the element
			if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink || hdr.Typeflag == tar.TypeReg {
				d, _ := ioutil.ReadAll(tr)
				data[filename] = d
			}
		}
	}

	return data, nil
}

// getTarReader returns a tar.Reader associated with the specified io.Reader,
// optionally backed by a gzip.Reader if gzip compression is detected.
//
// Gzip detection is done by using the magic numbers defined in the RFC1952 :
// the first two bytes should be 0x1f and 0x8b..
func getTarReader(r io.Reader) (*tar.Reader, error) {
	br := bufio.NewReader(r)
	header, err := br.Peek(2)

	if err == nil && bytes.Equal(header, gzipHeader) {
		gr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		return tar.NewReader(gr), nil
	}

	return tar.NewReader(br), nil
}
