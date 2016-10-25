// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/context"
)

func TestSignedURL(t *testing.T) {
	expires, _ := time.Parse(time.RFC3339, "2002-10-02T10:00:00-05:00")
	url, err := SignedURL("bucket-name", "object-name", &SignedURLOptions{
		GoogleAccessID: "xxx@clientid",
		PrivateKey:     dummyKey("rsa"),
		Method:         "GET",
		MD5:            []byte("202cb962ac59075b964b07152d234b70"),
		Expires:        expires,
		ContentType:    "application/json",
		Headers:        []string{"x-header1", "x-header2"},
	})
	if err != nil {
		t.Error(err)
	}
	want := "https://storage.googleapis.com/bucket-name/object-name?" +
		"Expires=1033570800&GoogleAccessId=xxx%40clientid&Signature=" +
		"ITqNWQHr7ayIj%2B0Ds5%2FzUT2cWMQQouuFmu6L11Zd3kfNKvm3sjyGIzO" +
		"gZsSUoter1SxP7BcrCzgqIZ9fQmgQnuIpqqLL4kcGmTbKsQS6hTknpJM%2F" +
		"2lS4NY6UH1VXBgm2Tce28kz8rnmqG6svcGvtWuOgJsETeSIl1R9nAEIDCEq" +
		"ZJzoOiru%2BODkHHkpoFjHWAwHugFHX%2B9EX4SxaytiN3oEy48HpYGWV0I" +
		"h8NvU1hmeWzcLr41GnTADeCn7Eg%2Fb5H2GCNO70Cz%2Bw2fn%2BofLCUeR" +
		"YQd%2FhES8oocv5kpHZkstc8s8uz3aKMsMauzZ9MOmGy%2F6VULBgIVvi6a" +
		"AwEBIYOw%3D%3D"
	if url != want {
		t.Fatalf("Unexpected signed URL; found %v", url)
	}
}

func TestSignedURL_PEMPrivateKey(t *testing.T) {
	expires, _ := time.Parse(time.RFC3339, "2002-10-02T10:00:00-05:00")
	url, err := SignedURL("bucket-name", "object-name", &SignedURLOptions{
		GoogleAccessID: "xxx@clientid",
		PrivateKey:     dummyKey("pem"),
		Method:         "GET",
		MD5:            []byte("202cb962ac59075b964b07152d234b70"),
		Expires:        expires,
		ContentType:    "application/json",
		Headers:        []string{"x-header1", "x-header2"},
	})
	if err != nil {
		t.Error(err)
	}
	want := "https://storage.googleapis.com/bucket-name/object-name?" +
		"Expires=1033570800&GoogleAccessId=xxx%40clientid&Signature=" +
		"B7XkS4dfmVDoe%2FoDeXZkWlYmg8u2kI0SizTrzL5%2B9RmKnb5j7Kf34DZ" +
		"JL8Hcjr1MdPFLNg2QV4lEH86Gqgqt%2Fv3jFOTRl4wlzcRU%2FvV5c5HU8M" +
		"qW0FZ0IDbqod2RdsMONLEO6yQWV2HWFrMLKl2yMFlWCJ47et%2BFaHe6v4Z" +
		"EBc0%3D"
	if url != want {
		t.Fatalf("Unexpected signed URL; found %v", url)
	}
}

func TestSignedURL_MissingOptions(t *testing.T) {
	pk := dummyKey("rsa")
	var tests = []struct {
		opts   *SignedURLOptions
		errMsg string
	}{
		{
			&SignedURLOptions{},
			"missing required credentials",
		},
		{
			&SignedURLOptions{GoogleAccessID: "access_id"},
			"missing required credentials",
		},
		{
			&SignedURLOptions{
				GoogleAccessID: "access_id",
				PrivateKey:     pk,
			},
			"missing required method",
		},
		{
			&SignedURLOptions{
				GoogleAccessID: "access_id",
				PrivateKey:     pk,
				Method:         "PUT",
			},
			"missing required expires",
		},
	}
	for _, test := range tests {
		_, err := SignedURL("bucket", "name", test.opts)
		if !strings.Contains(err.Error(), test.errMsg) {
			t.Errorf("expected err: %v, found: %v", test.errMsg, err)
		}
	}
}

func dummyKey(kind string) []byte {
	slurp, err := ioutil.ReadFile(fmt.Sprintf("./testdata/dummy_%s", kind))
	if err != nil {
		log.Fatal(err)
	}
	return slurp
}

func TestCopyObjectMissingFields(t *testing.T) {
	var tests = []struct {
		srcBucket, srcName, destBucket, destName string
		errMsg                                   string
	}{
		{
			"mybucket", "", "mybucket", "destname",
			"srcName and destName must be non-empty",
		},
		{
			"mybucket", "srcname", "mybucket", "",
			"srcName and destName must be non-empty",
		},
		{
			"", "srcfile", "mybucket", "destname",
			"srcBucket and destBucket must both be non-empty",
		},
		{
			"mybucket", "srcfile", "", "destname",
			"srcBucket and destBucket must both be non-empty",
		},
	}
	for i, test := range tests {
		_, err := CopyObject(context.TODO(), test.srcBucket, test.srcName, test.destBucket, test.destName, nil)
		if !strings.Contains(err.Error(), test.errMsg) {
			t.Errorf("CopyObject test #%v: err = %v, want %v", i, err, test.errMsg)
		}
	}
}

func TestObjectNames(t *testing.T) {
	// Naming requirements: https://cloud.google.com/storage/docs/bucket-naming
	const maxLegalLength = 1024

	type testT struct {
		name, want string
	}
	tests := []testT{
		// Embedded characters important in URLs.
		{"foo % bar", "foo%20%25%20bar"},
		{"foo ? bar", "foo%20%3F%20bar"},
		{"foo / bar", "foo%20/%20bar"},
		{"foo %?/ bar", "foo%20%25%3F/%20bar"},

		// Non-Roman scripts
		{"타코", "%ED%83%80%EC%BD%94"},
		{"世界", "%E4%B8%96%E7%95%8C"},

		// Longest legal name
		{strings.Repeat("a", maxLegalLength), strings.Repeat("a", maxLegalLength)},

		// Line terminators besides CR and LF: https://en.wikipedia.org/wiki/Newline#Unicode
		{"foo \u000b bar", "foo%20%0B%20bar"},
		{"foo \u000c bar", "foo%20%0C%20bar"},
		{"foo \u0085 bar", "foo%20%C2%85%20bar"},
		{"foo \u2028 bar", "foo%20%E2%80%A8%20bar"},
		{"foo \u2029 bar", "foo%20%E2%80%A9%20bar"},

		// Null byte.
		{"foo \u0000 bar", "foo%20%00%20bar"},

		// Non-control characters that are discouraged, but not forbidden, according to the documentation.
		{"foo # bar", "foo%20%23%20bar"},
		{"foo []*? bar", "foo%20%5B%5D%2A%3F%20bar"},

		// Angstrom symbol singleton and normalized forms: http://unicode.org/reports/tr15/
		{"foo \u212b bar", "foo%20%E2%84%AB%20bar"},
		{"foo \u0041\u030a bar", "foo%20A%CC%8A%20bar"},
		{"foo \u00c5 bar", "foo%20%C3%85%20bar"},

		// Hangul separating jamo: http://www.unicode.org/versions/Unicode7.0.0/ch18.pdf (Table 18-10)
		{"foo \u3131\u314f bar", "foo%20%E3%84%B1%E3%85%8F%20bar"},
		{"foo \u1100\u1161 bar", "foo%20%E1%84%80%E1%85%A1%20bar"},
		{"foo \uac00 bar", "foo%20%EA%B0%80%20bar"},
	}

	// C0 control characters not forbidden by the docs.
	var runes []rune
	for r := rune(0x01); r <= rune(0x1f); r++ {
		if r != '\u000a' && r != '\u000d' {
			runes = append(runes, r)
		}
	}
	tests = append(tests, testT{fmt.Sprintf("foo %s bar", string(runes)), "foo%20%01%02%03%04%05%06%07%08%09%0B%0C%0E%0F%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F%20bar"})

	// C1 control characters, plus DEL.
	runes = nil
	for r := rune(0x7f); r <= rune(0x9f); r++ {
		runes = append(runes, r)
	}
	tests = append(tests, testT{fmt.Sprintf("foo %s bar", string(runes)), "foo%20%7F%C2%80%C2%81%C2%82%C2%83%C2%84%C2%85%C2%86%C2%87%C2%88%C2%89%C2%8A%C2%8B%C2%8C%C2%8D%C2%8E%C2%8F%C2%90%C2%91%C2%92%C2%93%C2%94%C2%95%C2%96%C2%97%C2%98%C2%99%C2%9A%C2%9B%C2%9C%C2%9D%C2%9E%C2%9F%20bar"})

	opts := &SignedURLOptions{
		GoogleAccessID: "xxx@clientid",
		PrivateKey:     dummyKey("rsa"),
		Method:         "GET",
		MD5:            []byte("202cb962ac59075b964b07152d234b70"),
		Expires:        time.Date(2002, time.October, 2, 10, 0, 0, 0, time.UTC),
		ContentType:    "application/json",
		Headers:        []string{"x-header1", "x-header2"},
	}

	for _, test := range tests {
		g, err := SignedURL("bucket-name", test.name, opts)
		if err != nil {
			t.Errorf("SignedURL(%q) err=%v, want nil", test.name, err)
		}
		if w := "/bucket-name/" + test.want; !strings.Contains(g, w) {
			t.Errorf("SignedURL(%q)=%q, want substring %q", test.name, g, w)
		}
	}
}
