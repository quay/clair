// Copyright 2017 clair authors
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

package dpkg

import (
	"testing"

	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
)

func TestListFeatures(t *testing.T) {
	for _, test := range []featurefmt.TestCase{
		{
			"valid status file",
			map[string]string{"var/lib/dpkg/status": "dpkg/testdata/valid"},
			[]featurefmt.PackageInfo{
				{"adduser", "3.116ubuntu1", "", ""},
				{"apt", "1.6.3ubuntu0.1", "", ""},
				{"base-files", "10.1ubuntu2.2", "", ""},
				{"base-passwd", "3.5.44", "", ""},
				{"bash", "4.4.18-2ubuntu1", "", ""},
				{"bsdutils", "1:2.31.1-0.4ubuntu3.1", "util-linux", "2.31.1-0.4ubuntu3.1"},
				{"bzip2", "1.0.6-8.1", "", ""},
				{"coreutils", "8.28-1ubuntu1", "", ""},
				{"dash", "0.5.8-2.10", "", ""},
				{"debconf", "1.5.66", "", ""},
				{"debianutils", "4.8.4", "", ""},
				{"diffutils", "1:3.6-1", "", ""},
				{"dpkg", "1.19.0.5ubuntu2", "", ""},
				{"e2fsprogs", "1.44.1-1", "", ""},
				{"fdisk", "2.31.1-0.4ubuntu3.1", "util-linux", "2.31.1-0.4ubuntu3.1"},
				{"findutils", "4.6.0+git+20170828-2", "", ""},
				{"gcc-8-base", "8-20180414-1ubuntu2", "gcc-8", "8-20180414-1ubuntu2"},
				{"gpgv", "2.2.4-1ubuntu1.1", "gnupg2", "2.2.4-1ubuntu1.1"},
				{"grep", "3.1-2", "", ""},
				{"gzip", "1.6-5ubuntu1", "", ""},
				{"hostname", "3.20", "", ""},
				{"init-system-helpers", "1.51", "", ""},
				{"libacl1", "2.2.52-3build1", "acl", "2.2.52-3build1"},
				{"libapt-pkg5.0", "1.6.3ubuntu0.1", "apt", "1.6.3ubuntu0.1"},
				{"libattr1", "1:2.4.47-2build1", "attr", "1:2.4.47-2build1"},
				{"libaudit-common", "1:2.8.2-1ubuntu1", "audit", "1:2.8.2-1ubuntu1"},
				{"libaudit1", "1:2.8.2-1ubuntu1", "audit", "1:2.8.2-1ubuntu1"},
				{"libblkid1", "2.31.1-0.4ubuntu3.1", "util-linux", "2.31.1-0.4ubuntu3.1"},
				{"libbz2-1.0", "1.0.6-8.1", "bzip2", "1.0.6-8.1"},
				{"libc-bin", "2.27-3ubuntu1", "glibc", "2.27-3ubuntu1"},
				{"libc6", "2.27-3ubuntu1", "glibc", "2.27-3ubuntu1"},
				{"libcap-ng0", "0.7.7-3.1", "libcap-ng", "0.7.7-3.1"},
				{"libcom-err2", "1.44.1-1", "e2fsprogs", "1.44.1-1"},
				{"libdb5.3", "5.3.28-13.1ubuntu1", "db5.3", "5.3.28-13.1ubuntu1"},
				{"libdebconfclient0", "0.213ubuntu1", "cdebconf", "0.213ubuntu1"},
				{"libext2fs2", "1.44.1-1", "e2fsprogs", "1.44.1-1"},
				{"libfdisk1", "2.31.1-0.4ubuntu3.1", "util-linux", "2.31.1-0.4ubuntu3.1"},
				{"libffi6", "3.2.1-8", "libffi", "3.2.1-8"},
				{"libgcc1", "1:8-20180414-1ubuntu2", "gcc-8", "8-20180414-1ubuntu2"},
				{"libgcrypt20", "1.8.1-4ubuntu1.1", "", ""},
				{"libgmp10", "2:6.1.2+dfsg-2", "gmp", "2:6.1.2+dfsg-2"},
				{"libgnutls30", "3.5.18-1ubuntu1", "gnutls28", "3.5.18-1ubuntu1"},
				{"libgpg-error0", "1.27-6", "libgpg-error", "1.27-6"},
				{"libhogweed4", "3.4-1", "nettle", "3.4-1"},
				{"libidn2-0", "2.0.4-1.1build2", "libidn2", "2.0.4-1.1build2"},
				{"liblz4-1", "0.0~r131-2ubuntu3", "lz4", "0.0~r131-2ubuntu3"},
				{"liblzma5", "5.2.2-1.3", "xz-utils", "5.2.2-1.3"},
				{"libmount1", "2.31.1-0.4ubuntu3.1", "util-linux", "2.31.1-0.4ubuntu3.1"},
				{"libncurses5", "6.1-1ubuntu1.18.04", "ncurses", "6.1-1ubuntu1.18.04"},
				{"libncursesw5", "6.1-1ubuntu1.18.04", "ncurses", "6.1-1ubuntu1.18.04"},
				{"libnettle6", "3.4-1", "nettle", "3.4-1"},
				{"libp11-kit0", "0.23.9-2", "p11-kit", "0.23.9-2"},
				{"libpam-modules", "1.1.8-3.6ubuntu2", "pam", "1.1.8-3.6ubuntu2"},
				{"libpam-modules-bin", "1.1.8-3.6ubuntu2", "pam", "1.1.8-3.6ubuntu2"},
				{"libpam-runtime", "1.1.8-3.6ubuntu2", "pam", "1.1.8-3.6ubuntu2"},
				{"libpam0g", "1.1.8-3.6ubuntu2", "pam", "1.1.8-3.6ubuntu2"},
				{"libpcre3", "2:8.39-9", "pcre3", "2:8.39-9"},
				{"libprocps6", "2:3.3.12-3ubuntu1.1", "procps", "2:3.3.12-3ubuntu1.1"},
				{"libseccomp2", "2.3.1-2.1ubuntu4", "libseccomp", "2.3.1-2.1ubuntu4"},
				{"libselinux1", "2.7-2build2", "libselinux", "2.7-2build2"},
				{"libsemanage-common", "2.7-2build2", "libsemanage", "2.7-2build2"},
				{"libsemanage1", "2.7-2build2", "libsemanage", "2.7-2build2"},
				{"libsepol1", "2.7-1", "libsepol", "2.7-1"},
				{"libsmartcols1", "2.31.1-0.4ubuntu3.1", "util-linux", "2.31.1-0.4ubuntu3.1"},
				{"libss2", "1.44.1-1", "e2fsprogs", "1.44.1-1"},
				{"libstdc++6", "8-20180414-1ubuntu2", "gcc-8", "8-20180414-1ubuntu2"},
				{"libsystemd0", "237-3ubuntu10.3", "systemd", "237-3ubuntu10.3"},
				{"libtasn1-6", "4.13-2", "", ""},
				{"libtinfo5", "6.1-1ubuntu1.18.04", "ncurses", "6.1-1ubuntu1.18.04"},
				{"libudev1", "237-3ubuntu10.3", "systemd", "237-3ubuntu10.3"},
				{"libunistring2", "0.9.9-0ubuntu1", "libunistring", "0.9.9-0ubuntu1"},
				{"libuuid1", "2.31.1-0.4ubuntu3.1", "util-linux", "2.31.1-0.4ubuntu3.1"},
				{"libzstd1", "1.3.3+dfsg-2ubuntu1", "libzstd", "1.3.3+dfsg-2ubuntu1"},
				{"login", "1:4.5-1ubuntu1", "shadow", "1:4.5-1ubuntu1"},
				{"lsb-base", "9.20170808ubuntu1", "lsb", "9.20170808ubuntu1"},
				{"mawk", "1.3.3-17ubuntu3", "", ""},
				{"mount", "2.31.1-0.4ubuntu3.1", "util-linux", "2.31.1-0.4ubuntu3.1"},
				{"ncurses-base", "6.1-1ubuntu1.18.04", "ncurses", "6.1-1ubuntu1.18.04"},
				{"ncurses-bin", "6.1-1ubuntu1.18.04", "ncurses", "6.1-1ubuntu1.18.04"},
				{"passwd", "1:4.5-1ubuntu1", "shadow", "1:4.5-1ubuntu1"},
				{"perl-base", "5.26.1-6ubuntu0.2", "perl", "5.26.1-6ubuntu0.2"},
				{"procps", "2:3.3.12-3ubuntu1.1", "", ""},
				{"sed", "4.4-2", "", ""},
				{"sensible-utils", "0.0.12", "", ""},
				{"sysvinit-utils", "2.88dsf-59.10ubuntu1", "sysvinit", "2.88dsf-59.10ubuntu1"},
				{"tar", "1.29b-2", "", ""},
				{"ubuntu-keyring", "2018.02.28", "", ""},
				{"util-linux", "2.31.1-0.4ubuntu3.1", "", ""},
				{"zlib1g", "1:1.2.11.dfsg-0ubuntu2", "zlib", "1:1.2.11.dfsg-0ubuntu2"},
			},
		},
		{
			"corrupted status file",
			map[string]string{"var/lib/dpkg/status": "dpkg/testdata/corrupted"},
			[]featurefmt.PackageInfo{
				{"libpam-runtime", "1.1.8-3.1ubuntu3", "pam", "1.1.8-3.1ubuntu3"},
				{"libpam-modules-bin", "1.1.8-3.1ubuntu3", "pam", "1.1.8-3.1ubuntu3"},
				{"makedev", "2.3.1-93ubuntu1", "", ""},
				{"libgcc1", "1:5.1.1-12ubuntu1", "gcc-5", "5.1.1-12ubuntu1"},
			},
		},
	} {
		featurefmt.RunTest(t, test, &lister{}, dpkg.ParserName)
	}
}
