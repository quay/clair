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

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/versionfmt/dpkg"
)

func TestListFeatures(t *testing.T) {
	for _, test := range []featurefmt.TestCase{
		{
			"valid status file",
			map[string]string{"var/lib/dpkg/status": "dpkg/testdata/valid"},
			[]database.Feature{
				{"adduser", "3.116ubuntu1", "adduser", "3.116ubuntu1", dpkg.ParserName},
				{"apt", "1.6.3ubuntu0.1", "apt", "1.6.3ubuntu0.1", dpkg.ParserName},
				{"base-files", "10.1ubuntu2.2", "base-files", "10.1ubuntu2.2", dpkg.ParserName},
				{"base-passwd", "3.5.44", "base-passwd", "3.5.44", dpkg.ParserName},
				{"bash", "4.4.18-2ubuntu1", "bash", "4.4.18-2ubuntu1", dpkg.ParserName},
				{"bsdutils", "1:2.31.1-0.4ubuntu3.1", "util-linux", "2.31.1-0.4ubuntu3.1", dpkg.ParserName},
				{"bzip2", "1.0.6-8.1", "bzip2", "1.0.6-8.1", dpkg.ParserName},
				{"coreutils", "8.28-1ubuntu1", "coreutils", "8.28-1ubuntu1", dpkg.ParserName},
				{"dash", "0.5.8-2.10", "dash", "0.5.8-2.10", dpkg.ParserName},
				{"debconf", "1.5.66", "debconf", "1.5.66", dpkg.ParserName},
				{"debianutils", "4.8.4", "debianutils", "4.8.4", dpkg.ParserName},
				{"diffutils", "1:3.6-1", "diffutils", "1:3.6-1", dpkg.ParserName},
				{"dpkg", "1.19.0.5ubuntu2", "dpkg", "1.19.0.5ubuntu2", dpkg.ParserName},
				{"e2fsprogs", "1.44.1-1", "e2fsprogs", "1.44.1-1", dpkg.ParserName},
				{"fdisk", "2.31.1-0.4ubuntu3.1", "util-linux", "2.31.1-0.4ubuntu3.1", dpkg.ParserName},
				{"findutils", "4.6.0+git+20170828-2", "findutils", "4.6.0+git+20170828-2", dpkg.ParserName},
				{"gcc-8-base", "8-20180414-1ubuntu2", "gcc-8", "8-20180414-1ubuntu2", dpkg.ParserName},
				{"gpgv", "2.2.4-1ubuntu1.1", "gnupg2", "2.2.4-1ubuntu1.1", dpkg.ParserName},
				{"grep", "3.1-2", "grep", "3.1-2", dpkg.ParserName},
				{"gzip", "1.6-5ubuntu1", "gzip", "1.6-5ubuntu1", dpkg.ParserName},
				{"hostname", "3.20", "hostname", "3.20", dpkg.ParserName},
				{"init-system-helpers", "1.51", "init-system-helpers", "1.51", dpkg.ParserName},
				{"libacl1", "2.2.52-3build1", "acl", "2.2.52-3build1", dpkg.ParserName},
				{"libapt-pkg5.0", "1.6.3ubuntu0.1", "apt", "1.6.3ubuntu0.1", dpkg.ParserName},
				{"libattr1", "1:2.4.47-2build1", "attr", "1:2.4.47-2build1", dpkg.ParserName},
				{"libaudit-common", "1:2.8.2-1ubuntu1", "audit", "1:2.8.2-1ubuntu1", dpkg.ParserName},
				{"libaudit1", "1:2.8.2-1ubuntu1", "audit", "1:2.8.2-1ubuntu1", dpkg.ParserName},
				{"libblkid1", "2.31.1-0.4ubuntu3.1", "util-linux", "2.31.1-0.4ubuntu3.1", dpkg.ParserName},
				{"libbz2-1.0", "1.0.6-8.1", "bzip2", "1.0.6-8.1", dpkg.ParserName},
				{"libc-bin", "2.27-3ubuntu1", "glibc", "2.27-3ubuntu1", dpkg.ParserName},
				{"libc6", "2.27-3ubuntu1", "glibc", "2.27-3ubuntu1", dpkg.ParserName},
				{"libcap-ng0", "0.7.7-3.1", "libcap-ng", "0.7.7-3.1", dpkg.ParserName},
				{"libcom-err2", "1.44.1-1", "e2fsprogs", "1.44.1-1", dpkg.ParserName},
				{"libdb5.3", "5.3.28-13.1ubuntu1", "db5.3", "5.3.28-13.1ubuntu1", dpkg.ParserName},
				{"libdebconfclient0", "0.213ubuntu1", "cdebconf", "0.213ubuntu1", dpkg.ParserName},
				{"libext2fs2", "1.44.1-1", "e2fsprogs", "1.44.1-1", dpkg.ParserName},
				{"libfdisk1", "2.31.1-0.4ubuntu3.1", "util-linux", "2.31.1-0.4ubuntu3.1", dpkg.ParserName},
				{"libffi6", "3.2.1-8", "libffi", "3.2.1-8", dpkg.ParserName},
				{"libgcc1", "1:8-20180414-1ubuntu2", "gcc-8", "8-20180414-1ubuntu2", dpkg.ParserName},
				{"libgcrypt20", "1.8.1-4ubuntu1.1", "libgcrypt20", "1.8.1-4ubuntu1.1", dpkg.ParserName},
				{"libgmp10", "2:6.1.2+dfsg-2", "gmp", "2:6.1.2+dfsg-2", dpkg.ParserName},
				{"libgnutls30", "3.5.18-1ubuntu1", "gnutls28", "3.5.18-1ubuntu1", dpkg.ParserName},
				{"libgpg-error0", "1.27-6", "libgpg-error", "1.27-6", dpkg.ParserName},
				{"libhogweed4", "3.4-1", "nettle", "3.4-1", dpkg.ParserName},
				{"libidn2-0", "2.0.4-1.1build2", "libidn2", "2.0.4-1.1build2", dpkg.ParserName},
				{"liblz4-1", "0.0~r131-2ubuntu3", "lz4", "0.0~r131-2ubuntu3", dpkg.ParserName},
				{"liblzma5", "5.2.2-1.3", "xz-utils", "5.2.2-1.3", dpkg.ParserName},
				{"libmount1", "2.31.1-0.4ubuntu3.1", "util-linux", "2.31.1-0.4ubuntu3.1", dpkg.ParserName},
				{"libncurses5", "6.1-1ubuntu1.18.04", "ncurses", "6.1-1ubuntu1.18.04", dpkg.ParserName},
				{"libncursesw5", "6.1-1ubuntu1.18.04", "ncurses", "6.1-1ubuntu1.18.04", dpkg.ParserName},
				{"libnettle6", "3.4-1", "nettle", "3.4-1", dpkg.ParserName},
				{"libp11-kit0", "0.23.9-2", "p11-kit", "0.23.9-2", dpkg.ParserName},
				{"libpam-modules", "1.1.8-3.6ubuntu2", "pam", "1.1.8-3.6ubuntu2", dpkg.ParserName},
				{"libpam-modules-bin", "1.1.8-3.6ubuntu2", "pam", "1.1.8-3.6ubuntu2", dpkg.ParserName},
				{"libpam-runtime", "1.1.8-3.6ubuntu2", "pam", "1.1.8-3.6ubuntu2", dpkg.ParserName},
				{"libpam0g", "1.1.8-3.6ubuntu2", "pam", "1.1.8-3.6ubuntu2", dpkg.ParserName},
				{"libpcre3", "2:8.39-9", "pcre3", "2:8.39-9", dpkg.ParserName},
				{"libprocps6", "2:3.3.12-3ubuntu1.1", "procps", "2:3.3.12-3ubuntu1.1", dpkg.ParserName},
				{"libseccomp2", "2.3.1-2.1ubuntu4", "libseccomp", "2.3.1-2.1ubuntu4", dpkg.ParserName},
				{"libselinux1", "2.7-2build2", "libselinux", "2.7-2build2", dpkg.ParserName},
				{"libsemanage-common", "2.7-2build2", "libsemanage", "2.7-2build2", dpkg.ParserName},
				{"libsemanage1", "2.7-2build2", "libsemanage", "2.7-2build2", dpkg.ParserName},
				{"libsepol1", "2.7-1", "libsepol", "2.7-1", dpkg.ParserName},
				{"libsmartcols1", "2.31.1-0.4ubuntu3.1", "util-linux", "2.31.1-0.4ubuntu3.1", dpkg.ParserName},
				{"libss2", "1.44.1-1", "e2fsprogs", "1.44.1-1", dpkg.ParserName},
				{"libstdc++6", "8-20180414-1ubuntu2", "gcc-8", "8-20180414-1ubuntu2", dpkg.ParserName},
				{"libsystemd0", "237-3ubuntu10.3", "systemd", "237-3ubuntu10.3", dpkg.ParserName},
				{"libtasn1-6", "4.13-2", "libtasn1-6", "4.13-2", dpkg.ParserName},
				{"libtinfo5", "6.1-1ubuntu1.18.04", "ncurses", "6.1-1ubuntu1.18.04", dpkg.ParserName},
				{"libudev1", "237-3ubuntu10.3", "systemd", "237-3ubuntu10.3", dpkg.ParserName},
				{"libunistring2", "0.9.9-0ubuntu1", "libunistring", "0.9.9-0ubuntu1", dpkg.ParserName},
				{"libuuid1", "2.31.1-0.4ubuntu3.1", "util-linux", "2.31.1-0.4ubuntu3.1", dpkg.ParserName},
				{"libzstd1", "1.3.3+dfsg-2ubuntu1", "libzstd", "1.3.3+dfsg-2ubuntu1", dpkg.ParserName},
				{"login", "1:4.5-1ubuntu1", "shadow", "1:4.5-1ubuntu1", dpkg.ParserName},
				{"lsb-base", "9.20170808ubuntu1", "lsb", "9.20170808ubuntu1", dpkg.ParserName},
				{"mawk", "1.3.3-17ubuntu3", "mawk", "1.3.3-17ubuntu3", dpkg.ParserName},
				{"mount", "2.31.1-0.4ubuntu3.1", "util-linux", "2.31.1-0.4ubuntu3.1", dpkg.ParserName},
				{"ncurses-base", "6.1-1ubuntu1.18.04", "ncurses", "6.1-1ubuntu1.18.04", dpkg.ParserName},
				{"ncurses-bin", "6.1-1ubuntu1.18.04", "ncurses", "6.1-1ubuntu1.18.04", dpkg.ParserName},
				{"passwd", "1:4.5-1ubuntu1", "shadow", "1:4.5-1ubuntu1", dpkg.ParserName},
				{"perl-base", "5.26.1-6ubuntu0.2", "perl", "5.26.1-6ubuntu0.2", dpkg.ParserName},
				{"procps", "2:3.3.12-3ubuntu1.1", "procps", "2:3.3.12-3ubuntu1.1", dpkg.ParserName},
				{"sed", "4.4-2", "sed", "4.4-2", dpkg.ParserName},
				{"sensible-utils", "0.0.12", "sensible-utils", "0.0.12", dpkg.ParserName},
				{"sysvinit-utils", "2.88dsf-59.10ubuntu1", "sysvinit", "2.88dsf-59.10ubuntu1", dpkg.ParserName},
				{"tar", "1.29b-2", "tar", "1.29b-2", dpkg.ParserName},
				{"ubuntu-keyring", "2018.02.28", "ubuntu-keyring", "2018.02.28", dpkg.ParserName},
				{"util-linux", "2.31.1-0.4ubuntu3.1", "util-linux", "2.31.1-0.4ubuntu3.1", dpkg.ParserName},
				{"zlib1g", "1:1.2.11.dfsg-0ubuntu2", "zlib", "1:1.2.11.dfsg-0ubuntu2", dpkg.ParserName},
			},
		},
		{
			"corrupted status file",
			map[string]string{"var/lib/dpkg/status": "dpkg/testdata/corrupted"},
			[]database.Feature{
				{"libpam-runtime", "1.1.8-3.1ubuntu3", "pam", "1.1.8-3.1ubuntu3", dpkg.ParserName},
				{"libpam-modules-bin", "1.1.8-3.1ubuntu3", "pam", "1.1.8-3.1ubuntu3", dpkg.ParserName},
				{"makedev", "2.3.1-93ubuntu1", "makedev", "2.3.1-93ubuntu1", dpkg.ParserName},
				{"libgcc1", "1:5.1.1-12ubuntu1", "gcc-5", "5.1.1-12ubuntu1", dpkg.ParserName},
			},
		},
	} {
		featurefmt.RunTest(t, test, &lister{}, dpkg.ParserName)
	}
}
