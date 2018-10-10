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

package rpm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/versionfmt/rpm"
)

var expectedBigCaseInfo = []featurefmt.PackageInfo{
	{"publicsuffix-list-dafsa", "20180514-1.fc28", "publicsuffix-list", "20180514-1.fc28"},
	{"libreport-filesystem", "2.9.5-1.fc28", "libreport", "2.9.5-1.fc28"},
	{"fedora-gpg-keys", "28-5", "fedora-repos", "28-5"},
	{"fedora-release", "28-2", "", ""},
	{"filesystem", "3.8-2.fc28", "", ""},
	{"tzdata", "2018e-1.fc28", "", ""},
	{"pcre2", "10.31-10.fc28", "", ""},
	{"glibc-minimal-langpack", "2.27-32.fc28", "glibc", "2.27-32.fc28"},
	{"glibc-common", "2.27-32.fc28", "glibc", "2.27-32.fc28"},
	{"bash", "4.4.23-1.fc28", "", ""},
	{"zlib", "1.2.11-8.fc28", "", ""},
	{"bzip2-libs", "1.0.6-26.fc28", "bzip2", "1.0.6-26.fc28"},
	{"libcap", "2.25-9.fc28", "", ""},
	{"libgpg-error", "1.31-1.fc28", "", ""},
	{"libzstd", "1.3.5-1.fc28", "zstd", "1.3.5-1.fc28"},
	{"expat", "2.2.5-3.fc28", "", ""},
	{"nss-util", "3.38.0-1.0.fc28", "", ""},
	{"libcom_err", "1.44.2-0.fc28", "e2fsprogs", "1.44.2-0.fc28"},
	{"libffi", "3.1-16.fc28", "", ""},
	{"libgcrypt", "1.8.3-1.fc28", "", ""},
	{"libxml2", "2.9.8-4.fc28", "", ""},
	{"libacl", "2.2.53-1.fc28", "acl", "2.2.53-1.fc28"},
	{"sed", "4.5-1.fc28", "", ""},
	{"libmount", "2.32.1-1.fc28", "util-linux", "2.32.1-1.fc28"},
	{"p11-kit", "0.23.12-1.fc28", "", ""},
	{"libidn2", "2.0.5-1.fc28", "", ""},
	{"libcap-ng", "0.7.9-4.fc28", "", ""},
	{"lz4-libs", "1.8.1.2-4.fc28", "lz4", "1.8.1.2-4.fc28"},
	{"libassuan", "2.5.1-3.fc28", "", ""},
	{"keyutils-libs", "1.5.10-6.fc28", "keyutils", "1.5.10-6.fc28"},
	{"glib2", "2.56.1-4.fc28", "", ""},
	{"systemd-libs", "238-9.git0e0aa59.fc28", "systemd", "238-9.git0e0aa59.fc28"},
	{"dbus-libs", "1:1.12.10-1.fc28", "dbus", "1.12.10-1.fc28"},
	{"libtasn1", "4.13-2.fc28", "", ""},
	{"ca-certificates", "2018.2.24-1.0.fc28", "", ""},
	{"libarchive", "3.3.1-4.fc28", "", ""},
	{"openssl", "1:1.1.0h-3.fc28", "openssl", "1.1.0h-3.fc28"},
	{"libusbx", "1.0.22-1.fc28", "", ""},
	{"libsemanage", "2.8-2.fc28", "", ""},
	{"libutempter", "1.1.6-14.fc28", "", ""},
	{"mpfr", "3.1.6-1.fc28", "", ""},
	{"gnutls", "3.6.3-4.fc28", "", ""},
	{"gzip", "1.9-3.fc28", "", ""},
	{"acl", "2.2.53-1.fc28", "", ""},
	{"nss-softokn-freebl", "3.38.0-1.0.fc28", "nss-softokn", "3.38.0-1.0.fc28"},
	{"nss", "3.38.0-1.0.fc28", "", ""},
	{"libmetalink", "0.1.3-6.fc28", "", ""},
	{"libdb-utils", "5.3.28-30.fc28", "libdb", "5.3.28-30.fc28"},
	{"file-libs", "5.33-7.fc28", "file", "5.33-7.fc28"},
	{"libsss_idmap", "1.16.3-2.fc28", "sssd", "1.16.3-2.fc28"},
	{"libsigsegv", "2.11-5.fc28", "", ""},
	{"krb5-libs", "1.16.1-13.fc28", "krb5", "1.16.1-13.fc28"},
	{"libnsl2", "1.2.0-2.20180605git4a062cf.fc28", "", ""},
	{"python3-pip", "9.0.3-2.fc28", "python-pip", "9.0.3-2.fc28"},
	{"python3", "3.6.6-1.fc28", "", ""},
	{"pam", "1.3.1-1.fc28", "", ""},
	{"python3-gobject-base", "3.28.3-1.fc28", "pygobject3", "3.28.3-1.fc28"},
	{"python3-smartcols", "0.3.0-2.fc28", "python-smartcols", "0.3.0-2.fc28"},
	{"python3-iniparse", "0.4-30.fc28", "python-iniparse", "0.4-30.fc28"},
	{"openldap", "2.4.46-3.fc28", "", ""},
	{"libseccomp", "2.3.3-2.fc28", "", ""},
	{"npth", "1.5-4.fc28", "", ""},
	{"gpgme", "1.10.0-4.fc28", "", ""},
	{"json-c", "0.13.1-2.fc28", "", ""},
	{"libyaml", "0.1.7-5.fc28", "", ""},
	{"libpkgconf", "1.4.2-1.fc28", "pkgconf", "1.4.2-1.fc28"},
	{"pkgconf-pkg-config", "1.4.2-1.fc28", "pkgconf", "1.4.2-1.fc28"},
	{"iptables-libs", "1.6.2-3.fc28", "iptables", "1.6.2-3.fc28"},
	{"device-mapper-libs", "1.02.146-5.fc28", "lvm2", "2.02.177-5.fc28"},
	{"systemd-pam", "238-9.git0e0aa59.fc28", "systemd", "238-9.git0e0aa59.fc28"},
	{"systemd", "238-9.git0e0aa59.fc28", "", ""},
	{"elfutils-default-yama-scope", "0.173-1.fc28", "elfutils", "0.173-1.fc28"},
	{"libcurl", "7.59.0-6.fc28", "curl", "7.59.0-6.fc28"},
	{"python3-librepo", "1.8.1-7.fc28", "librepo", "1.8.1-7.fc28"},
	{"rpm-plugin-selinux", "4.14.1-9.fc28", "rpm", "4.14.1-9.fc28"},
	{"rpm", "4.14.1-9.fc28", "", ""},
	{"libdnf", "0.11.1-3.fc28", "", ""},
	{"rpm-build-libs", "4.14.1-9.fc28", "rpm", "4.14.1-9.fc28"},
	{"python3-rpm", "4.14.1-9.fc28", "rpm", "4.14.1-9.fc28"},
	{"dnf", "2.7.5-12.fc28", "", ""},
	{"deltarpm", "3.6-25.fc28", "", ""},
	{"sssd-client", "1.16.3-2.fc28", "sssd", "1.16.3-2.fc28"},
	{"cracklib-dicts", "2.9.6-13.fc28", "cracklib", "2.9.6-13.fc28"},
	{"tar", "2:1.30-3.fc28", "tar", "1.30-3.fc28"},
	{"diffutils", "3.6-4.fc28", "", ""},
	{"langpacks-en", "1.0-12.fc28", "langpacks", "1.0-12.fc28"},
	{"libgcc", "8.1.1-5.fc28", "gcc", "8.1.1-5.fc28"},
	{"pkgconf-m4", "1.4.2-1.fc28", "pkgconf", "1.4.2-1.fc28"},
	{"dnf-conf", "2.7.5-12.fc28", "dnf", "2.7.5-12.fc28"},
	{"fedora-repos", "28-5", "", ""},
	{"setup", "2.11.4-1.fc28", "", ""},
	{"basesystem", "11-5.fc28", "", ""},
	{"ncurses-base", "6.1-5.20180224.fc28", "ncurses", "6.1-5.20180224.fc28"},
	{"libselinux", "2.8-1.fc28", "", ""},
	{"ncurses-libs", "6.1-5.20180224.fc28", "ncurses", "6.1-5.20180224.fc28"},
	{"glibc", "2.27-32.fc28", "", ""},
	{"libsepol", "2.8-1.fc28", "", ""},
	{"xz-libs", "5.2.4-2.fc28", "xz", "5.2.4-2.fc28"},
	{"info", "6.5-4.fc28", "texinfo", "6.5-4.fc28"},
	{"libdb", "5.3.28-30.fc28", "", ""},
	{"elfutils-libelf", "0.173-1.fc28", "elfutils", "0.173-1.fc28"},
	{"popt", "1.16-14.fc28", "", ""},
	{"nspr", "4.19.0-1.fc28", "", ""},
	{"libxcrypt", "4.1.2-1.fc28", "", ""},
	{"lua-libs", "5.3.4-10.fc28", "lua", "5.3.4-10.fc28"},
	{"libuuid", "2.32.1-1.fc28", "util-linux", "2.32.1-1.fc28"},
	{"readline", "7.0-11.fc28", "", ""},
	{"libattr", "2.4.48-3.fc28", "attr", "2.4.48-3.fc28"},
	{"coreutils-single", "8.29-7.fc28", "coreutils", "8.29-7.fc28"},
	{"libblkid", "2.32.1-1.fc28", "util-linux", "2.32.1-1.fc28"},
	{"gmp", "1:6.1.2-7.fc28", "gmp", "6.1.2-7.fc28"},
	{"libunistring", "0.9.10-1.fc28", "", ""},
	{"sqlite-libs", "3.22.0-4.fc28", "sqlite", "3.22.0-4.fc28"},
	{"audit-libs", "2.8.4-2.fc28", "audit", "2.8.4-2.fc28"},
	{"chkconfig", "1.10-4.fc28", "", ""},
	{"libsmartcols", "2.32.1-1.fc28", "util-linux", "2.32.1-1.fc28"},
	{"pcre", "8.42-3.fc28", "", ""},
	{"grep", "3.1-5.fc28", "", ""},
	{"crypto-policies", "20180425-5.git6ad4018.fc28", "", ""},
	{"gdbm-libs", "1:1.14.1-4.fc28", "gdbm", "1.14.1-4.fc28"},
	{"p11-kit-trust", "0.23.12-1.fc28", "p11-kit", "0.23.12-1.fc28"},
	{"openssl-libs", "1:1.1.0h-3.fc28", "openssl", "1.1.0h-3.fc28"},
	{"ima-evm-utils", "1.1-2.fc28", "", ""},
	{"gdbm", "1:1.14.1-4.fc28", "gdbm", "1.14.1-4.fc28"},
	{"gobject-introspection", "1.56.1-1.fc28", "", ""},
	{"shadow-utils", "2:4.6-1.fc28", "shadow-utils", "4.6-1.fc28"},
	{"libpsl", "0.20.2-2.fc28", "", ""},
	{"nettle", "3.4-2.fc28", "", ""},
	{"libfdisk", "2.32.1-1.fc28", "util-linux", "2.32.1-1.fc28"},
	{"cracklib", "2.9.6-13.fc28", "", ""},
	{"libcomps", "0.1.8-11.fc28", "", ""},
	{"nss-softokn", "3.38.0-1.0.fc28", "", ""},
	{"nss-sysinit", "3.38.0-1.0.fc28", "nss", "3.38.0-1.0.fc28"},
	{"libksba", "1.3.5-7.fc28", "", ""},
	{"kmod-libs", "25-2.fc28", "kmod", "25-2.fc28"},
	{"libsss_nss_idmap", "1.16.3-2.fc28", "sssd", "1.16.3-2.fc28"},
	{"libverto", "0.3.0-5.fc28", "", ""},
	{"gawk", "4.2.1-1.fc28", "", ""},
	{"libtirpc", "1.0.3-3.rc2.fc28", "", ""},
	{"python3-libs", "3.6.6-1.fc28", "python3", "3.6.6-1.fc28"},
	{"python3-setuptools", "39.2.0-6.fc28", "python-setuptools", "39.2.0-6.fc28"},
	{"libpwquality", "1.4.0-7.fc28", "", ""},
	{"util-linux", "2.32.1-1.fc28", "", ""},
	{"python3-libcomps", "0.1.8-11.fc28", "libcomps", "0.1.8-11.fc28"},
	{"python3-six", "1.11.0-3.fc28", "python-six", "1.11.0-3.fc28"},
	{"cyrus-sasl-lib", "2.1.27-0.2rc7.fc28", "cyrus-sasl", "2.1.27-0.2rc7.fc28"},
	{"libssh", "0.8.2-1.fc28", "", ""},
	{"qrencode-libs", "3.4.4-5.fc28", "qrencode", "3.4.4-5.fc28"},
	{"gnupg2", "2.2.8-1.fc28", "", ""},
	{"python3-gpg", "1.10.0-4.fc28", "gpgme", "1.10.0-4.fc28"},
	{"libargon2", "20161029-5.fc28", "argon2", "20161029-5.fc28"},
	{"libmodulemd", "1.6.2-2.fc28", "", ""},
	{"pkgconf", "1.4.2-1.fc28", "", ""},
	{"libpcap", "14:1.9.0-1.fc28", "libpcap", "1.9.0-1.fc28"},
	{"device-mapper", "1.02.146-5.fc28", "lvm2", "2.02.177-5.fc28"},
	{"cryptsetup-libs", "2.0.4-1.fc28", "cryptsetup", "2.0.4-1.fc28"},
	{"elfutils-libs", "0.173-1.fc28", "elfutils", "0.173-1.fc28"},
	{"dbus", "1:1.12.10-1.fc28", "dbus", "1.12.10-1.fc28"},
	{"libnghttp2", "1.32.1-1.fc28", "nghttp2", "1.32.1-1.fc28"},
	{"librepo", "1.8.1-7.fc28", "", ""},
	{"curl", "7.59.0-6.fc28", "", ""},
	{"rpm-libs", "4.14.1-9.fc28", "rpm", "4.14.1-9.fc28"},
	{"libsolv", "0.6.35-1.fc28", "", ""},
	{"python3-hawkey", "0.11.1-3.fc28", "libdnf", "0.11.1-3.fc28"},
	{"rpm-sign-libs", "4.14.1-9.fc28", "rpm", "4.14.1-9.fc28"},
	{"python3-dnf", "2.7.5-12.fc28", "dnf", "2.7.5-12.fc28"},
	{"dnf-yum", "2.7.5-12.fc28", "dnf", "2.7.5-12.fc28"},
	{"rpm-plugin-systemd-inhibit", "4.14.1-9.fc28", "rpm", "4.14.1-9.fc28"},
	{"nss-tools", "3.38.0-1.0.fc28", "nss", "3.38.0-1.0.fc28"},
	{"openssl-pkcs11", "0.4.8-1.fc28", "", ""},
	{"vim-minimal", "2:8.1.328-1.fc28", "vim", "8.1.328-1.fc28"},
	{"glibc-langpack-en", "2.27-32.fc28", "glibc", "2.27-32.fc28"},
	{"rootfiles", "8.1-22.fc28", "", ""},
}

func TestRpmFeatureDetection(t *testing.T) {
	for _, test := range []featurefmt.TestCase{
		{
			"valid small case",
			map[string]string{"var/lib/rpm/Packages": "rpm/testdata/valid"},
			[]featurefmt.PackageInfo{
				{"centos-release", "7-1.1503.el7.centos.2.8", "", ""},
				{"filesystem", "3.2-18.el7", "", ""},
			},
		},
		{
			"valid big case",
			map[string]string{"var/lib/rpm/Packages": "rpm/testdata/valid_big"},
			expectedBigCaseInfo,
		},
	} {
		featurefmt.RunTest(t, test, lister{}, rpm.ParserName)
	}
}

func TestParseSourceRPM(t *testing.T) {
	for _, test := range [...]struct {
		sourceRPM string

		expectedName    string
		expectedVersion string
		expectedErr     string
	}{
		// valid cases
		{"publicsuffix-list-20180514-1.fc28.src.rpm", "publicsuffix-list", "20180514-1.fc28", ""},
		{"libreport-2.9.5-1.fc28.src.rpm", "libreport", "2.9.5-1.fc28", ""},
		{"lua-5.3.4-10.fc28.src.rpm", "lua", "5.3.4-10.fc28", ""},
		{"crypto-policies-20180425-5.git6ad4018.fc28.src.rpm", "crypto-policies", "20180425-5.git6ad4018.fc28", ""},

		// invalid cases
		{"crypto-policies-20180425-5.git6ad4018.fc28.src.dpkg", "", "", "unexpected package type, expect: 'rpm', got: 'dpkg'"},
		{"crypto-policies-20180425-5.git6ad4018.fc28.debian-8.rpm", "", "", "unexpected package architecture, expect: 'src' or 'nosrc', got: 'debian-8'"},
		{"fc28.src.rpm", "", "", "unexpected termination while parsing 'Release Token'"},
		{"...", "", "", "unexpected package type, expect: 'rpm', got: ''"},

		// impossible case
		// This illustrates the limitation of this parser, it will not find the
		// error cased by extra '-' in the intended version/expect token. Based
		// on the documentation, this case should never happen and indicates a
		// corrupted rpm database.
		// actual expected: name="lua", version="5.3.4", release="10.fc-28"
		{"lua-5.3.4-10.fc-28.src.rpm", "lua-5.3.4", "10.fc-28", ""},
	} {
		pkg := featurefmt.PackageInfo{}
		err := parseSourceRPM(test.sourceRPM, &pkg)
		if test.expectedErr != "" {
			require.EqualError(t, err, test.expectedErr)
			continue
		}

		require.Nil(t, err)
		require.Equal(t, test.expectedName, pkg.SourceName)
		require.Equal(t, test.expectedVersion, pkg.SourceVersion)
	}
}
