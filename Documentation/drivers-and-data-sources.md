# Understanding drivers, their data sources, and creating your own

Clair is organized into many different software components all of which are dynamically registered at compile time.
All of these components can be found in the `ext/` directory.

## Driver Types

| Driver Type  | Functionality                                                                      | Example       |
|--------------|------------------------------------------------------------------------------------|---------------|
| featurefmt   | parses features of a particular format out of a layer                              | apk           |
| featurens    | identifies whether a particular namespaces is applicable to a layer                | alpine 3.5    |
| imagefmt     | determines the location of the root filesystem location for a layer                | docker        |
| notification | implements the transport used to notify of vulnerability changes                   | webhook       |
| versionfmt   | parses and compares version strings                                                | rpm           |
| vulnmdsrc    | fetches vulnerability metadata and appends them to vulnerabilities being processed | nvd           |
| vulnsrc      | fetches vulnerabilities for a set of namespaces                                    | alpine-sec-db |

## Data Sources for the built-in drivers

| Data Source                        | Data Collected                                                           | Format | License         |
|------------------------------------|--------------------------------------------------------------------------|--------|-----------------|
| [Debian Security Bug Tracker]      | Debian 6, 7, 8, unstable namespaces                                      | [dpkg] | [Debian]        |
| [Ubuntu CVE Tracker]               | Ubuntu 12.04, 12.10, 13.04, 14.04, 14.10, 15.04, 15.10, 16.04 namespaces | [dpkg] | [GPLv2]         |
| [Red Hat Security Data]            | CentOS 5, 6, 7 namespaces                                                | [rpm]  | [CVRF]          |
| [Oracle Linux Security Data]       | Oracle Linux 5, 6, 7 namespaces                                          | [rpm]  | [CVRF]          |
| [Amazon Linux Security Advisories] | Amazon Linux 2018.03, 2 namespaces                                       | [rpm]  | [MIT-0]         |
| [SUSE OVAL Descriptions]           | openSUSE, SUSE Linux Enterprise namespaces                               | [rpm]  | [CC-BY-NC-4.0]  |
| [Alpine SecDB]                     | Alpine 3.3, Alpine 3.4, Alpine 3.5 namespaces                            | [apk]  | [MIT]           |
| [NIST NVD]                         | Generic Vulnerability Metadata                                           | N/A    | [Public Domain] |

[Debian Security Bug Tracker]: https://security-tracker.debian.org/tracker
[Ubuntu CVE Tracker]: https://launchpad.net/ubuntu-cve-tracker
[Red Hat Security Data]: https://www.redhat.com/security/data/metrics
[Oracle Linux Security Data]: https://linux.oracle.com/security/
[SUSE OVAL Descriptions]: https://www.suse.com/de-de/support/security/oval/
[Amazon Linux Security Advisories]: https://alas.aws.amazon.com/
[NIST NVD]: https://nvd.nist.gov
[dpkg]: https://en.wikipedia.org/wiki/dpkg
[rpm]: http://www.rpm.org
[Debian]: https://www.debian.org/license
[GPLv2]: https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html
[CVRF]: http://www.icasi.org/cvrf-licensing/
[Public Domain]: https://nvd.nist.gov/faq
[Alpine SecDB]: http://git.alpinelinux.org/cgit/alpine-secdb/
[apk]: http://git.alpinelinux.org/cgit/apk-tools/
[MIT]: https://gist.github.com/jzelinskie/6da1e2da728424d88518be2adbd76979
[MIT-0]: https://spdx.org/licenses/MIT-0.html
[CC-BY-NC-4.0]: https://creativecommons.org/licenses/by-nc/4.0/]

## Adding new drivers

In order to allow programmers to add additional behavior, Clair follows a pattern that Go programmers may recognize from the standard `database/sql` library.
Each Driver Type defines an interface that must be implemented by drivers.

```go
type DriverInterface interface {
	Action() error
}

func RegisterDriver(name, DriverInterface) { ... }
```

Create a new Go package containing an implementation of the driver interface.
In the source file that implements this custom interface, create an `init()` function that registers the driver.

```go
func init() {
	drivers.RegisterDriver("mydrivername", myDriverImplementation{})
}

// This line causes the Go compiler to enforce that myDriverImplementation
// implements the the DriverInterface at compile time.
var _ drivers.DriverInterface = myDriverImplementation{}

type myDriverImplementation struct{}

func (d myDriverImplementation) Action() error {
	fmt.Println("Hello, Clair!")
	return nil
}
```

The final step is to import the new driver in `main.go` as `_` in order ensure that the `init()` function executes, thus registering your driver.

```go
import (
	...

	_ "github.com/you/yourclairdriver"
)
```

If you believe what you've created can benefit others outside of your organization, please consider open sourcing it and creating a pull request to get it included by default.
