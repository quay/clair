---
title: "info"
description: "The info command description and usage"
keywords: "display, docker, information"
---

<!-- This file is maintained within the docker/docker Github
     repository at https://github.com/docker/docker/. Make all
     pull requests against that repo. If you see this file in
     another repository, consider it read-only there, as it will
     periodically be overwritten by the definitive file. Pull
     requests which include edits to this file in other repositories
     will be rejected.
-->

# info

```markdown
Usage:  docker info [OPTIONS]

Display system-wide information

Options:
  -f, --format string   Format the output using the given Go template
      --help            Print usage
```

This command displays system wide information regarding the Docker installation.
Information displayed includes the kernel version, number of containers and images.
The number of images shown is the number of unique images. The same image tagged
under different names is counted only once.

If a format is specified, the given template will be executed instead of the
default format. Go's [text/template](http://golang.org/pkg/text/template/) package
describes all the details of the format.

Depending on the storage driver in use, additional information can be shown, such
as pool name, data file, metadata file, data space used, total data space, metadata
space used, and total metadata space.

The data file is where the images are stored and the metadata file is where the
meta data regarding those images are stored. When run for the first time Docker
allocates a certain amount of data space and meta data space from the space
available on the volume where `/var/lib/docker` is mounted.

# Examples

## Display Docker system information

Here is a sample output for a daemon running on Ubuntu, using the overlay2
storage driver and a node that is part of a 2-node swarm:

    $ docker -D info
    Containers: 14
     Running: 3
     Paused: 1
     Stopped: 10
    Images: 52
    Server Version: 1.13.0
    Storage Driver: overlay2
     Backing Filesystem: extfs
     Supports d_type: true
     Native Overlay Diff: false
    Logging Driver: json-file
    Cgroup Driver: cgroupfs
    Plugins:
     Volume: local
     Network: bridge host macvlan null overlay
    Swarm: active
     NodeID: rdjq45w1op418waxlairloqbm
     Is Manager: true
     ClusterID: te8kdyw33n36fqiz74bfjeixd
     Managers: 1
     Nodes: 2
     Orchestration:
      Task History Retention Limit: 5
     Raft:
      Snapshot Interval: 10000
      Number of Old Snapshots to Retain: 0
      Heartbeat Tick: 1
      Election Tick: 3
     Dispatcher:
      Heartbeat Period: 5 seconds
     CA Configuration:
      Expiry Duration: 3 months
     Node Address: 172.16.66.128 172.16.66.129
     Manager Addresses:
      172.16.66.128:2477
    Runtimes: runc
    Default Runtime: runc
    Init Binary: docker-init
    containerd version: 8517738ba4b82aff5662c97ca4627e7e4d03b531
    runc version: ac031b5bf1cc92239461125f4c1ffb760522bbf2
    init version: N/A (expected: v0.13.0)
    Security Options:
     apparmor
     seccomp
      Profile: default
    Kernel Version: 4.4.0-31-generic
    Operating System: Ubuntu 16.04.1 LTS
    OSType: linux
    Architecture: x86_64
    CPUs: 2
    Total Memory: 1.937 GiB
    Name: ubuntu
    ID: H52R:7ZR6:EIIA:76JG:ORIY:BVKF:GSFU:HNPG:B5MK:APSC:SZ3Q:N326
    Docker Root Dir: /var/lib/docker
    Debug Mode (client): true
    Debug Mode (server): true
     File Descriptors: 30
     Goroutines: 123
     System Time: 2016-11-12T17:24:37.955404361-08:00
     EventsListeners: 0
    Http Proxy: http://test:test@proxy.example.com:8080
    Https Proxy: https://test:test@proxy.example.com:8080
    No Proxy: localhost,127.0.0.1,docker-registry.somecorporation.com
    Registry: https://index.docker.io/v1/
    WARNING: No swap limit support
    Labels:
     storage=ssd
     staging=true
    Experimental: false
    Insecure Registries:
     127.0.0.0/8
    Registry Mirrors:
      http://192.168.1.2/
      http://registry-mirror.example.com:5000/
    Live Restore Enabled: false

The global `-D` option tells all `docker` commands to output debug information.

The example below shows the output for a daemon running on Red Hat Enterprise Linux,
using the devicemapper storage driver. As can be seen in the output, additional
information about the devicemapper storage driver is shown:

    $ docker info
    Containers: 14
     Running: 3
     Paused: 1
     Stopped: 10
    Images: 52
    Server Version: 1.10.3
    Storage Driver: devicemapper
     Pool Name: docker-202:2-25583803-pool
     Pool Blocksize: 65.54 kB
     Base Device Size: 10.74 GB
     Backing Filesystem: xfs
     Data file: /dev/loop0
     Metadata file: /dev/loop1
     Data Space Used: 1.68 GB
     Data Space Total: 107.4 GB
     Data Space Available: 7.548 GB
     Metadata Space Used: 2.322 MB
     Metadata Space Total: 2.147 GB
     Metadata Space Available: 2.145 GB
     Udev Sync Supported: true
     Deferred Removal Enabled: false
     Deferred Deletion Enabled: false
     Deferred Deleted Device Count: 0
     Data loop file: /var/lib/docker/devicemapper/devicemapper/data
     Metadata loop file: /var/lib/docker/devicemapper/devicemapper/metadata
     Library Version: 1.02.107-RHEL7 (2015-12-01)
    Execution Driver: native-0.2
    Logging Driver: json-file
    Plugins:
     Volume: local
     Network: null host bridge
    Kernel Version: 3.10.0-327.el7.x86_64
    Operating System: Red Hat Enterprise Linux Server 7.2 (Maipo)
    OSType: linux
    Architecture: x86_64
    CPUs: 1
    Total Memory: 991.7 MiB
    Name: ip-172-30-0-91.ec2.internal
    ID: I54V:OLXT:HVMM:TPKO:JPHQ:CQCD:JNLC:O3BZ:4ZVJ:43XJ:PFHZ:6N2S
    Docker Root Dir: /var/lib/docker
    Debug mode (client): false
    Debug mode (server): false
    Username: gordontheturtle
    Registry: https://index.docker.io/v1/
    Insecure registries:
     myinsecurehost:5000
     127.0.0.0/8

You can also specify the output format:

    $ docker info --format '{{json .}}'
	{"ID":"I54V:OLXT:HVMM:TPKO:JPHQ:CQCD:JNLC:O3BZ:4ZVJ:43XJ:PFHZ:6N2S","Containers":14, ...}

Here is a sample output for a daemon running on Windows Server 2016:

    E:\docker>docker info
    Containers: 1
     Running: 0
     Paused: 0
     Stopped: 1
    Images: 17
    Server Version: 1.13.0
    Storage Driver: windowsfilter
     Windows:
    Logging Driver: json-file
    Plugins:
     Volume: local
     Network: nat null overlay
    Swarm: inactive
    Default Isolation: process
    Kernel Version: 10.0 14393 (14393.206.amd64fre.rs1_release.160912-1937)
    Operating System: Windows Server 2016 Datacenter
    OSType: windows
    Architecture: x86_64
    CPUs: 8
    Total Memory: 3.999 GiB
    Name: WIN-V0V70C0LU5P
    ID: NYMS:B5VK:UMSL:FVDZ:EWB5:FKVK:LPFL:FJMQ:H6FT:BZJ6:L2TD:XH62
    Docker Root Dir: C:\control
    Debug Mode (client): false
    Debug Mode (server): false
    Registry: https://index.docker.io/v1/
    Insecure Registries:
     127.0.0.0/8
    Registry Mirrors:
      http://192.168.1.2/
      http://registry-mirror.example.com:5000/
    Live Restore Enabled: false
