# Solaris Application Container Configuration

Solaris application containers can be configured using the following properties, all of the below properties have mappings to properties specified under zonecfg(1M) man page, except milestone.

## milestone
The SMF(Service Management Facility) FMRI which should go to "online" state before we start the desired process within the container.

**`milestone`** *(string, OPTIONAL)*

### Example
```json
"milestone": "svc:/milestone/container:default"
```

## limitpriv
The maximum set of privileges any process in this container can obtain.
The property should consist of a comma-separated privilege set specification as described in priv_str_to_set(3C) man page for the respective release of Solaris.

**`limitpriv`** *(string, OPTIONAL)*

### Example
```json
"limitpriv": "default"
```

## maxShmMemory
The maximum amount of shared memory allowed for this application container.
A scale (K, M, G, T) can be applied to the value for each of these numbers (for example, 1M is one megabyte).
Mapped to max-shm-memory in zonecfg(1M) man page.

**`maxShmMemory`** *(string, OPTIONAL)*

### Example
```json
"maxShmMemory": "512m"
```

## cappedCPU
Sets a limit on the amount of CPU time that can be used by a container.
The unit used translates to the percentage of a single CPU that can be used by all user threads in a container, expressed as a fraction (for example, .75) or a mixed number (whole number and fraction, for example, 1.25).
An ncpu value of 1 means 100% of a CPU, a value of 1.25 means 125%, .75 mean 75%, and so forth.
When projects within a capped container have their own caps, the minimum value takes precedence.
cappedCPU is mapped to capped-cpu in zonecfg(1M) man page.

* **`ncpus`** *(string, OPTIONAL)*

### Example
```json
"cappedCPU": {
        "ncpus": "8"
}
```

## cappedMemory
The physical and swap caps on the memory that can be used by this application container.
A scale (K, M, G, T) can be applied to the value for each of these numbers (for example, 1M is one megabyte).
cappedMemory is mapped to capped-memory in zonecfg(1M) man page.

* **`physical`** *(string, OPTIONAL)*
* **`swap`** *(string, OPTIONAL)*

### Example
```json
"cappedMemory": {
        "physical": "512m",
        "swap": "512m"
}
```

## Network

### Automatic Network (anet)
anet is specified as an array that is used to setup networking for Solaris application containers.
The anet resource represents the automatic creation of a network resource for an application container.
The zones administration daemon, zoneadmd, is the primary process for managing the container's virtual platform.
One of the daemons is responsibilities is creation and teardown of the networks for the container.
For more information on the daemon check the zoneadmd(1M) man page.
When such a container is started, a temporary VNIC(Virtual NIC) is automatically created for the container.
The VNIC is deleted when the container is torn down.
The following properties can be used to setup automatic networks.
For additional information on properties check zonecfg(1M) man page for the respective release of Solaris.

* **`linkname`** *(string, OPTIONAL)* Specify a name for the automatically created VNIC datalink.
* **`lowerLink`** *(string, OPTIONAL)* Specify the link over which the VNIC will be created.
Mapped to lower-link in the zonecfg(1M) man page.
* **`allowedAddress`** *(string, OPTIONAL)* The set of IP addresses that the container can use might be constrained by specifying the allowedAddress property.
If allowedAddress has not been specified, then they can use any IP address on the associated physical interface for the network resource.
Otherwise, when allowedAddress is specified, the container cannot use IP addresses that are not in the allowedAddress list for the physical address.
Mapped to allowed-address in the zonecfg(1M) man page.
* **`configureAllowedAddress`** *(string, OPTIONAL)* If configureAllowedAddress is set to true, the addresses specified by allowedAddress are automatically configured on the interface each time the container starts.
When it is set to false, the allowedAddress will not be configured on container start.
Mapped to configure-allowed-address in the zonecfg(1M) man page.
* **`defrouter`** *(string, OPTIONAL)* The value for the OPTIONAL default router.
* **`macAddress`** *(string, OPTIONAL)* Set the VNIC's MAC addresses based on the specified value or keyword.
If not a keyword, it is interpreted as a unicast MAC address.
For a list of the supported keywords please refer to the zonecfg(1M) man page of the respective Solaris release.
Mapped to mac-address in the zonecfg(1M) man page.
* **`linkProtection`** *(string, OPTIONAL)* Enables one or more types of link protection using comma-separated values.
See the protection property in dladm(8) for supported values in respective release of Solaris.
Mapped to link-protection in the zonecfg(1M) man page.

#### Example
```json
"anet": [
    {
        "allowedAddress": "172.17.0.2/16",
        "configureAllowedAddress": "true",
        "defrouter": "172.17.0.1/16",
        "linkProtection": "mac-nospoof, ip-nospoof",
        "linkname": "net0",
        "lowerLink": "net2",
        "macAddress": "02:42:f8:52:c7:16"
    }
]
```
