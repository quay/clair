#!/usr/bin/env bash
set -e

# bits of this were adapted from lxc-checkconfig
# see also https://github.com/lxc/lxc/blob/lxc-1.0.2/src/lxc/lxc-checkconfig.in

possibleConfigs=(
	'/proc/config.gz'
	"/boot/config-$(uname -r)"
	"/usr/src/linux-$(uname -r)/.config"
	'/usr/src/linux/.config'
)

if [ $# -gt 0 ]; then
	CONFIG="$1"
else
	: ${CONFIG:="${possibleConfigs[0]}"}
fi

if ! command -v zgrep &> /dev/null; then
	zgrep() {
		zcat "$2" | grep "$1"
	}
fi

kernelVersion="$(uname -r)"
kernelMajor="${kernelVersion%%.*}"
kernelMinor="${kernelVersion#$kernelMajor.}"
kernelMinor="${kernelMinor%%.*}"

is_set() {
	zgrep "CONFIG_$1=[y|m]" "$CONFIG" > /dev/null
}
is_set_in_kernel() {
	zgrep "CONFIG_$1=y" "$CONFIG" > /dev/null
}
is_set_as_module() {
	zgrep "CONFIG_$1=m" "$CONFIG" > /dev/null
}

color() {
	local codes=()
	if [ "$1" = 'bold' ]; then
		codes=( "${codes[@]}" '1' )
		shift
	fi
	if [ "$#" -gt 0 ]; then
		local code=
		case "$1" in
			# see https://en.wikipedia.org/wiki/ANSI_escape_code#Colors
			black) code=30 ;;
			red) code=31 ;;
			green) code=32 ;;
			yellow) code=33 ;;
			blue) code=34 ;;
			magenta) code=35 ;;
			cyan) code=36 ;;
			white) code=37 ;;
		esac
		if [ "$code" ]; then
			codes=( "${codes[@]}" "$code" )
		fi
	fi
	local IFS=';'
	echo -en '\033['"${codes[*]}"'m'
}
wrap_color() {
	text="$1"
	shift
	color "$@"
	echo -n "$text"
	color reset
	echo
}

wrap_good() {
	echo "$(wrap_color "$1" white): $(wrap_color "$2" green)"
}
wrap_bad() {
	echo "$(wrap_color "$1" bold): $(wrap_color "$2" bold red)"
}
wrap_warning() {
	wrap_color >&2 "$*" red
}

check_flag() {
	if is_set_in_kernel "$1"; then
		wrap_good "CONFIG_$1" 'enabled'
	elif is_set_as_module "$1"; then
		wrap_good "CONFIG_$1" 'enabled (as module)'
	else
		wrap_bad "CONFIG_$1" 'missing'
	fi
}

check_flags() {
	for flag in "$@"; do
		echo "- $(check_flag "$flag")"
	done
}

check_command() {
	if command -v "$1" >/dev/null 2>&1; then
		wrap_good "$1 command" 'available'
	else
		wrap_bad "$1 command" 'missing'
	fi
}

check_device() {
	if [ -c "$1" ]; then
		wrap_good "$1" 'present'
	else
		wrap_bad "$1" 'missing'
	fi
}

check_distro_userns() {
	source /etc/os-release 2>/dev/null || /bin/true
	if [[ "${ID}" =~ ^(centos|rhel)$ && "${VERSION_ID}" =~ ^7 ]]; then
		# this is a CentOS7 or RHEL7 system
		grep -q "user_namespace.enable=1" /proc/cmdline || {
			# no user namespace support enabled
			wrap_bad "  (RHEL7/CentOS7" "User namespaces disabled; add 'user_namespace.enable=1' to boot command line)"
		}
	fi
}

if [ ! -e "$CONFIG" ]; then
	wrap_warning "warning: $CONFIG does not exist, searching other paths for kernel config ..."
	for tryConfig in "${possibleConfigs[@]}"; do
		if [ -e "$tryConfig" ]; then
			CONFIG="$tryConfig"
			break
		fi
	done
	if [ ! -e "$CONFIG" ]; then
		wrap_warning "error: cannot find kernel config"
		wrap_warning "  try running this script again, specifying the kernel config:"
		wrap_warning "    CONFIG=/path/to/kernel/.config $0 or $0 /path/to/kernel/.config"
		exit 1
	fi
fi

wrap_color "info: reading kernel config from $CONFIG ..." white
echo

echo 'Generally Necessary:'

echo -n '- '
cgroupSubsystemDir="$(awk '/[, ](cpu|cpuacct|cpuset|devices|freezer|memory)[, ]/ && $3 == "cgroup" { print $2 }' /proc/mounts | head -n1)"
cgroupDir="$(dirname "$cgroupSubsystemDir")"
if [ -d "$cgroupDir/cpu" -o -d "$cgroupDir/cpuacct" -o -d "$cgroupDir/cpuset" -o -d "$cgroupDir/devices" -o -d "$cgroupDir/freezer" -o -d "$cgroupDir/memory" ]; then
	echo "$(wrap_good 'cgroup hierarchy' 'properly mounted') [$cgroupDir]"
else
	if [ "$cgroupSubsystemDir" ]; then
		echo "$(wrap_bad 'cgroup hierarchy' 'single mountpoint!') [$cgroupSubsystemDir]"
	else
		echo "$(wrap_bad 'cgroup hierarchy' 'nonexistent??')"
	fi
	echo "    $(wrap_color '(see https://github.com/tianon/cgroupfs-mount)' yellow)"
fi

if [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = 'Y' ]; then
	echo -n '- '
	if command -v apparmor_parser &> /dev/null; then
		echo "$(wrap_good 'apparmor' 'enabled and tools installed')"
	else
		echo "$(wrap_bad 'apparmor' 'enabled, but apparmor_parser missing')"
		echo -n '    '
		if command -v apt-get &> /dev/null; then
			echo "$(wrap_color '(use "apt-get install apparmor" to fix this)')"
		elif command -v yum &> /dev/null; then
			echo "$(wrap_color '(your best bet is "yum install apparmor-parser")')"
		else
			echo "$(wrap_color '(look for an "apparmor" package for your distribution)')"
		fi
	fi
fi

flags=(
	NAMESPACES {NET,PID,IPC,UTS}_NS
	DEVPTS_MULTIPLE_INSTANCES
	CGROUPS CGROUP_CPUACCT CGROUP_DEVICE CGROUP_FREEZER CGROUP_SCHED CPUSETS MEMCG
	KEYS
	MACVLAN VETH BRIDGE BRIDGE_NETFILTER
	NF_NAT_IPV4 IP_NF_FILTER IP_NF_TARGET_MASQUERADE
	NETFILTER_XT_MATCH_{ADDRTYPE,CONNTRACK}
	NF_NAT NF_NAT_NEEDED

	# required for bind-mounting /dev/mqueue into containers
	POSIX_MQUEUE
)
check_flags "${flags[@]}"
echo

echo 'Optional Features:'
{
	check_flags USER_NS
	check_distro_userns
}
{
	check_flags SECCOMP
}
{
	check_flags MEMCG_KMEM MEMCG_SWAP MEMCG_SWAP_ENABLED
	if  is_set MEMCG_SWAP && ! is_set MEMCG_SWAP_ENABLED; then
		echo "    $(wrap_color '(note that cgroup swap accounting is not enabled in your kernel config, you can enable it by setting boot option "swapaccount=1")' bold black)"
	fi
}

if [ "$kernelMajor" -lt 3 ] || [ "$kernelMajor" -eq 3 -a "$kernelMinor" -le 18 ]; then
	check_flags RESOURCE_COUNTERS
fi

if [ "$kernelMajor" -lt 3 ] || [ "$kernelMajor" -eq 3 -a "$kernelMinor" -le 13 ]; then
	netprio=NETPRIO_CGROUP
else
	netprio=CGROUP_NET_PRIO
fi

flags=(
	BLK_CGROUP IOSCHED_CFQ BLK_DEV_THROTTLING
	CGROUP_PERF
	CGROUP_HUGETLB
	NET_CLS_CGROUP $netprio
	CFS_BANDWIDTH FAIR_GROUP_SCHED RT_GROUP_SCHED
)
check_flags "${flags[@]}"

check_flags EXT3_FS EXT3_FS_XATTR EXT3_FS_POSIX_ACL EXT3_FS_SECURITY
if ! is_set EXT3_FS || ! is_set EXT3_FS_XATTR || ! is_set EXT3_FS_POSIX_ACL || ! is_set EXT3_FS_SECURITY; then
	echo "    $(wrap_color '(enable these ext3 configs if you are using ext3 as backing filesystem)' bold black)"
fi

check_flags EXT4_FS EXT4_FS_POSIX_ACL EXT4_FS_SECURITY
if ! is_set EXT4_FS || ! is_set EXT4_FS_POSIX_ACL || ! is_set EXT4_FS_SECURITY; then
	echo "    $(wrap_color 'enable these ext4 configs if you are using ext4 as backing filesystem' bold black)"
fi

echo '- Storage Drivers:'
{
	echo '- "'$(wrap_color 'aufs' blue)'":'
	check_flags AUFS_FS | sed 's/^/  /'
	if ! is_set AUFS_FS && grep -q aufs /proc/filesystems; then
		echo "    $(wrap_color '(note that some kernels include AUFS patches but not the AUFS_FS flag)' bold black)"
	fi

	echo '- "'$(wrap_color 'btrfs' blue)'":'
	check_flags BTRFS_FS | sed 's/^/  /'

	echo '- "'$(wrap_color 'devicemapper' blue)'":'
	check_flags BLK_DEV_DM DM_THIN_PROVISIONING | sed 's/^/  /'

	echo '- "'$(wrap_color 'overlay' blue)'":'
	check_flags OVERLAY_FS | sed 's/^/  /'

	echo '- "'$(wrap_color 'zfs' blue)'":'
	echo "  - $(check_device /dev/zfs)"
	echo "  - $(check_command zfs)"
	echo "  - $(check_command zpool)"
} | sed 's/^/  /'
echo

