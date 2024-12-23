#!/bin/sh

curr_ver=0.6.7

# Copyright: antonk (antonk.d3v@gmail.com)
# github.com/friendly-bits

export conf_dir="/etc/geoip-shell" install_dir="/usr/bin" lib_dir="/usr/lib/geoip-shell" iplist_dir="/tmp/geoip-shell"
export lock_file="/tmp/geoip-shell.lock" excl_file="/etc/geoip-shell/iplist-exclusions.conf"
export p_name="geoip-shell" conf_file="/etc/geoip-shell/geoip-shell.conf" _lib="$lib_dir/geoip-shell-lib" i_script="$install_dir/geoip-shell" _nl='
'
export LC_ALL=C POSIXLY_CORRECT=YES default_IFS="	 $_nl"

[ "$root_ok" ] || { [ "$(id -u)" = 0 ] && export root_ok="1"; }
. "${_lib}-common.sh" || exit 1
export _OWRT_install=1
. "${_lib}-owrt.sh" || die
[ "$fwbe_ok" ] || [ ! "$root_ok" ] && return 0
[ -f "$conf_dir/${p_name}.const" ] && { . "$conf_dir/${p_name}.const" || die; } ||
	{ [ ! "$in_uninstall" ] && die "$conf_dir/${p_name}.const is missing. Please reinstall $p_name."; }

[ -s "$conf_file" ] && nodie=1 getconfig _fw_backend
if [ ! "$_fw_backend" ]; then
	rm -f "$conf_dir/setupdone"
	[ "$first_setup" ] && return 0
	case "$me $1" in "$p_name configure"|"${p_name}-manage.sh configure"|*" -h"*|*" -V"*) return 0; esac
	[ ! "$in_uninstall" ] && die "Config file $conf_file is missing or corrupted. Please run '$p_name configure'."
	_fw_backend="$(detect_fw_backend)"
elif ! check_fw_backend "$_fw_backend"; then
	_fw_be_rv=$?
	if [ "$in_uninstall" ]; then
		_fw_backend=
	else
		case $_fw_be_rv in
			1) die ;;
			2) die "Firewall backend '${_fw_backend}ables' not found." ;;
			3) die "Utility 'ipset' not found."
		esac
	fi
fi
export fwbe_ok=1 _fw_backend
:
