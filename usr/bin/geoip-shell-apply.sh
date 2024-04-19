#!/bin/sh

curr_ver=0.5.2

# Copyright: antonk (antonk.d3v@gmail.com)
# github.com/friendly-bits

p_name="geoip-shell"
. "/usr/bin/${p_name}-geoinit.sh" || exit 1

san_args "$@"
newifs "$delim"
set -- $_args; oldifs

usage() {
cat <<EOF

Usage: $me <action> [-l <"list_ids">] [-d] [-V] [-h]
Switches geoip blocking on/off, or loads/removes ip sets and firewall rules for specified lists.

Actions:
  on|off      : enable or disable the geoip blocking chain (via a rule in the base chain)
  add|remove  : Add or remove ip sets and firewall rules for lists specified with the '-l' option

Options:
  -l $list_ids_usage

  -d  : Debug
  -V  : Version
  -h  : This help

EOF
}

die_a() {
	destroy_tmp_ipsets
	set +f; rm "$iplist_dir/"*.iplist 2>/dev/null; set -f
	die "$@"
}

action="$1"
case "$action" in
	add|remove|on|off|update) shift ;;
	*) unknownact
esac

while getopts ":l:dVh" opt; do
	case $opt in
		l) list_ids=$OPTARG ;;
		d) ;;
		V) echo "$curr_ver"; exit 0 ;;
		h) usage; exit 0 ;;
		*) unknownopt
	esac
done
shift $((OPTIND-1))

extra_args "$@"

is_root_ok



get_config_vars



tolower action

geotag_aux="${geotag}_aux"

checkvars datadir geomode ifaces _fw_backend noblock

[ "$ifaces" != all ] && {
	all_ifaces="$(detect_ifaces)" || die "$FAIL detect network interfaces."
	nl2sp all_ifaces
	subtract_a_from_b "$all_ifaces" "$ifaces" bad_ifaces
	[ "$bad_ifaces" ] && die "Network interfaces '$bad_ifaces' do not exist in this system."
}


. "$_lib-$_fw_backend.sh" || exit 1

case "$geomode" in
	whitelist) iplist_verdict=accept; fw_target=ACCEPT ;;
	blacklist) iplist_verdict=drop; fw_target=DROP ;;
	*) die "Unknown firewall mode '$geomode'."
esac

case "$action" in
	on) geoip_on; exit ;;
	off) geoip_off; exit
esac

apply_rules
