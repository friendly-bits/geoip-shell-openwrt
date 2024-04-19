#!/bin/sh

curr_ver=0.5.2

# Copyright: antonk (antonk.d3v@gmail.com)
# github.com/friendly-bits

kill_geo_pids() {
	i_kgp=0 _parent="$(grep -o "${p_name}[^[:space:]]*" "/proc/$PPID/comm")"
	while true; do
		i_kgp=$((i_kgp+1)); _killed=
		_geo_ps="$(pgrep -fa "(${p_name}\-|$ripe_url_stats|$ripe_url_api|$ipdeny_ipv4_url|$ipdeny_ipv6_url)" | grep -v pgrep)"
		newifs "$_nl" kgp
		for _p in $_geo_ps; do
			_pid="${_p% *}"
			_p="$p_name${_p##*"$p_name"}"
			_p="${_p%% *}"
			case "$_pid" in "$$"|"$PPID"|*[!0-9]*) continue; esac
			[ "$_p" = "$_parent" ] && continue
			IFS=' '
			for g in run fetch apply cronsetup backup detect-lan; do
				case "$_p" in *${p_name}-$g*)
					kill "$_pid" 2>/dev/null
					_killed=1
				esac
			done
		done
		oldifs kgp
		[ ! "$_killed" ] || [ $i_kgp -gt 10 ] && break
	done
	unisleep
}

rm_iplists_rules() {
	echo "Removing $p_name ip lists and firewall rules..."

	kill_geo_pids

	rm_lock

	[ "$_fw_backend" ] && rm_all_georules || return 1

	set +f
	[ "$iplist_dir" ] && rm -f "${iplist_dir:?}"/*.iplist 2>/dev/null
	set -f
	:
}

rm_cron_jobs() {
	echo "Removing cron jobs..."
	crontab -u root -l 2>/dev/null | grep -v "${p_name}-run.sh" | crontab -u root -
	:
}

rm_geodir() {
	[ "$1" ] && [ -d "$1" ] && {
		printf '%s\n' "Deleting the $2 directory '$1'..."
		rm -rf "$1"
	}
}

rm_data() {
	rm_geodir "$datadir" data
	:
}

rm_symlink() {
	rm -f "${install_dir}/${p_name}" 2>/dev/null
}

rm_config() {
	rm_geodir "$conf_dir" config
	:
}

[ ! "$_fw_backend" ] && [ "$root_ok" ] && {
	if [ "$_OWRTFW" ]; then
		[ "$_OWRTFW" = 4 ] && _fw_backend=nft || _fw_backend=ipt
	elif [ -f "$_lib-check-compat.sh" ]; then
		. "$_lib-check-compat.sh"
		if check_fw_backend nft; then
			_fw_backend=nft
		elif check_fw_backend ipt; then
			_fw_backend=ipt
		fi
	fi 2>/dev/null
}

:
