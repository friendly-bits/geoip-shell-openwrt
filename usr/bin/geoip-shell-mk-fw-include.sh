#!/bin/sh
p_name=geoip-shell
install_dir="/usr/bin"
conf_dir="/etc/geoip-shell"
fw_include_path="/usr/bin/geoip-shell-fw-include.sh"
_lib="/usr/lib/geoip-shell/geoip-shell-lib"
me="${0##*/}"
. "${_lib}-owrt.sh" || exit 1

die() {
	logger -s -t "$me" -p user.err "$1"
	exit 1
}

mk_fw_include() {
	[ "$p_name_c" ] && [ "$_OWRTFW" ] && [ "$fw_include_path" ] || die "Error: essential variables are unset."
	check_owrt_include && return 0
	logger -s -t "$me" -p user.info "Creating the firewall include for $p_name."
	rel=
	[ "$_OWRTFW" = 3 ] && rel=".reload=1"
	uci delete "firewall.$p_name_c" 2>/dev/null
	errors="$(
		for o in "=include" ".enabled=1" ".type=script" ".path=$fw_include_path" "$rel"; do
			[ "$o" ] && printf '%s\n' "set firewall.$p_name_c$o"
		done | uci batch 2>&1 && uci commit firewall 2>&1
	)"
	[ "$errors" ] || ! check_owrt_include && {
		uci revert firewall."$p_name_c" 2>/dev/null
		die "Failed to add firewall include. Errors: '$(printf %s "$errors" | tr '\n' ' ')'."
	}
	reload_config
}

[ ! -f "$conf_dir/setupdone" ] &&
	die "$p_name has not been configured. Please run '$p_name configure'."

if [ -f "$conf_dir/no_persist" ]; then
	$init_script enabled 2>/dev/null && {
		logger -s -t "$me" -p user.warn "no_persist file exists. Disabling the init script."
		$init_script disable
	}
	check_owrt_include && { rm_owrt_fw_include; reload_owrt_fw; }
	exit 1
fi

mk_fw_include
