#!/bin/sh

curr_ver=0.6.8

# Copyright: antonk (antonk.d3v@gmail.com)
# github.com/friendly-bits

p_name="geoip-shell"
export inbound_geomode nolog=1 manmode=1

. "/usr/bin/${p_name}-geoinit.sh" &&
script_dir="$install_dir" &&
. "$_lib-setup.sh" &&
. "$_lib-uninstall.sh" || exit 1

san_args "$@"
newifs "$delim"
set -- $_args; oldifs

ccodes_syn="<\"country_codes\">"
fam_syn="<ipv4|ipv6|\"ipv4 ipv6\">"
mode_syn="<whitelist|blacklist|disable>"
ifaces_syn="<\"[ifaces]\"|auto|all>"
lan_syn="<\"[lan_ips]\"|auto|none>"
tr_syn="<\"[trusted_ips]\"|none>"
ports_syn="<[tcp|udp]:[allow|block]:[all|<ports>]>"
sch_syn="<\"[expression]\"|disable>"
user_ccode_syn="<[user_country_code]|none>"
fw_be_syn="<ipt|nft>"
datadir_syn="<\"path\">"
noblock_syn="<true|false>"
nobackup_syn="<true|false>"
nft_p_syn="<memory|performance>"
force_cr_syn="<true|false>"
no_persist_syn="<true|false>"

usage() {

cat <<EOF

Usage: ${blue}$me <action> [options]${n_c}

Provides interface to configure geoblocking.

${purple}Actions${n_c}:
  ${blue}configure${n_c}  :  change $p_name config
  ${blue}status${n_c}     :  check on the current status of geoblocking
  ${blue}reset${n_c}      :  reset geoip config and firewall geoip rules
  ${blue}restore${n_c}    :  re-apply geoblocking rules from the config
  ${blue}showconfig${n_c} :  print the contents of the config file
  ${blue}on|off${n_c}     :  enable or disable the geoblocking chain (via a rule in the base geoip chain)
  ${blue}stop${n_c}       :  kill any running geoip-shell processes, remove geoip-shell firewall rules and unload ip sets

${purple}'configure' action${n_c}:
  General syntax: ${blue}configure [options] [-D $direction_syn <options>]${n_c}
  Example: '$p_name configure inbound <options>' configures inbound traffic geoblocking.

  To configure separately inbound and outbound geoblocking in one command, use the direction keyword twice. Example:
    '$p_name configure -D inbound <options> -D outbound <options>'
  If direction (inbound|outbound) is not specified, defaults to configuring inboud traffic geoblocking. Example:
    '$p_name configure <options>'

${purple}Options for 'configure -D $direction_syn'${n_c}
  (affects geoblocking in the specified direction, or inbound if direction not specified):

  ${blue}-m $mode_syn${n_c} : Geoblocking mode: whitelist, blacklist or disable.
${sp8}'disable' removes all previous config options for specified direction and disables geoblocking for it.

  ${blue}-c $ccodes_syn${n_c} : 2-letter country codes to include in whitelist/blacklist.
${sp8}If passing multiple country codes, use double quotes.

  ${blue}-p $ports_syn${n_c} :
${sp8}For given protocol (tcp/udp), use 'block' to geoblock traffic on specific ports or on all ports.
${sp8}or use 'allow' to geoblock all traffic except on specific ports.
${sp8}To specify ports for both tcp and udp in one command, use the '-p' option twice.

${purple}General options for the 'configure' action${n_c} (affects geoblocking in both directions):

  ${blue}-f ${fam_syn}${n_c} : Ip families (defaults to 'ipv4 ipv6'). Use double quotes for multiple families.

  ${blue}-u $srcs_syn${n_c} : Use this ip list source for download. Supported sources: ripe, ipdeny, maxmind.

  ${blue}-i $ifaces_syn${n_c} :
${sp8}Changes which network interface(s) geoblocking firewall rules will be applied to.
${sp8}'all' will apply geoblocking to all network interfaces.
${sp8}'auto' will automatically detect WAN interfaces (this may cause problems if the machine has no direct WAN connection).
${sp8}Generally, if the machine has dedicated WAN interfaces, specify them, otherwise pick 'all'.

  ${blue}-l $lan_syn${n_c} :
${sp8}Specifies LAN ip's or subnets to exclude from geoblocking (both ipv4 and ipv6).
${sp8}Only compatible with whitelist mode.
${sp8}Generally, in whitelist mode, if the machine has no dedicated WAN interfaces,
${sp8}specify LAN ip's or subnets to avoid blocking them. Otherwise you probably don't need this.
${sp8}'auto' will automatically detect LAN subnets during the initial setup and at every update of the ip lists.
${sp8}'none' removes previously set LAN ip's and disables the automatic detection.
${sp8}*Don't use 'auto' if the machine has a dedicated WAN interface*

  ${blue}-t $tr_syn${n_c} :
${sp8}Specifies trusted ip's or subnets to exclude from geoblocking (both ipv4 and ipv6).
${sp8}This option is independent from the above LAN ip's option.
${sp8}Works both in whitelist and blacklist mode.
${sp8}'none' removes previously set trusted ip's

  ${blue}-U <auto|pause|none|"[ip_addresses]">${n_c} :
${sp8}Policy for allowing automatic ip list updates when outbound geoblocking is enabled.
${sp8}Use 'auto' to detect ip addresses automatically once and always allow outbound connection to detected addresses.
${sp8}Or use 'pause' to always temporarily pause outbound geoblocking before fetching ip list updates.
${sp8}Or specify ip addresses for ip lists source (ripe, ipdeny or maxmind) to allow - for multiple addresses, use double quotes.
${sp8}Or use 'none' to remove previously assigned server ip addresses and disable this feature.

  ${blue}-r $user_ccode_syn${n_c} :
${sp8}Specify user's country code. Used to prevent accidental lockout of a remote machine.
${sp8}'none' disables this feature.

  ${blue}-o $nobackup_syn${n_c} :
${sp8}No backup. If set to 'true', $p_name will not create a backup of ip lists and firewall rules state after applying changes,
${sp8}and will automatically re-fetch ip lists after each reboot.
${sp8}Default is 'true' for OpenWrt, 'false' for all other systems.

  ${blue}-a $datadir_syn${n_c} :
${sp8}Set custom path to directory where backups and the status file will be stored.
${sp8}Default is '/tmp/geoip-shell-data' for OpenWrt, '/var/lib/$p_name' for all other systems.

  ${blue}-s $sch_syn${n_c} :
${sp8}Schedule expression for the periodic cron job implementing automatic update of the ip lists, must be inside double quotes.
${sp8}Example expression: "15 4 * * *" (at 4:15 [am] every day)
${sp8}'disable' will disable automatic updates of the ip lists.

  ${blue}-w $fw_be_syn${n_c} :
${sp8}Specify firewall backend to use with $p_name. 'ipt' for iptables, 'nft' for nftables.
${sp8}Default is nftables if present in the system.

  ${blue}-O $nft_p_syn${n_c} :
${sp8}Optimization policy for nftables sets.
${sp8}By default optimizes for memory if the machine has less than 2GiB of RAM, otherwise for performance.
${sp8}Doesn't work with iptables.

  ${blue}-N $noblock_syn${n_c} :
${sp8}No Block: Skip creating the rule which redirects traffic to the geoblocking chain.
${sp8}Everything will be installed and configured but geoblocking will not be enabled. Default is false.

  ${blue}-n $no_persist_syn${n_c} :
${sp8}No Persistence: Skip creating the persistence cron job or init script.
${sp8}$p_name will likely not work after reboot. Default is false.

  ${blue}-P $force_cr_syn${n_c} : Force cron-based persistence even when the system may not support it. Default is false.

${purple}Other options${n_c}:

  -v : Verbose status output
  -z : $nointeract_usage Will fail if required options are not specified or invalid.
  -d : Debug
  -V : Version
  -h : This help

EOF
}

set_opt() {
	var_name="$1"
	[ "$opt" != p ] && {
		eval "oldval=\"\$${1}\""
		[ -n "$oldval" ] && {
			fordirection=
			case "$opt" in m|c) fordirection=" for direction '$direction'"; esac
			die "Option '-$opt' can not be used twice${fordirection}."
		}
	}
	case "$opt" in
		m|c|p) set_directional_opt "$var_name" ;;
		*) eval "$var_name"='$OPTARG'; return 0
	esac
}

set_directional_opt() {
	[ ! "$1" ] && die "set_direction_opt: arg is unset"
	d_var_name="$1"
	[ "$action" != configure ] && { usage; die "Option '-$opt' must be used with the 'configure' action."; }
	case "$direction" in
		inbound|outbound)
			case "$opt" in
				m|c) eval "${direction}_${d_var_name}"='$OPTARG' ;;
				p) eval "${direction}_ports_arg=\"\${${direction}_ports_arg}$OPTARG$_nl\""
			esac ;;
		*) die "Internal error: unexpected direction '$direction'."
	esac
	req_direc_opt=
}

tolower action "$1"
case "$action" in
	configure) direction=inbound; shift ;;
	status|restore|reset|on|off|stop|showconfig) shift ;;
	*) action="$1"; unknownact
esac

req_direc_opt=
while getopts ":D:m:c:f:s:i:l:t:p:r:u:U:a:o:w:O:n:N:P:zvdVh" opt; do
	case $opt in
		D) tolower OPTARG
			case "$OPTARG" in inbound|outbound) ;; *)
				usage; die "Invalid geoblocking direction '$OPTARG'. Use '-D inbound' or '-D outbound'."
			esac
			[ "$action" != configure ] && { usage; die "Action is '$action', but specifying geoblocking direction is only valid for action 'configure'."; }
			[ "$req_direc_opt" ] && { usage; die "Provide valid options for the '$direction' direction."; }
			direction="$OPTARG"
			req_direc_opt=1 ;;
		m) set_opt geomode_arg ;;
		c) set_opt ccodes_arg ;;
		p) set_opt ports_arg ;;

		f) set_opt families_arg ;;
		s) set_opt schedule_arg ;;
		i) set_opt ifaces_arg ;;
		l) set_opt lan_ips_arg ;;
		t) set_opt trusted_arg ;;
		r) set_opt user_ccode_arg ;;
		u) set_opt geosource_arg ;;
		U) set_opt source_ips_arg ;;
		a) set_opt datadir_arg ;;
		w) set_opt _fw_backend_arg ;;
		O) set_opt nft_perf_arg ;;

		o) set_opt nobackup_arg ;;
		n) set_opt no_persist_arg ;;
		N) set_opt noblock_arg ;;
		P) set_opt force_cron_persist_arg ;;

		z) nointeract_arg=1 ;;
		v) verb_status="-v" ;;
		d) ;;
		V) echo "$curr_ver"; exit 0 ;;
		h) usage; exit 0 ;;
		*) unknownopt
	esac
done
shift $((OPTIND-1))

[ "$req_direc_opt" ] && { usage; die "Provide valid options for direction '$direction'."; }




extra_args "$@"

is_root_ok

restore_from_config() {
	restore_msg="Restoring $p_name from ${_prev}config... "
	restore_ok_msg="Successfully restored $p_name from ${_prev}config."
	[ "$conf_act" = reset ] && {
		restore_msg="Applying ${_prev}config... "
		restore_ok_msg="Successfully applied ${_prev}config."
	}
	printf '\n%s\n' "$restore_msg"

	rm_iplists_rules || return 1
	rm -f "$status_file"

	run_args=
	for d in inbound outbound; do
		eval "[ -n \"\${${d}_iplists}\" ] && run_args=\"\${run_args}\${${d}_iplists} \""
	done

	if [ -n "$run_args" ]; then
		eval "call_script -l \"$run_command\" add -l \"$run_args\" -o" && {
			printf '%s\n' "$restore_ok_msg"
			return 0
		}
	else
		echo "No ip lists registered - skipping firewall rules creation."
		return 0
	fi

	[ "$first_setup" ] && die

	[ ! "$prev_config_try" ] && [ "$prev_config" ] && {
		prev_config_try=1
		export main_config="$prev_config"

		{ nodie=1 export_conf=1 get_config_vars || { echolog -err "$FAIL load the previous config."; false; }; } &&
		_prev="previous " &&
		{
			[ ! "$_fw_backend_change" ] ||
			{
				[ "$_fw_backend" ] && . "${_lib}-${_fw_backend}.sh" ||
					{ echolog -err "$FAIL load the '$_fw_backend' library."; false; }
			}
		} &&
		restore_from_config && { set_all_config; return 0; }
	}

	[ -f "$datadir/backup/$p_name.conf.bak" ] && call_script -l "$i_script-backup.sh" restore && {
		unset main_config
		get_config_vars
		check_lists_coherence && return 0
	}

	die "$FAIL restore $p_name state. If it's a bug then please report it."
}

check_for_lockout() {
	[ "$user_ccode" = none ] && return 0

	u_ccode="${_nl}Your country code '$user_ccode'"
	lockout_exp=

	for direction in inbound outbound; do
		eval "iplists=\"\$${direction}_iplists\"
			geomode=\"\$${direction}_geomode\"
			geomode_change=\"\$${direction}_geomode_change\"
			lists_change=\"\$${direction}_lists_change\""
		if [ "$first_setup" ] || [ "$geomode_change" ] || [ "$lists_change" ] || [ "$user_ccode_change" ]; then
			ccode_included=
			inlist="in the planned $direction geoblocking $geomode"

			for family in $families; do
				is_included "${user_ccode}_${family}" "$iplists" && ccode_included=1
			done
			case "$geomode" in
				whitelist) [ ! "$ccode_included" ] && { lockout_exp=1; echolog -warn "$u_ccode is not included $inlist."; } ;;
				blacklist) [ "$ccode_included" ] && { lockout_exp=1; echolog -warn "$u_ccode is included $inlist."; }
			esac
		fi
	done

	[ ! "$lockout_exp" ] || [ "$nointeract" ] && return 0

	printf '\n%s\n%s\n' "Make sure you do not lock yourself out." "Proceed?"
	pick_opt "y|n"
	case "$REPLY" in
		y) printf '\n%s\n' "Proceeding..." ;;
		n)
			inbound_geomode="$inbound_geomode_prev"
			outbound_geomode="$outbound_geomode_prev"
			inbound_iplists="$inbound_iplists_prev"
			outbound_iplists="$outbound_iplists_prev"
			[ ! "$first_setup" ] && report_lists
			echo
			echolog "Aborted action '$action'."
			die 130
	esac
	:
}

set_first_setup() {
	[ "$action" != configure ] && echolog "Changing action to 'configure'."
	rm_setupdone
	export first_setup=1
	action=configure reset_req=1
}

[ "$action" = showconfig ] && { printf '\n%s\n\n' "Config in $conf_file:"; cat "$conf_file"; die 0; }

unset conf_act rm_conf

[ "$action" != stop ] && { [ "$first_setup" ] || [ ! -f "$conf_dir/setupdone" ]; } && {
	export first_setup=1
	[ "$action" != configure ] && {
		echolog "${_nl}Setup has not been completed."
		set_first_setup
	}

	[ ! "$nointeract_arg" ] && [ -s "$conf_file" ] && {
		q="[K]eep previous"
		keep_opt=k
		for _par in inbound_geomode outbound_geomode inbound_ccodes outbound_ccodes inbound_ports outbound_ports \
			families ifaces lan_ips trusted user_ccode geosource datadir nobackup \
			_fw_backend nft_perf schedule no_persist noblock force_cron_persist; do
			eval "arg_val=\"\$${_par}_arg\""
			[ "$arg_val" ] && {
				nodie=1 getconfig prev_val "$_par" "$conf_file" 2>/dev/null
				[ "$arg_val" != "$prev_val" ] && { q="[M]erge previous and new"; keep_opt=m; break; }
			}
		done

		printf '\n%s\n' "Existing config file found. $q config or [f]orget the old config? [$keep_opt|f] or [a] to abort setup."
		pick_opt "$keep_opt|f|a"
		case "$REPLY" in
			a) die 130 ;;
			f) rm_conf=1
		esac
	}
}

[ -s "$conf_file" ] && [ ! "$rm_conf" ] && {
	tmp_conf_file="/tmp/${p_name}_upd.conf"
	main_conf_path="$conf_file"

	[ "$first_setup" ] && {
		sed 's/^tcp_ports=/inbound_tcp_ports=/;s/^udp_ports=/inbound_udp_ports=/;s/^geomode=/inbound_geomode=/;
				s/^iplists=/inbound_iplists=/' "$conf_file" > "$tmp_conf_file" && conf_file="$tmp_conf_file" ||
					{ FAIL; rm_conf=1; }
	}

	nodie=1 export_conf=1 get_config_vars || rm_conf=1
	conf_file="$main_conf_path"
	rm -f "$tmp_conf_file"
}

[ ! -s "$conf_file" ] || [ "$rm_conf" ] && {
	rm -f "$conf_file"
	rm_data
	unset datadir
	rm_setupdone
	export first_setup=1
}

[ "$_fw_backend" ] && { . "$_lib-$_fw_backend.sh" || die; } || {
	[ "$action" != configure ] && echolog "Firewall backend is not set."
	set_first_setup
}

[ -z "$inbound_geomode$outbound_geomode" ] && {
	[ "$action" != configure ] && echolog "${_nl}Geoblocking mode is not set for both inbound and outbound connections."
	set_first_setup
}

for direction in inbound outbound; do
	eval "dir_geomode=\"\$${direction}_geomode\""
	case "$dir_geomode" in
		whitelist|blacklist|disable) ;;
		*)
			case "$dir_geomode" in
				'') [ "$action" != configure ] && echolog "Geoblocking mode for direction '$direction' is not set." ;;
				*) echolog -err "Unexpected $direction geoblocking mode '$dir_geomode'."
			esac
			unset "${direction}_geomode"
			set_first_setup ;;
	esac
done

for dir in inbound outbound; do
	san_str "${dir}_ccodes_arg" || die
	toupper "${dir}_ccodes_arg"
done

run_command="$i_script-run.sh"

[ -f "$excl_file" ] && nodie=1 getconfig exclude_iplists exclude_iplists "$excl_file"

erract="action '$action'"
incompat="$erract is incompatible with option"

case "$action" in
	status|restore|reset|on|off|stop) [ "$inbound_ccodes_arg$outbound_ccodes_arg" ] && die "$incompat '-c'."
esac

[ "$action" != configure ] && {
	for i_opt in "inbound_ccodes c" "outbound_ccodes c" "inbound_geomode m" "outbound_geomode m" \
			"inbound_ports p" "outbound_ports p" "trusted t" "lan_ips l" "ifaces i" \
			"geosource u" "source_ips U" "datadir a" "nobackup o" "schedule s" \
			"families f" "user_ccode r" "nft_perf O" "nointeract z"; do
		eval "[ -n \"\$${i_opt% *}_arg\" ]" && die "$incompat '-${i_opt#* }'."
	done
}

[ "$action" = status ] && { . "$_lib-status.sh"; die $?; }

[ "$action" != stop ] && mk_lock
trap 'die' INT TERM HUP QUIT

case "$action" in
	on|off|stop)
		case "$action" in
			on) [ ! "$inbound_iplists$outbound_iplists" ] && die "No ip lists registered. Refusing to enable geoblocking."
				setconfig "noblock=false" ;;
			off) setconfig "noblock=true" ;;
			stop)
				kill_geo_pids
				mk_lock -f
				rm_iplists_rules
				die
		esac
		call_script "$i_script-apply.sh" $action
		die $? ;;
	reset)
		rm_iplists_rules
		rm_data
		[ -f "$conf_file" ] && { printf '%s\n' "Deleting the config file '$conf_file'..."; rm -f "$conf_file"; }
		rm_setupdone
		die 0 ;;
	restore) restore_from_config; die $?
esac

prev_config="$main_config"

[ ! -s "$conf_file" ] && {
	touch "$conf_file" || die "$FAIL create the config file."
	[ "$_fw_backend" ] && rm_iplists_rules
}


for var_name in datadir noblock nobackup schedule no_persist geosource ifaces families _fw_backend nft_perf user_ccode \
	lan_ips_ipv4 lan_ips_ipv6 trusted_ipv4 trusted_ipv6 source_ips_ipv4 source_ips_ipv6 source_ips_policy; do
	eval "${var_name}_prev=\"\$$var_name\""
done

export nointeract="${nointeract_arg:-$nointeract}"

get_general_prefs || die

for opt_ch in datadir noblock nobackup schedule no_persist geosource families \
		_fw_backend nft_perf user_ccode source_ips_policy; do
	unset "${opt_ch}_change"
	eval "[ \"\$${opt_ch}\" != \"\$${opt_ch}_prev\" ] && ${opt_ch}_change=1"
done

checkvars _fw_backend datadir

unset ccodes_arg_unset iplists_unset geomode_set ports_change geomode_change_g
[ ! "$inbound_ccodes_arg$outbound_ccodes_arg" ] && ccodes_arg_unset=1
[ ! "$inbound_iplists$outbound_iplists" ] && iplists_unset=1

for direction in inbound outbound; do
	[ -n "$geomode" ] && geomode_set=1
	eval "geomode_arg=\"\$${direction}_geomode_arg\"
			geomode=\"\$${direction}_geomode\""

	[ "$geomode" ] && geomode_set=1

	[ "$geomode_arg" ] && {
		tolower geomode_arg
		case "$geomode_arg" in whitelist|blacklist|disable)
			geomode_set=1
			eval "${direction}_geomode_arg=\"$geomode_arg\""
		esac
	}
done

for direction in inbound outbound; do
	unset ccodes process_args geomode_change
	contradicts1="contradicts $direction geoblocking mode 'disable'."
	contradicts2="To enable geoblocking for direction $direction: '$p_name configure -D $direction -m <whitelist|blacklist>'"

	for _par in geomode iplists tcp_ports udp_ports; do
		eval "${_par}=\"\${${direction}_${_par}}\" ${_par}_prev=\"\${${direction}_${_par}}\" \
			${direction}_${_par}_prev=\"\${${direction}_${_par}}\""
	done

	for _par in ccodes_arg ports_arg geomode_arg; do
		eval "${_par}=\"\$${direction}_${_par}\""
	done

	[ -n "$ccodes_arg" ] || [ -n "$ports_arg" ] && process_args=1

	[ "$geomode_arg" ] && {
		case "$geomode_arg" in
			whitelist|blacklist|disable) geomode="$geomode_arg" ;;
			'') ;;
			*)
				echolog -err "Invalid geoblocking mode '$geomode_arg'."
				[ "$nointeract" ] && die
				pick_geomode
		esac
	}

	[ ! "$geomode_set" ] && {
		if [ "$nointeract" ]; then
			[ "$direction" = outbound ] && die "Specify geoblocking mode with -m $mode_syn"
			geomode=disable
		elif [ "$direction" = inbound ]; then
			pick_geomode
		elif [ "$direction" = outbound ]; then
			echolog "${_nl}${yellow}NOTE${n_c}: You can set up *outbound* geoblocking later by running 'geoip-shell configure -D outbound -m <whitelist|blacklist>'."
		fi
	}

	: "${geomode:=disable}"

	if [ "$geomode" = disable ]; then
		[ "$ports_arg" ] && die "Option '-p' $contradicts1" "$contradicts2"
		[ "$ccodes_arg" ] && die "Option '-c' $contradicts1" "$contradicts2"
		process_args=
		unset iplists "${direction}_iplists"
		eval "${direction}_tcp_ports=skip ${direction}_udp_ports=skip ${direction}_geomode=disable"
	else
		process_args=1
	fi

	[ "$geomode" != "$geomode_prev" ] && { geomode_change=1; geomode_change_g=1; }

	eval "${direction}_geomode"='$geomode' "${direction}_geomode_change"='$geomode_change'

	[ "$direction" = outbound ] && ! is_whitelist_present && {
		[ "$lan_ips_arg" ] && die "Option '-l' can only be used in whitelist geoblocking mode."
		if [ -n "$lan_ips_ipv4$lan_ips_ipv6" ]; then
			echolog -warn "Inbound geoblocking mode is '$inbound_geomode', outbound geoblocking mode is '$outbound_geomode'. Removing lan ip's from config."
			unset lan_ips_ipv4 lan_ips_ipv6
		fi
	}

	[ ! "$process_args" ] && continue

	[ "$ports_arg" ] && { setports "${ports_arg%"$_nl"}" || die; }
	for opt_ch in tcp_ports udp_ports; do
		eval "[ \"\$${direction}_${opt_ch}\" != \"\$${direction}_${opt_ch}_prev\" ] && ${direction}_ports_change=1" &&
			ports_change=1
	done

	[ "$ccodes_arg" ] && validate_ccodes "$ccodes_arg"
	if { [ "$ccodes_arg_unset" ] && [ "$iplists_unset" ]; } || [ "$ccodes_arg" ] || [ "$geomode_change" ]; then
		if [ "$nointeract" ]; then
			[ "$direction" = outbound ] && {
				san_str all_ccodes_arg "$inbound_ccodes_arg $outbound_ccodes_arg" || die
				[ ! "$all_ccodes_arg" ] && die "Specify country codes with '-c $ccodes_syn'."
			}
			[ "$ccodes_arg" ] && pick_ccodes
		else
			pick_ccodes
		fi
	fi

	[ "$families_change" ] && [ ! "$ccodes" ] &&
		for list_id in $iplists; do
			add2list ccodes "${list_id%_*}"
		done

	unset lists_req excl_list_ids
	for ccode in $ccodes; do
		for f in $families; do
			list_id="${ccode}_$f"
			case "$exclude_iplists" in *"$list_id"*)
				add2list excl_list_ids "$list_id"
				continue
			esac
			add2list lists_req "$list_id"
		done
	done

	eval "${direction}_lists_req"='$lists_req' \
		"${direction}_ccodes"='$ccodes'
done

san_str all_ccodes_arg "$inbound_ccodes_arg $outbound_ccodes_arg" || die

[ "$excl_list_ids" ] && report_excluded_lists "$excl_list_ids"

[ "$all_ccodes_arg" ] && [ ! "$inbound_lists_req$outbound_lists_req" ] &&
	die "No applicable ip list id's could be generated for country codes '$all_ccodes_arg'."

unset lan_picked ifaces_picked ifaces_change

for direction in inbound outbound; do
	eval "geomode=\"\$${direction}_geomode\" geomode_change=\"\$${direction}_geomode_change\""
	[ "$geomode" = disable ] && continue
	if [ ! "$ifaces" ] && [ ! "$ifaces_arg" ]; then
		[ "$nointeract" ] && die "Specify interfaces with -i <\"ifaces\"|auto|all>."
		printf '\n%s\n%s\n%s\n%s\n' "${blue}Does this machine have dedicated WAN network interface(s)?$n_c [y|n] or [a] to abort." \
			"For example, a router or a virtual private server may have it." \
			"A machine connected to a LAN behind a router is unlikely to have it." \
			"It is important to answer this question correctly."
		pick_opt "y|n|a"
		case "$REPLY" in
			a) die 130 ;;
			y) pick_ifaces ;;
			n) ifaces=all; is_whitelist_present && [ ! "$lan_picked" ] && { warn_lockout; pick_lan_ips; }
		esac
		ifaces_change=1
	fi

	if [ "$ifaces_arg" ] && [ ! "$ifaces_picked" ]; then
		ifaces=
		case "$ifaces_arg" in
			all) ifaces=all
				is_whitelist_present && [ ! "$lan_picked" ] &&
					{ [ "$first_setup" ] || [ "$geomode_change" ] || [ "$ifaces_change" ]; } &&
						{ warn_lockout; pick_lan_ips; } ;;
			auto) ifaces_arg=''; pick_ifaces -a ;;
			*) pick_ifaces
		esac
	fi

	[ ! "$ifaces" ] && ifaces=all

	get_difference "$ifaces" "$ifaces_prev" || ifaces_change=1

	if [ ! "$lan_picked" ] && [ ! "$lan_ips_ipv4$lan_ips_ipv6" ] && is_whitelist_present && [ "$geomode_change" ] &&
		[ "$ifaces" = all ]; then
		warn_lockout; pick_lan_ips
	fi
done

[ "$lan_ips_arg" ] &&  [ ! "$lan_picked" ] && pick_lan_ips

[ "$geosource_change" ] && unset source_ips_ipv4 source_ips_ipv6

if [ "$source_ips_arg" ] || {
		[ "$outbound_geomode" != disable ] && [ ! "$source_ips_ipv4$source_ips_ipv6" ] && [ "$source_ips_policy" != pause ] &&
		{
			[ ! "$source_ips_policy" ] ||
			[ "$geosource_change" ] ||
			{ [ "$outbound_geomode_change" ] && [ "$outbound_geomode_prev" = disable ]; }
		}
	}
then
	pick_source_ips
fi

for opt_ch in lan_ips_ipv4 lan_ips_ipv6 trusted_ipv4 trusted_ipv6 source_ips_ipv4 source_ips_ipv6; do
	eval "[ \"\$${opt_ch}\" != \"\$${opt_ch}_prev\" ]" && eval "${opt_ch%_ipv*}_change=1"
done

[ "$source_ips_policy_change" ] && [ "$source_ips_policy" = true ] && source_ips_change=1

unset lists_change all_iplists all_iplists_prev all_add_iplists
for direction in inbound outbound; do
	eval "lists_req=\"\$${direction}_lists_req\" iplists=\"\$${direction}_iplists\" iplists_prev=\"\$${direction}_iplists_prev\""
	: "${lists_req:="$iplists"}"
	iplists="$lists_req"

	! get_difference "$iplists_prev" "$iplists" && {
		lists_change=1
		eval "${direction}_lists_change=1"
	}
	eval "${direction}_iplists"='$iplists'

	add2list all_iplists_prev "$iplists_prev"
	add2list all_iplists "$iplists"
done

subtract_a_from_b "$all_iplists_prev" "$all_iplists" all_add_iplists


unset run_restore_req run_add_req reset_req backup_req apply_req cron_req coherence_req

[ "$no_persist_change" ] || [ "$schedule_change" ] && cron_req=1

[ "$user_ccode_change" ] && backup_req=0

[ "$nobackup_change" ] && [ "$nobackup" = false ] && backup_req=1

[ "$ports_change" ] || [ "$ifaces_change" ] || [ "$geomode_change_g" ] || [ "$source_ips_policy_change" ] ||
	[ "$lan_ips_change" ] || [ "$trusted_change" ] || [ "$source_ips_change" ] ||
	[ "$noblock_change" ] || [ "$lists_change" ] && apply_req=1

[ "$nft_perf_change" ] && run_restore_req=1

[ "$all_add_iplists" ] && run_add_req=1

[ "$first_setup" ] || [ "$_fw_backend_change" ] || [ "$geosource_change" ] && reset_req=1

check_for_lockout

[ "$nobackup_change" ] && {
	[ -d "$datadir_prev/backup" ] && {
		printf %s "Removing old backup... "
		rm -rf "$datadir_prev/backup" || die "$FAIL remove old backup."
		OK
	}
}

[ "$datadir_change" ] && [ -n "${datadir_prev}" ] && {
	rm -rf "$datadir"
	mk_datadir
	[ -d "$datadir_prev" ] && {
		printf %s "Moving data to the new path... "
		set +f
		mv "$datadir_prev"/* "$datadir" || { rm -rf "$datadir"; die "$FAIL move the data directory."; }
		set -f
		OK
		printf %s "Removing the old data directory '$datadir_prev'..."
		rm -rf "$datadir_prev" || { rm -rf "$datadir"; die "$FAIL remove the old data directory."; }
		OK
	}
}

export datadir status_file="$datadir/status" nobackup

[ "$run_restore_req" ] &&
	{ [ "$nobackup_prev" = true ] || [ ! -s "$datadir/backup/$p_name.conf.bak" ] || [ ! -s "$status_file" ]; } &&
		reset_req=1

[ "$apply_req" ] && conf_act=apply
[ "$run_restore_req" ] && conf_act=run_restore
[ "$run_add_req" ] && conf_act=run_add
[ "$reset_req" ] && conf_act=reset

[ -z "$conf_act" ] && { check_lists_coherence -nr || conf_act=run_restore; }


if [ "$_fw_backend_change" ]; then
	if [ "$_fw_backend_prev" ]; then
		(
			export _fw_backend="$_fw_backend_prev"
			. "$_lib-$_fw_backend.sh" || exit 1
			rm_iplists_rules
			rm_data
			:
		) || die "$FAIL remove firewall rules for the backend '$_fw_backend_prev'."
	fi
	. "$_lib-$_fw_backend.sh" || die
else
	case "$conf_act" in backup|run_restore) ;; *)
		if [ "$nobackup" != true ] && [ -s "$status_file" ] && [ ! -s "$datadir/backup/status.bak" ]; then
			inbound_iplists="$inbound_iplists_prev" outbound_iplists="$outbound_iplists_prev" \
				call_script -l "$i_script-backup.sh" create-backup || rm_data
		fi
	esac
fi

set_all_config

case "$conf_act" in
	run_add|run_restore|reset)
		backup_req=
		cron_req=1 ;;
	apply)
		backup_req=1
		cron_req=1
		coherence_req=1 ;;
	*)
esac

mk_datadir

case "$conf_act" in
	reset)
		restore_from_config
		rv_conf=$? ;;
	run_add)
		[ "$all_add_iplists" ] || die "conf_act is 'run_add' but \$all_add_iplists is empty string"
		get_counters
		call_script -l "$i_script-run.sh" add -l "$all_add_iplists" -o
		rv_conf=$? ;;
	run_restore)
		get_counters
		call_script -l "$i_script-run.sh" restore -f
		rv_conf=$? ;;
	apply)
		get_counters
		call_script "$i_script-apply.sh" restore
		rv_conf=$?
		main_config=
		nodie=1 export_conf=1 get_config_vars || rv_conf=1
		;;
	'') rv_conf=0 ;;
esac

if [ "$rv_conf" = 0 ]; then
	[ "$coherence_req" ] && [ "$conf_act" != reset ] && {
		check_lists_coherence || restore_from_config || die
	}
else
	backup_req=1
fi

case "$rv_conf" in
	0) ;;
	254)
		echolog "Restoring previous config."
		main_config="$prev_config"
		nodie=1 export_conf=1 get_config_vars && check_lists_coherence ||
			{
				_prev="previous "
				prev_config_try=1
				restore_from_config
				die $?
			}
		set_all_config
		backup_req=
		rv_conf=0 ;;
	*) restore_from_config
esac || die

[ "$rv_conf" = 0 ] && {
	bk_conf_only=
	[ "$backup_req" = 0 ] && bk_conf_only='-s'
	[ "$backup_req" ] && [ "$nobackup" != true ] && [ "$inbound_iplists$outbound_iplists" ] &&
		call_script -l "$i_script-backup.sh" create-backup "$bk_conf_only"

	[ "$first_setup" ] && touch "$conf_dir/setupdone"
	if [ "$cron_req" ]; then
		call_script "$i_script-cronsetup.sh" || echolog -err "$FAIL update cron jobs."
		[ "$_OWRTFW" ] && {
			case "$no_persist" in
				true) disable_owrt_persist ;;
				false)
					if [ -z "$inbound_iplists$outbound_iplists" ]; then
						[ ! -f "$conf_dir/no_persist" ] && touch "$conf_dir/no_persist"
						echolog "Countries list in the config file is empty! No point in creating firewall include."
					else
						rm -f "$conf_dir/no_persist"
						check_owrt_init && check_owrt_include || {
							rm_lock
							enable_owrt_persist
							rv_conf=$?
							[ -f "$lock_file" ] && {
								echo "Waiting for background processes to complete..."
								for i in $(seq 1 30); do
									[ ! -f "$lock_file" ] && break
									sleep 1
								done
								[ $i = 30 ] && echolog -warn "Lock file '$lock_file' is still in place. Please check system log."
							}
						}
					fi
			esac
		}
	fi

	[ "$first_setup" ] && [ "$rv_conf" = 0 ] &&
		printf '\n%s\n' "Successfully configured $p_name for firewall backend: ${blue}${_fw_backend}ables${n_c}."

	report_lists
	statustip
}

die $rv_conf
