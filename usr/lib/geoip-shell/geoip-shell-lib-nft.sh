#!/bin/sh

curr_ver=0.6.7

# Copyright: antonk (antonk.d3v@gmail.com)
# github.com/friendly-bits

get_nft_family() {
	case "$1" in ipv4|ipv6) ;; *) echolog -err "get_nft_family: unexpected family '$1'"; nft_family=''; return 1; esac
	nft_family="${1%ipv4}"
	nft_family="ip${nft_family#ipv}"
}

is_geochain_on() {
	[ "$1" = '-f' ] && { force_read='-f'; shift; }
	[ "$1" ] || { echolog -err "is_geochain_on: direction not specified"; return 2; }
	set_dir_vars "$1"
	get_matching_line "$(nft_get_chain "$base_geochain" "$force_read")" "*" "${geotag}_enable" "*"
}

nft_get_geotable() {
	[ "$1" != "-f" ] && [ -n "$geotable_cont" ] && { printf '%s\n' "$geotable_cont"; return 0; }
	export geotable_cont="$(nft -ta list ruleset inet | sed -n -e /"^table inet $geotable"/\{:1 -e n\;/^\}/q\;p\;b1 -e \})"
	[ -z "$geotable_cont" ] && return 1 || { printf '%s\n' "$geotable_cont"; return 0; }
}

nft_get_chain() {
	_chain_cont="$(nft_get_geotable "$2" | sed -n "/chain $1 {/{:1 n;/^${blank}*}/q;p;b1;}")"
	[ -z "$_chain_cont" ] && return 1 || { printf '%s\n' "$_chain_cont"; return 0; }
}

rm_all_georules() {
	nft_get_geotable -f 1>/dev/null 2>/dev/null || return 0
	get_counters
	printf_s "Removing $p_name firewall rules... "
	export geotable_cont=
	nft delete table inet "$geotable" || { echolog -err -nolog "$FAIL delete table '$geotable'."; return 1; }
	OK
}

encode_rules() {
	unset sed_inc_counter_2
	[ "$1" != '-n' ] && sed_inc_counter_2="s/Z*=/=/;s/packetsZ/packets\ /;s/ZbytesZ/\ bytes\ /"

	sed "s/comment//;s/${p_name}[_]*//g;s/${p_name_cap}[_]*//g;s/ct\ state//;s/\"//g;s/\;//g;s/{//g;s/}//g;s/aux_//;s/^${blanks}//;
		s/ifname/if/;s/accept/acpt/g;s/drop/drp/;s/saddr/sa/;s/daddr/da/;s/inbound/in/g;s/outbound/out/g;s/dport/dpt/;
		s/link-local/lnkl/;s/-/_/g;s/\./_/g;s~/~W~g;s/\!=/X/g;s/,/Y/g;s/:/Q/g;s/@/U/;s/${blanks}/Z/g;
		$sed_inc_counter_2"
}

get_counters_nft() {
	counter_strings="$(
		nft -ta list ruleset inet | \
		sed -n ":2 /chain $p_name_cap/{:1 n;/^${blank}*}/b2;s/ # handle.*//;/counter${blanks}packets/{s/counter${blanks}//;p;};b1;}" | \
		$awk_cmd 'match($0,/[ 	]packets [0-9]+ bytes [0-9]+/){print substr($0,1,RSTART-1) substr($0,RSTART+RLENGTH) "=" substr($0,RSTART+1,RLENGTH-1)}' | \
		encode_rules
	)"
	:
}

mk_nft_rm_cmd() {
	chain="$1"; _chain_cont="$2"; shift 2
	[ ! "$chain" ] && { echolog -err "mk_nft_rm_cmd: no chain name specified."; return 1; }
	for tag in "$@"; do
		printf '%s\n' "$_chain_cont" | sed -n "/$tag/{s/^.* # handle/delete rule inet $geotable $chain handle/;s/$/ # $tag/;p;}" || return 1
	done
}

get_nft_list() {
	n=0; _res=
	[ "$1" = '!=' ] && { _res='!='; shift; n=$((n+1)); }
	case "$1" in
		'{')
			while :; do
				shift; n=$((n+1))
				[ "$1" = '}' ] && break
				_res="$_res$1"
			done ;;
		*) _res="$_res$1"
	esac
}

get_fwrules_iplists() {
	case "$1" in
		inbound) addr_type=saddr ;;
		outbound) addr_type=daddr ;;
		*) echolog -err "get_fw_rules_iplists: direction not specified"; return 1;
	esac
	set_dir_vars "$1"
	nft_get_chain "$geochain" "$force_read" | {
		sed -n "/${addr_type}${blank}*@[a-zA-Z0-9_][a-zA-Z0-9_]*/{s/@dhcp_4.*/@dhcp_4/;s/.*@//;s/_[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].*//;s/${blanks}accept.*//;s/${blanks}drop.*//;s/_4/_ipv4/;s/_6/_ipv6/;p;}"
	}
	:
}

get_ipsets() {
	nft_get_geotable -f | sed -n "/^${blank}*set${blank}/{s/^${blank}*set${blank}${blank}*//;s/${blank}.*//;p;}"
}

get_ipset_elements() {
    get_matching_line "$2" "" "$1" "*" ipset
    [ "$ipset" ] && nft list set inet "$geotable" "$ipset" |
        sed -n "/elements${blank}*=/{s/elements${blank}*=${blank}*{//;:1 /}/{s/}//;p;q;};p;n;b1;}"
}

cnt_ipset_elements() {
    get_matching_line "$2" "" "$1" "*" ipset
    [ ! "$ipset" ] && { echo 0; return 1; }
    get_ipset_elements "$1" "$2" | wc -w
}

print_ipset_elements() {
	get_ipset_elements "$1" "$2" | $awk_cmd '{gsub(",", "");$1=$1};1' ORS=' '
}

report_fw_state() {
	curr_geotable="$(nft_get_geotable)" || {
		printf '%s\n' "$FAIL read the firewall state or firewall table '$geotable' does not exist." >&2
		incr_issues
		return 1
	}

	direction="$1"
	set_dir_vars "$direction"
	is_geochain_on "$direction" && chain_status="${green}enabled $_V" || { chain_status="${red}disabled $_X"; incr_issues; }
	printf '%s\n' "  Geoblocking firewall chain: $chain_status"
	[ "$geomode" = whitelist ] && {
		wl_rule="$(printf %s "$curr_geotable" | grep "drop comment \"${geotag}_${direction}_whitelist_block\"")"
		case "$wl_rule" in
			'') wl_rule_status="$_X"; incr_issues ;;
			*) wl_rule_status="$_V"
		esac
		printf '%s\n' "  whitelist blocking rule: $wl_rule_status"
	}

	if [ "$verb_status" ]; then
		dashes="$(printf '%156s' ' ' | tr ' ' '-')"
		fmt_str="  %-9s%-11s%-5s%-8s%-5s%-24s%-33s%s\n"
		printf "\n%s\n%s\n${fmt_str}%s\n" "  Firewall rules in the $geochain chain:" \
			"  $dashes${blue}" packets bytes ipv verdict prot dports interfaces extra "$n_c  $dashes"
		rules="$(nft_get_chain "$geochain" | sed "s/^${blank}*//;s/ # handle.*//" | grep .)" ||
			{ printf '%s\n' "${red}None $_X"; incr_issues; }
		newifs "$_nl" rules
		for rule in $rules; do
			newifs ' "' wrds
			set -- $rule
			case "$families" in "ipv4 ipv6"|"ipv6 ipv4") dfam="both" ;; *) dfam="$families"; esac
			pkts='---'; bytes='---'; ipv="$dfam"; verd='---'; prot='all'; dports='all'; in='all'; line=''
			while [ -n "$1" ]; do
				case "$1" in
					iifname|oifname) shift; get_nft_list "$@"; in="$_res"; shift "$n" ;;
					ip) ipv="ipv4" ;;
					ip6) ipv="ipv6" ;;
					dport) shift; get_nft_list "$@"; dports="$_res"; shift "$n" ;;
					udp|tcp) prot="$1 " ;;
					packets) pkts=$(num2human "$2"); shift ;;
					bytes) bytes=$(num2human "$2" bytes); shift ;;
					counter) ;;
					accept) verd="ACCEPT" ;;
					drop) verd="DROP  " ;;
					*) line="$line$1 "
				esac
				shift
			done
			printf "$fmt_str" "$pkts " "$bytes " "$ipv " "$verd " "$prot " "$dports " "$in " "${line% }"
		done
		oldifs rules
		echo
	fi
}

destroy_tmp_ipsets() {
	echo "Destroying temporary ipsets..."
	for load_ipset in $load_ipsets; do
		nft delete set inet "$geotable" "$load_ipset" 1>/dev/null 2>/dev/null
	done
}

geoip_on() {
	for direction in ${1:-inbound outbound}; do
		set_dir_vars "$direction"
		[ "$geomode" = disable ] && {
			echo "$direction geoblocking mode is set to 'disable' - skipping."
			continue
		}
		get_nft_geoip_state -f "$direction" || return 1
		[ -n "$geochain_on" ] && { echo "${direction} geoblocking is already enabled."; continue; }
		if [ -z "$base_chain_cont" ]; then
			missing_chain="base geoip"
		elif [ -z "$geochain_cont" ]; then
			missing_chain=geoip
		fi
		[ -n "$missing_chain" ] && {
			echolog -err "Cannot enable $direction geoblocking because $direction $missing_chain chain is missing."
			continue
		}

		printf_s "Adding $direction geoblocking enable rule... "
		printf '%s\n' "add rule inet $geotable $base_geochain jump $geochain comment ${geotag}_enable" | nft -f - &&
			is_geochain_on -f "$direction" || { FAIL; die "$FAIL add $direction geoblocking enable rule."; }
		OK
	done
}

geoip_off() {
	off_ok=
	for direction in ${1:-inbound outbound}; do
		get_nft_geoip_state -f "$direction" || return 1
		[ -z "$geochain_on" ] && { echo "$direction geoblocking is already disabled."; continue; }
		printf %s "Removing the geoblocking enable rule for direction '$direction'... "
		mk_nft_rm_cmd "$base_geochain" "$base_chain_cont" "${geotag}_enable" | nft -f - &&
			! is_geochain_on -f "$direction" ||
				{ FAIL; echolog -err "$FAIL remove $direction geoblocking enable rule."; return 1; }
		off_ok=1
		OK
	done
	[ ! "$off_ok" ] && return 2
	:
}

get_nft_geoip_state() {
	unset geomode geochain base_geochain geotable_cont geochain_cont base_chain_cont geochain_on
	[ "$1" = '-f' ] && { force_read='-f'; shift; }
	[ "$1" ] || { echolog -err "get_nft_geoip_state: direction not specified"; return 1; }
	set_dir_vars "$1"
	nft_get_geotable "$force_read" 1>/dev/null
	geochain_on=
	is_geochain_on "$1" && geochain_on=1
	geochain_cont="$(nft_get_chain "$geochain")"
	base_chain_cont="$(nft_get_chain "$base_geochain")"
	:
}

apply_rules() {
	: "${nft_perf:=memory}"

	nft add table inet "$geotable" || die "$FAIL create table '$geotable'"

	printf_s "${_nl}Loading ip sets... "
	for load_ipset in $load_ipsets; do
		get_ipset_id "$load_ipset" || die_a
		iplist_file="${iplist_dir}/${list_id}.iplist"
		[ -f "$iplist_file" ] || { FAIL; die_a "Can not find the iplist file '$iplist_file'."; }


		{
			printf %s "add set inet $geotable $load_ipset \
				{ type ${ipset_family}_addr; flags interval; auto-merge; policy $nft_perf; "
			sed '/\}/{s/,*[ 	]*\}/ \}; \}/;q;};$ {s/$/; \}/}' "$iplist_file"
		} | nft -f - || { FAIL; die_a "$FAIL import the iplist from '$iplist_file' into ip set '$load_ipset'."; }

	done
	OK

	curr_ipsets="$(get_ipsets)"
	newifs "$_nl" aru
	for family in ipv4 ipv6; do
		for ipset_type in allow allow_in allow_out dhcp; do
			ipset="${ipset_type}_${family#ipv}"
			case "$curr_ipsets" in *"$ipset"*) add2list rm_ipsets "$ipset"; esac
		done
	done
	oldifs aru

	opt_ifaces_gen=
	[ "$ifaces" != all ] && {
		unset br1 br2
		case "$ifaces" in *' '*) br1='{ ' br2=' }'; esac
		opt_ifaces_gen="$br1$(printf '"%s", ' $ifaces)"
		opt_ifaces_gen="${opt_ifaces_gen%", "}$br2"
	}

	printf_s "Assembling nftables commands... "

	nft_get_geotable -f 1>/dev/null
	nft_cmd_chain="$(
		for direction in inbound outbound; do
			set_dir_vars "$direction"
			for chain in "$base_geochain" "$geochain"; do
				case "$geotable_cont" in *"chain $chain "*)
					printf '%s\n%s\n' "flush chain inet $geotable $chain" "delete chain inet $geotable $chain"
				esac
			done
		done

		for rm_ipset in $rm_ipsets; do
			printf '%s\n' "delete set inet $geotable $rm_ipset"
		done

		for family in $families; do
			allow_iplist_file_prev=
			for direction in inbound outbound; do
				eval "geomode=\"\$${direction}_geomode\""
				set_allow_ipset_vars "$direction" "$family"
				[ "$allow_iplist_file" = "$allow_iplist_file_prev" ] || [ "$geomode" = disable ] ||
					[ ! -s "$allow_iplist_file" ] && continue
				allow_iplist_file_prev="$allow_iplist_file"
				eval "allow_ipset_type=\"\${allow_ipset_type_${direction}_${family}}\""

				interval=
				[ "${allow_ipset_type}" = net ] && interval="flags interval; auto-merge;"

				printf %s "add set inet $geotable $allow_ipset_name { type ${family}_addr; $interval elements={ "
				sed '/^$/d;s/$/,/' "$allow_iplist_file"
				printf '%s\n' " }; }"
			done
		done

		is_whitelist_present && {
			case "$families" in *ipv4*)
				printf '%s%s\n' "add set inet $geotable dhcp_4 { type ipv4_addr; flags interval; auto-merge; elements="\
					"{ 192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8 }; }"
			esac
		}

		for direction in inbound outbound; do
			set_dir_vars "$direction"
			geopath="inet $geotable $geochain"
			rule_prefix="rule $geopath"

			case "$direction" in
				inbound) hook=prerouting priority=-141 addr_type=saddr iface_keyword=iifname ;;
				outbound) hook=postrouting priority=0 addr_type=daddr iface_keyword=oifname
			esac
			opt_ifaces=
			[ "$opt_ifaces_gen" ] && opt_ifaces="$iface_keyword $opt_ifaces_gen "

			case "$geomode" in
				whitelist) iplist_verdict=accept ;;
				blacklist) iplist_verdict=drop ;;
				disable)
					continue ;;
				*) echolog -err "Unknown geoblocking mode '$geomode'."; exit 1
			esac

			printf '%s\n' "add chain inet $geotable $base_geochain { type filter hook $hook priority $priority; policy accept; }"
			printf '%s\n' "add chain $geopath"

			[ "$geomode" = whitelist ] && [ "$ifaces" = all ] &&
				printf '%s\n' "add rule $geopath $iface_keyword lo accept comment ${geotag_aux}_loopback"

			printf '%s\n' "add $rule_prefix ${opt_ifaces}ct state established,related accept comment ${geotag_aux}_est-rel"

			for family in $families; do
				set_allow_ipset_vars "$direction" "$family"
				[ ! -s "$allow_iplist_file" ] && continue
				get_nft_family "$family" || exit 1
				printf '%s\n' "add $rule_prefix $opt_ifaces$nft_family $addr_type @$allow_ipset_name accept comment ${geotag_aux}_allow"
			done

			[ "$geomode" = whitelist ] && {
				for family in $families; do
					get_nft_family "$family" || exit 1
					f_short="${family#ipv}"
					case "$f_short" in
						6)
							dhcp_addr="fc00::/6"
							dhcp_dports="546, 547" ;;
						4)
							dhcp_addr="@dhcp_4"
							dhcp_dports="67, 68"
					esac
					rule_DHCP_1="$opt_ifaces$nft_family $addr_type $dhcp_addr udp dport { $dhcp_dports }"
					rule_DHCP_2="accept comment \"${geotag_aux}_DHCP_${f_short}\""
					get_counter_val "$rule_DHCP_1 $rule_DHCP_2"
					printf '%s\n' "add $rule_prefix $rule_DHCP_1 counter $counter_val $rule_DHCP_2"

				done
			}

			for proto in tcp udp; do
				eval "ports_exp=\"\${${direction}_${proto}_ports%:*}\" ports=\"\${${direction}_${proto}_ports##*:}\""
				case "$ports_exp" in
					skip) continue ;;
					all) ports_exp="meta l4proto $proto" ;;
					'') echolog -err "\$ports_exp is empty string for direction '$direction'"; exit 1 ;;
					*)
						unset br1 br2
						case "$ports" in *','*)
							br1='{ ' br2=' }'
							ports="$(printf %s "$ports" | sed 's/,/, /g')"
						esac
						ports_exp="$proto $(printf %s "$ports_exp" | sed "s/multiport //;s/!dport/dport !=/") $br1$ports$br2"
				esac
				rule_ports_pt1="$opt_ifaces$ports_exp"
				rule_ports_pt2="accept comment \"${geotag_aux}_ports\""
				get_counter_val "$rule_ports_pt1 $rule_ports_pt2"
				printf '%s\n' "add $rule_prefix $rule_ports_pt1 counter $counter_val $rule_ports_pt2"
			done

			eval "planned_ipsets_direction=\"\${planned_ipsets_${direction}}\""
			for ipset in $planned_ipsets_direction; do
				get_ipset_id "$ipset" &&
				get_nft_family "$ipset_family" || exit 1
				rule_ipset="$opt_ifaces$nft_family $addr_type @$ipset"
				get_counter_val "$rule_ipset $iplist_verdict"
				printf '%s\n' "add $rule_prefix $rule_ipset counter $counter_val $iplist_verdict comment ${geotag}"
			done

			[ "$geomode" = whitelist ] && {
				rule_wl_pt2="drop comment \"${geotag}_${direction}_whitelist_block\""
				get_counter_val "$opt_ifaces$rule_wl_pt2"
				printf '%s\n' "add $rule_prefix ${opt_ifaces}counter $counter_val $rule_wl_pt2"
			}

			[ "$noblock" = false ] && printf '%s\n' "add rule inet $geotable $base_geochain jump $geochain comment ${geotag}_enable"
		done

		:
	)" || die_a 254 "$FAIL assemble nftables commands."
	OK

	printf_s "Applying new firewall rules... "
	nft_output="$(printf '%s\n' "$nft_cmd_chain" | nft -f - 2>&1)" || {
		FAIL
		echolog -err "$FAIL apply new firewall rules"
		echolog "nftables errors: '$(printf %s "$nft_output" | head -c 1k | tr '\n' ';')'"
		die
	}

	OK

	nft_get_geotable -f >/dev/null
	ports_conf=
	ports_exp=
	for direction in inbound outbound; do
		set_dir_vars "$direction"
		[ "$geomode" = disable ] && continue
		for proto in tcp udp; do
			eval "ports_exp=\"\$${direction}_${proto}_ports\""
			case "$ports_exp" in skip|all) continue; esac
			ports_line="$(nft_get_chain "$geochain" | grep -m1 -o "${proto} dport.*${geotag_aux}_ports")"

			IFS=' 	' set -- $ports_line; shift 2
			get_nft_list "$@"; ports_exp="$_res"
			unset mp neg
			case "$ports_exp" in *','*) mp="multiport "; esac
			case "$ports_exp" in *'!'*) neg='!'; esac
			ports_conf="$ports_conf${direction}_${proto}_ports=$mp${neg}dport:${ports_exp#*"!="}$_nl"
		done
	done
	[ "$ports_conf" ] && setconfig "${ports_conf%"$_nl"}"

	:
}

extract_iplists() {
	printf_s "Restoring ip lists from backup... "
	mkdir -p "$iplist_dir"
	for list_id in $iplists; do
		bk_file="$bk_dir/$list_id.$bk_ext"
		iplist_file="$iplist_dir/${list_id}.iplist"

		[ ! -s "$bk_file" ] && rstr_failed "'$bk_file' is empty or doesn't exist."

		$extract_cmd "$bk_file" > "$iplist_file" || rstr_failed "$FAIL extract backup file '$bk_file'."
		[ ! -s "$iplist_file" ] && rstr_failed "$FAIL extract ip list for $list_id."
	done
	OK
	:
}

create_backup() {
	getstatus "$status_file" || bk_failed
	for list_id in $iplists; do
		bk_file="${bk_dir_new}/${list_id}.${bk_ext:-bak}"
		eval "list_date=\"\$prev_date_${list_id}\""
		[ -z "$list_date" ] && bk_failed "$FAIL get date for ip list '$list_id'."
		list_id_short="${list_id%%_*}_${list_id##*ipv}"
		ipset="${list_id_short}_${list_date}"

		rm -f "$tmp_file"
		nft list set inet "$geotable" "$ipset" |
			sed -n "/elements${blank}*=${blank}*{/{s/${blanks}//g;p;/\}/q;:1 n;s/${blanks}//;p;/\}/q;b1;}" \
				> "$tmp_file" && [ -s "$tmp_file" ] ||
					bk_failed "${_nl}$FAIL create backup of the ipset for iplist id '$list_id'."


		$compr_cmd < "$tmp_file" > "$bk_file" || bk_failed "$compr_cmd exited with status $? for ip list '$list_id'."
		[ -s "$bk_file" ] || bk_failed "resulting compressed file for '$list_id' is empty or doesn't exist."
	done
	:
}

geotable="$geotag"
inbound_base_geochain=${p_name_cap}_BASE_IN outbound_base_geochain=${p_name_cap}_BASE_OUT
