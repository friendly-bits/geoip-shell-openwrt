#!/bin/sh

curr_ver=0.5.2

# Copyright: antonk (antonk.d3v@gmail.com)
# github.com/friendly-bits

get_nft_family() {
	nft_family="${family%ipv4}"; nft_family="ip${nft_family#ipv}"
}

is_geochain_on() {
	get_matching_line "$(nft_get_chain "$base_geochain" "$1")" "*" "${geotag}_enable" "*" test; rv=$?
	return $rv
}

nft_get_geotable() {
	[ "$1" != "-f" ] && [ -n "$_geotable_cont" ] && { printf '%s\n' "$_geotable_cont"; return 0; }
	export _geotable_cont="$(nft -ta list ruleset inet | sed -n -e /"^table inet $geotable"/\{:1 -e n\;/^\}/q\;p\;b1 -e \})"
	[ -z "$_geotable_cont" ] && return 1 || { printf '%s\n' "$_geotable_cont"; return 0; }
}

nft_get_chain() {
	_chain_cont="$(nft_get_geotable "$2" | sed -n -e /"chain $1 {"/\{:1 -e n\;/"^[[:space:]]*}"/q\;p\;b1 -e \})"
	[ -z "$_chain_cont" ] && return 1 || { printf '%s\n' "$_chain_cont"; return 0; }
}

rm_all_georules() {
	printf %s "Removing firewall geoip rules... "
	nft_get_geotable -f 1>/dev/null 2>/dev/null || return 0
	nft delete table inet "$geotable" || { echolog -err -nolog "$FAIL delete table '$geotable'."; return 1; }
	export _geotable_cont=
	OK
}

mk_nft_rm_cmd() {
	chain="$1"; _chain_cont="$2"; shift 2
	[ ! "$chain" ] || [ ! "$*" ] && return 1
	for tag in "$@"; do
		printf '%s\n' "$_chain_cont" | sed -n "/$tag/"'s/^.* # handle/'"delete rule inet $geotable $chain handle"'/p' || return 1
	done
}

get_nft_list() {
	n=0; _res=
	[ "$1" = '!=' ] && { _res='!='; shift; n=$((n+1)); }
	case "$1" in
		'{')
			while true; do
				shift; n=$((n+1))
				[ "$1" = '}' ] && break
				_res="$_res$1"
			done ;;
		*) _res="$_res$1"
	esac
}

get_fwrules_iplists() {
	nft_get_geotable "$force_read" |
		sed -n "/saddr[[:space:]]*@.*${geotag}.*$nft_verdict/{s/.*@//;s/_.........._${geotag}.*//p}"
}

get_ipset_id() {
	list_id="${1%_"$geotag"}"
	list_id="${list_id%_*}"
	family="${list_id#*_}"
	case "$family" in
		ipv4|ipv6) return 0 ;;
		*) echolog -err "ip set name '$1' has unexpected format."
			unset family list_id
			return 1
	esac
}

get_ipsets() {
	nft -t list sets inet | grep -o "[a-zA-Z0-9_-]*_$geotag"
}

get_ipset_iplists() {
	nft -t list sets inet | sed -n "/$geotag/{s/.*set[[:space:]]*//;s/_.........._${geotag}.*//p}"
}

get_ipset_elements() {
    get_matching_line "$ipsets" "" "$1" "*" ipset
    [ "$ipset" ] && nft list set inet "$geotable" "$ipset" |
        sed -n -e /"elements[[:space:]]*=/{s/elements[[:space:]]*=[[:space:]]*{//;:1" -e "/}/{s/}//"\; -e p\; -e q\; -e \}\; -e p\; -e n\;b1 -e \}
}

cnt_ipset_elements() {
    get_matching_line "$ipsets" "" "$1" "*" ipset
    [ ! "$ipset" ] && { echo 0; return 1; }
    get_ipset_elements "$1" | wc -w
}

print_ipset_elements() {
	get_ipset_elements "$1" | awk '{gsub(",", "");$1=$1};1' ORS=' '
}

report_fw_state() {
	curr_geotable="$(nft_get_geotable)" ||
		{ printf '%s\n' "$FAIL read the firewall state or firewall table $geotable does not exist." >&2; incr_issues; }

	wl_rule="$(printf %s "$curr_geotable" | grep "drop comment \"${geotag}_whitelist_block\"")"

	is_geochain_on && chain_status="${green}enabled $_V" || { chain_status="${red}disabled $_X"; incr_issues; }
	printf '%s\n' "Geoip firewall chain: $chain_status"
	[ "$geomode" = whitelist ] && {
		case "$wl_rule" in
			'') wl_rule_status="$_X"; incr_issues ;;
			*) wl_rule_status="$_V"
		esac
		printf '%s\n' "Whitelist blocking rule: $wl_rule_status"
	}
	[ ! "$nft_perf" ] && { nft_perf="${red}Not set $_X"; incr_issues; }
	printf '\n%s\n' "nftables sets optimization policy: ${blue}$nft_perf$n_c"

	if [ "$verb_status" ]; then
		dashes="$(printf '%158s' ' ' | tr ' ' '-')"
		fmt_str="%-9s%-11s%-5s%-8s%-5s%-24s%-33s%s\n"
		printf "\n%s\n%s\n${fmt_str}%s\n" "${purple}Firewall rules in the $geochain chain${n_c}:" \
			"$dashes${blue}" packets bytes ipv verdict prot dports interfaces extra "$n_c$dashes"
		rules="$(nft_get_chain "$geochain" | sed 's/^[[:space:]]*//;s/ # handle.*//' | grep .)" ||
			{ printf '%s\n' "${red}None $_X"; incr_issues; }
		newifs "$_nl" rules
		for rule in $rules; do
			newifs ' "' wrds
			set -- $rule
			case "$families" in "ipv4 ipv6"|"ipv6 ipv4") dfam="both" ;; *) dfam="$families"; esac
			pkts='---'; bytes='---'; ipv="$dfam"; verd='---'; prot='all'; dports='all'; in='all'; line=''
			while [ -n "$1" ]; do
				case "$1" in
					iifname) shift; get_nft_list "$@"; in="$_res"; shift "$n" ;;
					ip) ipv="ipv4" ;;
					ip6) ipv="ipv6" ;;
					dport) shift; get_nft_list "$@"; dports="$_res"; shift "$n" ;;
					udp|tcp) prot="$1 " ;;
					packets) pkts=$(num2human $2); shift ;;
					bytes) bytes=$(num2human $2 bytes); shift ;;
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
	for new_ipset in $new_ipsets; do
		nft delete set inet "$geotable" "$new_ipset" 1>/dev/null 2>/dev/null
	done
}

geoip_on() {
	get_nft_geoip_state
	[ -n "$geochain_on" ] && { echo "Geoip chain is already switched on."; exit 0; }
	[ -z "$base_chain_cont" ] && missing_chain="base geoip"
	[ -z "$geochain_cont" ] && missing_chain=geoip
	[ -n "$missing_chain" ] && { echo "Can't switch geoip on because the $missing_chain chain is missing."; exit 1; }

	printf %s "Adding the geoip enable rule... "
	printf '%s\n' "add rule inet $geotable $base_geochain jump $geochain comment ${geotag}_enable" | nft -f -; rv=$?
	[ $rv != 0 ] || ! is_geochain_on -f && { FAIL; die "$FAIL add firewall rule."; }
	OK
}

geoip_off() {
	get_nft_geoip_state
	[ -z "$geochain_on" ] && { echo "Geoip chain is already disabled."; exit 0; }
	printf %s "Removing the geoip enable rule... "
	mk_nft_rm_cmd "$base_geochain" "$base_chain_cont" "${geotag}_enable" | nft -f -; rv=$?
	[ $rv != 0 ] || is_geochain_on -f && { FAIL; die "$FAIL remove firewall rule."; }
	OK
}

get_nft_geoip_state() {
	nft_get_geotable -f 1>/dev/null
	geochain_on=
	is_geochain_on && geochain_on=1
	geochain_cont="$(nft_get_chain "$geochain")"
	base_chain_cont="$(nft_get_chain "$base_geochain")"
}

apply_rules() {

	: "${nft_perf:=memory}"

	get_nft_geoip_state

	[ ! "$list_ids" ] && [ "$action" != update ] && {
		usage
		die 254 "Specify iplist id's!"
	}

	unset old_ipsets new_ipsets
	curr_ipsets="$(nft -t list sets inet | grep "$geotag")"

	getstatus "$status_file" || die "$FAIL read the status file '$status_file'."

	for list_id in $list_ids; do
		case "$list_id" in *_*) ;; *) die "Invalid iplist id '$list_id'."; esac
		family="${list_id#*_}"
		iplist_file="${iplist_dir}/${list_id}.iplist"
		eval "list_date=\"\$prev_date_${list_id}\""
		[ ! "$list_date" ] && die "$FAIL read value for 'prev_date_${list_id}' from file '$status_file'."
		ipset="${list_id}_${list_date}_${geotag}"
		case "$curr_ipsets" in
			*"$ipset"* ) [ "$action" = add ] && { echo "Ip set for '$list_id' is already up-to-date."; continue; }
				old_ipsets="$old_ipsets$ipset " ;;
			*"$list_id"* )
				get_matching_line "$curr_ipsets" "*" "$list_id" "*" ipset_line
				n="${ipset_line#*set }"
				old_ipset="${n%"_$geotag"*}_$geotag"
				old_ipsets="$old_ipsets$old_ipset "
		esac
		[ "$action" = "add" ] && new_ipsets="$new_ipsets$ipset "
	done

	nft add table inet $geotable || die "$FAIL create table '$geotable'"

	for new_ipset in $new_ipsets; do
		printf %s "Adding ip set '$new_ipset'... "
		get_ipset_id "$new_ipset" || die_a
		iplist_file="${iplist_dir}/${list_id}.iplist"
		[ ! -f "$iplist_file" ] && die_a "Can not find the iplist file '$iplist_file'."

		[ "$debugmode" ] && ip_cnt="$(tr ',' ' ' < "$iplist_file" | wc -w)"
		

		{
			printf %s "add set inet $geotable $new_ipset { type ${family}_addr; flags interval; auto-merge; policy $nft_perf; "
			cat "$iplist_file"
			printf '%s\n' "; }"
		} | nft -f - || die_a "$FAIL import the iplist from '$iplist_file' into ip set '$new_ipset'."
		OK

		
	done

	opt_ifaces=
	[ "$ifaces" != all ] && opt_ifaces="iifname { $(printf '"%s", ' $ifaces) }"
	georule="rule inet $geotable $geochain $opt_ifaces"

	printf %s "Assembling nftables commands... "
	nft_cmd_chain="$(
		rv=0

		printf '%s\n%s\n' "add chain inet $geotable $base_geochain { type filter hook prerouting priority -141; policy accept; }" \
			"add chain inet $geotable $geochain"

		mk_nft_rm_cmd "$geochain" "$geochain_cont" "${geotag}_whitelist_block" "${geotag_aux}" || exit 1

		mk_nft_rm_cmd "$base_geochain" "$base_chain_cont" "${geotag}_enable" || exit 1

		for old_ipset in $old_ipsets; do
			mk_nft_rm_cmd "$geochain" "$geochain_cont" "$old_ipset" || exit 1
			printf '%s\n' "delete set inet $geotable $old_ipset"
		done

		for family in $families; do
			nft_get_geotable | grep "trusted_${family}_${geotag}" >/dev/null &&
				printf '%s\n' "delete set inet $geotable trusted_${family}_${geotag}"
			eval "trusted=\"\$trusted_$family\""
			interval=
			case "${trusted%%":"*}" in net|ip)
				[ "${trusted%%":"*}" = net ] && interval="flags interval; auto-merge;"
				trusted="${trusted#*":"}"
			esac

			[ -n "$trusted" ] && {
				get_nft_family
				printf %s "add set inet $geotable trusted_${family}_${geotag} \
					{ type ${family}_addr; $interval elements={ "
				printf '%s,' $trusted
				printf '%s\n' " }; }"
				printf '%s\n' "insert $georule $nft_family saddr @trusted_${family}_${geotag} accept comment ${geotag_aux}_trusted"
			}
		done

		if [ "$geomode" = "whitelist" ]; then
			for family in $families; do
				if [ ! "$autodetect" ]; then
					eval "lan_ips=\"\$lan_ips_$family\""
				else
					a_d_failed=
					lan_ips="$(call_script "${i_script}-detect-lan.sh" -s -f "$family")" || a_d_failed=1
					[ ! "$lan_ips" ] || [ "$a_d_failed" ] && { echolog -err "$FAIL detect $family LAN subnets."; exit 1; }
					nl2sp lan_ips "net:$lan_ips"
					eval "lan_ips_$family=\"$lan_ips\""
				fi

				nft_get_geotable | grep "lan_ips_${family}_${geotag}" >/dev/null &&
					printf '%s\n' "delete set inet $geotable lan_ips_${family}_${geotag}"
				interval=
				[ "${lan_ips%%":"*}" = net ] && interval="flags interval; auto-merge;"
				lan_ips="${lan_ips#*":"}"
				[ -n "$lan_ips" ] && {
					get_nft_family
					printf %s "add set inet $geotable lan_ips_${family}_${geotag} \
						{ type ${family}_addr; $interval elements={ "
					printf '%s,' $lan_ips
					printf '%s\n' " }; }"
					printf '%s\n' "insert $georule $nft_family saddr @lan_ips_${family}_${geotag} accept comment ${geotag_aux}_lan"
				}
			done
			[ "$autodetect" ] && setconfig lan_ips_ipv4 lan_ips_ipv6
		fi

		[ "$geomode" = whitelist ] && [ "$ifaces" != all ] && {
			printf '%s\n' "insert $georule ip6 saddr fc00::/6 ip6 daddr fc00::/6 udp dport 546 counter accept comment ${geotag_aux}_DHCPv6"
			printf '%s\n' "insert $georule ip6 saddr fe80::/8 counter accept comment ${geotag_aux}_link-local"

		}

		for proto in tcp udp; do
			eval "ports_exp=\"\${${proto}_ports%:*}\" ports=\"\${${proto}_ports##*:}\""
			eval "proto_ports=\"\$${proto}_ports\""
			
			[ "$ports_exp" = skip ] && continue
			if [ "$ports_exp" = all ]; then
				ports_exp="meta l4proto $proto"
			else
				ports_exp="$proto $(printf %s "$ports_exp" | sed "s/multiport //;s/!dport/dport !=/") { $ports }"
			fi
			printf '%s\n' "insert $georule $ports_exp counter accept comment ${geotag_aux}_ports"
		done

		printf '%s\n' "insert $georule ct state established,related accept comment ${geotag_aux}_est-rel"

		[ "$geomode" = "whitelist" ] && [ "$ifaces" = all ] &&
			printf '%s\n' "insert rule inet $geotable $geochain iifname lo accept comment ${geotag_aux}-loopback"

		for new_ipset in $new_ipsets; do
			get_ipset_id "$new_ipset" || exit 1
			get_nft_family
			printf '%s\n' "add $georule $nft_family saddr @$new_ipset counter $iplist_verdict"
		done

		[ "$geomode" = whitelist ] && printf '%s\n' "add $georule counter drop comment ${geotag}_whitelist_block"

		[ "$noblock" = false ] && printf '%s\n' "add rule inet $geotable $base_geochain jump $geochain comment ${geotag}_enable"

		exit 0
	)" || die_a 254 "$FAIL assemble nftables commands."
	OK

	printf %s "Applying new firewall rules... "
	printf '%s\n' "$nft_cmd_chain" | nft -f - || die_a "$FAIL apply new firewall rules"
	OK

	[ "$noblock" = true ] && echolog -warn "Geoip blocking is disabled via config."

	echo

	:
}

restorebackup() {
	printf %s "Restoring ip lists from backup... "
	for list_id in $iplists; do
		bk_file="$bk_dir/$list_id.$bk_ext"
		iplist_file="$iplist_dir/${list_id}.iplist"

		[ ! -s "$bk_file" ] && rstr_failed "'$bk_file' is empty or doesn't exist."

		$extract_cmd "$bk_file" > "$iplist_file" || rstr_failed "$FAIL extract backup file '$bk_file'."
		[ ! -s "$iplist_file" ] && rstr_failed "$FAIL extract ip list for $list_id."
		line_cnt=$(wc -l < "$iplist_file")
		
	done
	OK

	[ "$restore_config" ] && { cp_conf restore || rstr_failed; }
	export main_config=

	rm_all_georules || rstr_failed "$FAIL remove firewall rules."

	call_script "${i_script}-apply.sh" add -l "$iplists"; apply_rv=$?
	rm "$iplist_dir/"*.iplist 2>/dev/null
	[ "$apply_rv" != 0 ] && rstr_failed "$FAIL restore the firewall state from backup." "reset"
	:
}

rm_rstr_tmp() {
	rm "$iplist_dir/"*.iplist 2>/dev/null
}

rstr_failed() {
	rm_rstr_tmp
	main_config=
	[ "$1" ] && echolog -err "$1"
	[ "$2" = reset ] && {
		echolog -err "*** Geoip blocking is not working. Removing geoip firewall rules. ***"
		rm_all_georules
	}
	die
}

rm_bk_tmp() {
	rm -f "$tmp_file" "$bk_dir/"*.new 2>/dev/null
}

bk_failed() {
	rm_bk_tmp
	die "$FAIL back up $p_name ip sets."
}

create_backup() {
	printf %s "Creating backup of $p_name ip sets... "
	getstatus "$status_file" || bk_failed
	for list_id in $iplists; do
		bk_file="${bk_dir}/${list_id}.${bk_ext:-bak}"
		iplist_file="$iplist_dir/${list_id}.iplist"
		eval "list_date=\"\$prev_date_${list_id}\""
		[ -z "$list_date" ] && bk_failed
		ipset="${list_id}_${list_date}_${geotag}"

		rm -f "$tmp_file" 2>/dev/null
		nft list set inet "$geotable" "$ipset" |
			sed -n -e /"elements[[:space:]]*=[[:space:]]*{"/\{ -e p\;:1 -e n\; -e p\; -e /\}/q\;b1 -e \} > "$tmp_file"
		[ ! -s "$tmp_file" ] && bk_failed

		[ "$debugmode" ] && bk_len="$(wc -l < "$tmp_file")"
		

		$compr_cmd < "$tmp_file" > "${bk_file}.new"; rv=$?
		[ "$rv" != 0 ] || [ ! -s "${bk_file}.new" ] && bk_failed
	done
	OK

	for f in "${bk_dir}"/*.new; do
		mv -- "$f" "${f%.new}" || bk_failed
	done
	:
}

geotable="$geotag"
base_geochain="GEOIP-BASE"
