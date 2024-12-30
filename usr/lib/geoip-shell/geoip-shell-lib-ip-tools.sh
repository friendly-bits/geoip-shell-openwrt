#!/bin/sh

curr_ver=0.6.8

# Copyright: antonk (antonk.d3v@gmail.com)
# github.com/friendly-bits

ip_to_int() {
	ip_itoint="$1"
	family_itoint="$2"
	ip2int_maskbits="$3"
	out_var_itoint="$4"

	case "$family_itoint" in ipv4|inet)
		bits_trim=$((32-ip2int_maskbits))

		newifs "." itoint
		set -- $ip_itoint

		IFS=" "
		for octet in "$1" "$2" "$3" "$4"; do
			case "$octet" in
				[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]) ;;
				*)
					echolog -err "ip_to_int: invalid octet '$octet'"
					oldifs itoint
					return 1
			esac
		done

		oldifs itoint
		ip2int_conv_exp="(($1<<24) + ($2<<16) + ($3<<8) + $4)>>$bits_trim<<$bits_trim"
		eval "$out_var_itoint=$(( $ip2int_conv_exp ))"
		return 0
	esac

	newifs ":" itoint
	set -- $ip_itoint
	oldifs itoint

	bits_processed=0
	chunks_done=0

	missing_chunks=$((8-$#))
	ip_itoint=
	for chunk in "$@"; do
		case "${chunk}" in '')
			missing_chunks=$((missing_chunks+1))
			while :; do
				case $missing_chunks in 0) break; esac

				bits_processed=$(( bits_processed + 16 ))
				chunks_done=$((chunks_done+1))
				ip_itoint="${ip_itoint}0 "

				case $(( ip2int_maskbits - bits_processed )) in 0|-*) break 2; esac

				missing_chunks=$((missing_chunks-1))
			done
			continue ;;
		esac

		case "$chunk" in
			????|???|??|?) ;;
			*)
				echolog -err "ip_to_int: invalid chunk '$chunk'"
				return 1
		esac

		case "$chunk" in
			*[!a-f0-9]*)
				echolog -err "ip_to_int: invalid chunk '$chunk'"
				return 1
		esac

		bits_processed=$(( bits_processed + 16 ))
		chunks_done=$((chunks_done+1))

		case $(( ip2int_maskbits - bits_processed )) in
			0)
				ip_itoint="${ip_itoint}$(( 0x${chunk} )) "
				break ;;
			-*)
				bits_trim=$(( bits_processed - ip2int_maskbits ))
				ip_itoint="${ip_itoint}$(( 0x${chunk}>>bits_trim<<bits_trim )) "
				break ;;
			*)
				ip_itoint="${ip_itoint}$(( 0x${chunk} )) "
		esac
	done

	while :; do
		case $(( 8 - chunks_done )) in 0) break; esac
		ip_itoint="${ip_itoint}0 "
		chunks_done=$(( chunks_done + 1 ))
	done

	eval "$out_var_itoint=\"$ip_itoint\""

	:
}

int_to_ip() {
	case "$3" in
		'') maskbits_iti='' ;;
		*) maskbits_iti="/$3"
	esac

	case "$2" in
		ipv4|inet)
			printf '%s\n' "$(( ($1>>24)&255 )).$(( ($1>>16)&255 )).$(( ($1>>8)&255 )).$(($1 & 255))${maskbits_iti}" ;;
		ipv6|inet6)
			set -- $1
			printf ':%x' $* |

			{
				hex_to_ipv6 || exit 1
				printf '%s\n' "${maskbits_iti}"
			}
	esac || return 1
	:
}

hex_to_ipv6() {
	IFS='' read -r ip_hti
	IFS=' '
	for zeroes in ":0:0:0:0:0:0:0:0" ":0:0:0:0:0:0:0" ":0:0:0:0:0:0" ":0:0:0:0:0" ":0:0:0:0" ":0:0:0" ":0:0"; do
		case "$ip_hti" in *$zeroes*)
			ip_hti="${ip_hti%%"$zeroes"*}::${ip_hti#*"$zeroes"}"
			break
		esac
	done

	case "$ip_hti" in *:::*) ip_hti="${ip_hti%%:::*}::${ip_hti#*:::}"; esac

	case "$ip_hti" in
        :[!:]*) ip_hti="${ip_hti#:}"
	esac

	printf %s "${ip_hti}"
}

aggregate_subnets() {
	inv_maskbits() {
		printf '%s\n' "aggregate_subnets: invalid mask bits '$1'" >&2
	}

	family_ags="$1"
	case "$1" in
		ipv4|inet) ip_len_bits=32 ;;
		ipv6|inet6) ip_len_bits=128 ;;
		*) echolog -err "aggregate_subnets: invalid family '$1'."; return 1
	esac

	res_ips_int="${_nl}"
	processed_maskbits=' '
	nonempty_ags=

	while IFS="$_nl" read -r subnet_ags; do
		case "$subnet_ags" in
			'') continue ;;
			*/*) maskbits="${subnet_ags##*/}" ;;
			*) maskbits=$ip_len_bits
		esac
		printf '%s\n' "${maskbits}/${subnet_ags%/*}"
	done |

	{
		sort -n
		printf '%s\n' EOF_AGS
	} |

	while IFS="$_nl" read -r subnet1; do
		case "$subnet1" in
			'') continue ;;
			EOF_AGS)
				[ "$nonempty_ags" ] && exit 254 # 254 means OK here
				exit 1
		esac

		maskbits="${subnet1%/*}"
		case "$maskbits" in *[!0-9]*)
			inv_maskbits "$maskbits"
			exit 1
		esac

		case "$maskbits" in ?|??|???) ;; *)
			inv_maskbits "$maskbits"
			exit 1
		esac

		case $((ip_len_bits-maskbits)) in -*)
			inv_maskbits "$maskbits"
			exit 1
		esac

		ip1_ags="${subnet1#*/}"

		ip_to_int "$ip1_ags" "$family_ags" "$maskbits" ip1_int || exit 1

		IFS=' '
		bits_processed=0
		ip1_trim=
		set -- $ip1_int
		chunk=
		for mb in $processed_maskbits; do
			chunks_done_last=0

			case "$family_ags" in
				ipv4|inet)
					bits_trim=$((32-mb))
					ip1_trim=$(( ip1_int>>bits_trim<<bits_trim )) ;;
				ipv6|inet6)
					for chunk in "$@"; do
						case $(( mb - (bits_processed+16) )) in
							0)
								bits_processed=$(( bits_processed + 16 ))
								chunks_done_last=$(( chunks_done_last + 1 ))
								ip1_trim="${ip1_trim}${chunk}"
								chunk=
								break ;;
							-*)
								bits_trim=$(( bits_processed + 16 - mb ))
								chunk=$(( chunk>>bits_trim<<bits_trim ))
								break ;;
							*)
								bits_processed=$(( bits_processed + 16 ))
								chunks_done_last=$(( chunks_done_last + 1 ))
								ip1_trim="${ip1_trim}${chunk} "
						esac
					done
			esac

			shift $chunks_done_last
			case "$res_ips_int" in *"${_nl}${ip1_trim}${chunk} "*) continue 2; esac
		done

		res_ips_int="${res_ips_int}${ip1_int} ${_nl}"

		case "$processed_maskbits" in *" $maskbits "*) ;; *)
			processed_maskbits="${processed_maskbits}${maskbits} "
		esac

		int_to_ip "$ip1_int" "$family_ags" "$maskbits" || {
			echolog -err "$FAIL convert '$ip1_int' to ip."
			exit 1
		}
		nonempty_ags=1
	done

	case $? in
		254) return 0 ;;
		*) cat >/dev/null; return 1
	esac
}

detect_lan_subnets() {
	case "$1" in
		ipv4|inet)
			case "$subnet_regex_ipv4" in '') echolog -err "detect_lan_subnets: regex is not set"; return 1; esac
			ifaces="dummy_123|$(
				ip -f inet route show table local scope link |
				sed -n '/[ 	]lo[ 	]/d;/[ 	]dev[ 	]/{s/.*[ 	]dev[ 	][ 	]*//;s/[ 	].*//;p}' | tr '\n' '|')"
			ip -o -f inet addr show | grep -E "${ifaces%|}" | grep -oE "$subnet_regex_ipv4" ;;
		ipv6|inet6)
			case "$subnet_regex_ipv6" in '') echolog -err "detect_lan_subnets: regex is not set"; return 1; esac
			ip -o -f inet6 addr show |
				grep -oE 'inet6[ 	]+(fd[0-9a-f]{0,2}:|fe80:)[0-9a-f:/]+' | grep -oE "$subnet_regex_ipv6\$" ;;
		*) echolog -err "detect_lan_subnets: invalid family '$1'."; return 1
	esac
}

get_lan_subnets() {
	detect_lan_subnets "$1" |
	aggregate_subnets "$1" || { echolog -err "$FAIL detect $1 LAN subnets."; return 1; }
}

:
