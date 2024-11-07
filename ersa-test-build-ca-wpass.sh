#!/bin/sh

#set -x

# exit with error
die() {
	echo "FAILED: $1"
	cd "$start_dir" || echo "FAILED to restore dir: $start_dir"
	exit 1
}

# user confirmation
confirm() {
	echo "$1"
	read -r key
}

# Update result list
update_result_list() {
	echo "$1"
	result_list="$result_list
$ersa_version | $ossl_version | $alg | $1"
}

# Run simple CA password test
run_easyrsa_ut() {
	# reset per pass env-vars
	unset -v EASYRSA_ALGO EASYRSA_CURVE \
		EASYRSA_BATCH EASYRSA_SILENT EASYRSA_SILENT_SSL

	# Check for automated password support
	if "$1" help options | grep -q passin
	then
		no_auto_pass=
	else
		no_auto_pass=1
	fi

	case "$3" in
		rsa)
			echo "GOOD algo: $3"
		;;
		ec)
			echo "Test for algo support: $3"
			if "$1" help options | grep -q -e '--use-algo.*ec'
			then
				if "$EASYRSA_OPENSSL" ecparam \
						-name secp384r1 \
							1>/dev/null
				then
					export EASYRSA_CURVE=secp384r1
					echo "GOOD algo: $3 = $EASYRSA_CURVE"
				else
					die "\
OpenSSL failed to generate ecparam file for curve 'secp384r1'"
				fi
			else
				update_result_list "easyrsa: '$3' not supported"

				# non-fatal error
				return 1
			fi
		;;
		ed)
			echo "Test for algo support: $3"
			if "$1" help options | grep -q -e '--use-algo.*ed'
			then
				#shellcheck disable=SC3037 # In POSIX sh, echo flags are undefined
				echo -n "OpenSSL: "
				if "$EASYRSA_OPENSSL" genpkey \
						-algorithm ed25519 \
							1>/dev/null
				then
					export EASYRSA_CURVE=ed25519
					echo "GOOD algo: $3 = $EASYRSA_CURVE"
				else
					update_result_list "openssl: 'ed25519' not found"

					# non-fatal error
					return 1
				fi
			else
				update_result_list "easyrsa: $3 not supported"

				# non-fatal error
				return 1
			fi
		;;
		*)
			die "wtf?"
	esac

	export EASYRSA_ALGO="$3"


		# allow ignore EasyRSA-3.0.9 and 3.0.7
		if [ "$ersa_version" = EasyRSA-3.0.9 ] || \
			[ "$ersa_version" = EasyRSA-3.0.8 ] || \
			[ "$ersa_version" = EasyRSA-3.0.7 ]
		then
			echo "${NL}***** NOTICE: $ersa_version"
			echo "              $ossl_version"
			echo "EasyRSA will ask for CA password, due to this bug!"
			[ "$do_all_test" ] || confirm "Run this test [y/N] ? "

			if [ ! "$key" = y ] && [ -z "$do_all_test" ]; then
				update_result_list "Skipped.."

				# non-fatal error
				return 1
			fi
		fi


	# Enable easyrsa options
	dash_s=1
	dash_S=1
	"$1" -s >/dev/null 2>&1 || dash_s=
	"$1" -S >/dev/null 2>&1 || dash_S=
	#unset -v dash_s dash_S

	# check for automated password support and RUN the TEST
	if [ "$no_auto_pass" ]; then

		# This check requires user password input
		echo "${NL}This version of EasyRSA does not support --passin"
		echo "ENTER PASSWORD REQUIRED"

		# Wait for confirmation
		echo "Please confirm or 'Ctrl-C' to quit: "
		[ "$do_all_test" ] || confirm "Run this test [y/N] ? "

		if [ "$key" = y ] || [ "$do_all_test" ]; then

			# BEGIN manual TEST
			"$1" --batch ${dash_s:+ -s} ${dash_S:+ -S} \
					init-pki || die "init-pki"
			"$1" --batch ${dash_s:+ -s} ${dash_S:+ -S} \
					build-ca || die "build-ca"

			update_result_list "manual build-ca OK"

			# inspect_CA_key
			inspect_CA_key 

			# change pass
			if "$1" set-rsa-pass ca; then
				update_result_list "manual set-rsa-pass OK"

				# inspect_CA_key
				inspect_CA_key
			else
				update_result_list "manual set-rsa-pass Failed"
			fi
		else
			update_result_list "easyrsa: No --passin"
		fi
	else
		# BEGIN automated TEST
		"$1" --batch ${dash_s:+ -s} ${dash_S:+ -S} \
				init-pki || die "init-pki"
		"$1" --batch ${dash_s:+ -s} ${dash_S:+ -S} \
				--passin=pass:"$in_pass" \
				--passout=pass:"$out_pass" \
				build-ca || die "build-ca"

		update_result_list "auto build-ca OK"

		# inspect_CA_key
		inspect_CA_key

		# change pass
		if "$1" --passin=pass:"$in_pass" \
				--passout=pass:"$new_pass" \
				--batch ${dash_s:+ -s} ${dash_S:+ -S} \
				set-rsa-pass ca
		then
			update_result_list "auto set-rsa-pass OK"

			# inspect_CA_key
			inspect_CA_key
		else
			update_result_list "auto set-rsa-pass Failed"

			echo "Testing easyrsa for incorrect error exit!"
			if "$1" --passin=pass:"$in_pass" \
					--passout=pass:"$new_pass" \
					--batch ${dash_s:+ -s} ${dash_S:+ -S} \
					set-rsa-pass ca
			then
				update_result_list "Second auto set-rsa-pass OK"

			else
				update_result_list "Second auto set-rsa-pass Failed"

				if "$EASYRSA_OPENSSL" "$EASYRSA_ALGO" \
					-noout -passin pass:"$new_pass" \
					-in "$EASYRSA_PKI"/private/ca.key
				then
					update_result_list "OpenSSL passed the CA key OK"

					# inspect_CA_key
					inspect_CA_key

				else
					update_result_list "OpenSSL Failed to passed the CA key"
				fi # new_pass
			fi # change pass 2
		fi # change pass
	fi # no_auto_pass

	# cleanup
	[ "$keep_pki" ] || rm -rf "${EASYRSA_PKI:?}"

	# End of this test
}

# Test the CA
inspect_CA_key() {
	ca_key="$EASYRSA_PKI"/private/ca.key
	if [ -f "$ca_key" ]; then
		: # ok
	else
		#update_result_list "Error: Missing CA key"
		die "Missing CA Key: '$ca_key'"
	fi

	key_error=
	key_cipher=
	if "$EASYRSA_OPENSSL" asn1parse -in "$ca_key" 1>/dev/null 2>&1
	then
		if "$EASYRSA_OPENSSL" asn1parse -in "$ca_key" | \
				grep -q des-ede3-cbc
		then
			key_error="Cipher: des-ede3-cbc"
		else
			if "$EASYRSA_OPENSSL" asn1parse -in "$ca_key" | \
					grep -q aes-256-cbc
			then
				key_cipher="GOOD: aes-256-cbc"
			else
				key_error="Unknown cipher!"
			fi
		fi
	else
		key_error="Failed asn1parse"
	fi

	if [ "$key_error" ]; then
		update_result_list "ERROR: $key_error"
	else
		update_result_list "$key_cipher"
	fi
}

# verify CA password is correct
verify_ca_pass() {
	if "$EASYRSA_OPENSSL" "$EASYRSA_ALGO" \
		-noout -passin pass:"$new_pass" \
		-in "$EASYRSA_PKI"/private/ca.key
	then
		update_result_list "OpenSSL passed the CA key OK"
		return
	else
		update_result_list "OpenSSL Failed to pass the CA key"
		return 1
	fi
}

# Find openssl versions
find_ersa_d() {
	find "$ERSA_ARC_D" -maxdepth 1 -name "*EasyRSA*"
}

# Find openssl versions
find_ossl_d() {
	find "$OSSL_ARC_D" -maxdepth 1 -name "*openssl*"
}

# Setup
NL='
'
in_pass='pppp'
out_pass='pppp'
new_pass='mmmm'
result_list=

# TODO: remove $start_dir
start_dir="$PWD"

# EasyRSA archive
ERSA_ARC_D="${ERSA_ARC_D:-/home/tct/git/easy-rsa}"
[ -d "$ERSA_ARC_D" ] || die "Missing ERSA_ARC_D: '$ERSA_ARC_D'"
#openssl archive
OSSL_ARC_D="${OSSL_ARC_D:-/home/tct/openssl}"
[ -d "$OSSL_ARC_D" ] || die "Missing OSSL_ARC_D: '$OSSL_ARC_D'"

# Options
do_all_test=
keep_pki=
while [ "$1" ]; do
	case "$1" in
		all)
			do_all_test=1 ;;
		keep)
			keep_pki=1 ;;
		*)
			die "Unknown option: '$1'"
	esac
	shift
done

# Find EasyRSA archives
for i in $(find_ersa_d); do
	[ -d "$i" ] && ersa_list="${ersa_list}${NL}${i}"
done

# Find OpenSSL archives
ossl_list=
for i in $(find_ossl_d); do
	[ -d "$i" ] && ossl_list="${ossl_list}${NL}${i}"
done

# Sort lists
ersa_list_sort="$(echo "$ersa_list" | sort -g)"
ossl_list_sort="$(echo "$ossl_list" | sort -g)"

# Show test matrix
echo "ersa_list_sort: $ersa_list_sort${NL}"
echo "ossl_list_sort: $ossl_list_sort${NL}"
confirm "Press enter to continue.."

# Run test
# EasyRSA sources
for p in $ersa_list_sort; do
	[ "$p" = "$ERSA_ARC_D" ] && continue
	ersa_version="${p##*/}"
	cd "$p" || die "cd $p"
	ersa_dir="$p"
	ersa_bin="$p"/easyrsa
	[ -f "$ersa_bin" ] || die "missing ersa_bin: $ersa_bin"

	# openssl sources
	for q in $ossl_list_sort; do
		[ "$q" = "$OSSL_ARC_D" ] && continue
		ossl_version="${q##*/}"
		pki_name="${ossl_version##*-}"
		ossl_bin="${q}/apps/openssl"

		[ -f "$ossl_bin" ] || die "missing ossl_bin: $ossl_bin"
		export EASYRSA_OPENSSL="$ossl_bin"

		# Chuck in algo for good measure
		#for alg in rsa ec ed; do
		alg=rsa

			begin="=====

BEGIN TEST:
    algo: $alg
 easyrsa: $ersa_bin
 openssl: $EASYRSA_OPENSSL${NL}"

	end="
END TEST:
    algo: $alg
 easyrsa: $ersa_bin
 openssl: $EASYRSA_OPENSSL

====="
			# Use a custom test PKI
			export EASYRSA_PKI="${ersa_dir}/ossl-${pki_name}-$alg"

			# run test
			echo "$begin"
			if run_easyrsa_ut "$ersa_bin" "$ossl_bin" "$alg"
			then
				echo "Successfully completed."
			else
				echo "Test abandoned!"
			fi
			result_list="$result_list${NL}"

			echo "$end"
		#done # alg

	done # openssl
	result_list="$result_list${NL}"

done # EsyRSA

# shellcheck disable=SC2181 # (style): Check exit code directly
[ $? = 0 ] || die "Unexpected error occured!"

echo "Result:"
echo "$result_list"

echo "${NL}==[ Complete ]=="
