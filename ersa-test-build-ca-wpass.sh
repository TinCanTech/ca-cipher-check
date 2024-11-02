#!/bin/sh

#set -x

# shellcheck disable=SC3045
# (warning): In POSIX sh, read -p is undefined.


die() {
	echo "FAILED: $1"
	cd "$start_dir" || echo "FAILED to restore dir: $start_dir"
	exit 1
}

# Run simple CA password test
run_easyrsa_ut() {
	begin="=====

BEGIN TEST:
 easyrsa: $1$
 openssl: $EASYRSA_OPENSSL"
	end="
END TEST:
 easyrsa: $1
 openssl: $EASYRSA_OPENSSL

====="

	# DISABLE easyrsa options by env vars only
	export EASYRSA_BATCH=
	export EASYRSA_SILENT=
	export EASYRSA_SILENT_SSL=

	# Check for automated password support
	no_auto_pass=
	"$1" help options | grep -q passin || no_auto_pass=1

	# Enable easyrsa options by env vars only
	export EASYRSA_BATCH=1
	export EASYRSA_SILENT=1
	export EASYRSA_SILENT_SSL=1

	# BEGIN TEST
	echo "$begin"
	"$1" init-pki

	# check for automated password support
	if [ "$no_auto_pass" ]; then
		# DISABLE
		#return

		# This check requires user password input
		echo "${NL}This version of EasyRSA does not support --passin"
		echo "ENTER PASSWORD REQUIRED"

		# Wait for confirmation
		echo "Please confirm or 'Ctrl-C' to quit: "
		[ "$do_all_test" ] || read -r -p "Run this test [y/N] ? " key
		if [ "$key" = y ] || [ "$do_all_test" ]; then
			"$1" build-ca || die "build-ca"

			# inspect_CA_key
			inspect_CA_key 
		else
			result_list="$result_list
$ersa_version | $ossl_version | Skipped.."
		fi
	else
		
		# Wait for confirmation
		#echo "Please confirm or 'Ctrl-C' to quit: "
		#read key

		# This check will auto-complete or error out
		"$1" --passin=pass:easyrsa --passout=pass:easyrsa \
			build-ca || die "build-ca"

			# inspect_CA_key
			inspect_CA_key 
	fi

	# cleanup
	[ "$keep_pki" ] || rm -rf "${EASYRSA_PKI:?}"

	# End of this test
	echo "$end"
}

# Test the CA
inspect_CA_key() {
	ca_key="$EASYRSA_PKI"/private/ca.key
	if [ -f "$ca_key" ]; then
		: # ok
	else
		result_list="$result_list
$ersa_version | $ossl_version | Error: Missing CA key"

		echo "CA Key: '$ca_key'"
		read -r -p "Press enter to continue.." key
		return
	fi

	key_error=
	key_cipher=
	if "$EASYRSA_OPENSSL" asn1parse -in "$ca_key" 1>/dev/null
	then
		if "$EASYRSA_OPENSSL" asn1parse -in "$ca_key" | \
				grep -q des-ede3-cbc
		then
			key_error="Cipher: des-ede3-cbc"
		else
			if "$EASYRSA_OPENSSL" asn1parse -in "$ca_key" | \
					grep -q aes-256-cbc
			then
				key_cipher="GOOD aes-256-cbc"
			else
				key_error="Unknown cipher!"
			fi
		fi
	else
		key_error="Failed asn1parse"
	fi

	if [ "$key_error" ]; then
		result_list="$result_list
$ersa_version | $ossl_version | Error: $key_error"
	else
		result_list="$result_list
$ersa_version | $ossl_version | $key_cipher"
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
start_dir="$PWD"
ERSA_ARC_D="${ERSA_ARC_D:-/home/tct/git/easy-rsa}"
OSSL_ARC_D="${OSSL_ARC_D:-/home/tct/openssl}"

do_all_test=
keep_pki=
while [ "$1" ]; do
	case "$1" in
		all)
			do_all_test=1 ;;
		keep)
			keep_pki=1 ;;
		*)
			echo "Unknown option: '$1'"
			exit 1
	esac
	shift
done

#TCT_EASYRSA_UT_D="${TCT_EASYRSA_UT_D:-/home/tct/git/easy-rsa/easyrsa-unit-tests/master}"
#TCT_EASYRSA_UT_BIN="$TCT_EASYRSA_UT_D"/easyrsa-unit-test.sh

[ -d "$ERSA_ARC_D" ] || die "Missing ERSA_ARC_D: '$ERSA_ARC_D'"
[ -d "$OSSL_ARC_D" ] || die "Missing OSSL_ARC_D: '$OSSL_ARC_D'"

for i in $(find_ersa_d); do
	[ -d "$i" ] && ersa_list="${ersa_list}${NL}${i}"
done

# Find OpenSSL archives
ossl_list=
for i in $(find_ossl_d); do
	[ -d "$i" ] && ossl_list="${ossl_list}${NL}${i}"
done

ersa_list_sort="$(echo "$ersa_list" | sort -g)"
ossl_list_sort="$(echo "$ossl_list" | sort -g)"

echo "ersa_list_sort: $ersa_list_sort${NL}"
echo "ossl_list_sort: $ossl_list_sort${NL}"
read -r -p "Press enter to continue.." key
result_list=

# Run test
for p in $ersa_list_sort; do
	[ "$p" = "$ERSA_ARC_D" ] && continue
	ersa_version="${p##*/}"
	cd "$p" || die "cd $p"
	ersa_dir="$p"
	ersa_bin="$p"/easyrsa
	[ -f "$ersa_bin" ] || die "missing ersa_bin: $ersa_bin"

	for q in $ossl_list_sort; do
		[ "$q" = "$OSSL_ARC_D" ] && continue
		ossl_version="${q##*/}"
		pki_name="${ossl_version##*-}"
		ossl_bin="${q}/apps/openssl"
		if [ -f "$ossl_bin" ]; then
			export EASYRSA_OPENSSL="$ossl_bin"

			# allow ignore EasyRSA-3.0.9 and 3.0.7
			if [ "$ersa_version" = EasyRSA-3.0.9 ] || \
				[ "$ersa_version" = EasyRSA-3.0.8 ] || \
				[ "$ersa_version" = EasyRSA-3.0.7 ]
			then
				echo "${NL}***** NOTICE: $ersa_version"
				echo "              $ossl_version"
				echo "EasyRSA will ask for CA password, due to this bug!"
				[ "$do_all_test" ] || read -r -p "Run this test [y/N] ? " key
				if [ ! "$key" = y ] && [ -z "$do_all_test" ]; then
					result_list="$result_list
$ersa_version | $ossl_version | Skipped.."
					continue
				fi
			fi

			# Use a custom test PKI
			export EASYRSA_PKI="${ersa_dir}/ossl-${pki_name}"
			run_easyrsa_ut "$ersa_bin" "$ossl_bin"
		else
			echo "missing ossl_bin: $ossl_bin"
			#read key
		fi
	done
		result_list="$result_list${NL}"
done

# shellcheck disable=SC2181 # (style): Check exit code directly
[ $? = 0 ] || echo "Unexpected error occured!"

echo "Result:"
echo "$result_list"

echo "${NL}==[ Complete ]=="

