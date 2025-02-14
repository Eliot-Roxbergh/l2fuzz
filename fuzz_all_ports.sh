#!/bin/bash
# Fuzz all open L2CAP ports on a target bluetooth address
readonly services_file="l2fuzz_open_ports.tmp"

# $1 should be a valid bluetooth address
if [ -z "$1" ]; then
	echo "First argument should be Bluetooth address of target (in format 00:FF:00:FF:00:FF)"
	echo "$0 00:FF:00:FF:00:FF"
	exit 1
fi
bt_addr="$1"

rm "$services_file" 2> /dev/null

# Discover all open L2CAP services using both manual connect and as reported by SDP
python3 l2fuzz.py "$bt_addr" scan-only

if [ $? -ne 0 ]; then
	echo "l2fuzz failed, see its print out for more info"
	exit 1
fi

# Read file generated by
#  python3 l2fuzz.py <bt_addr> scan-only
read -r -a services < "$services_file"


# Fuzz each open port on target
for item in "${services[@]}"; do
	python3 l2fuzz.py "$bt_addr" $item
done
