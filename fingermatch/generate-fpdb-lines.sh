#!/bin/sh

# Extracts a regular expression with line numbers from nmap-os-db related to
# the particular vendor.

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <path-to-nmap-os-db> <os-name-regex>"
  exit 1;
fi

echo -n `grep -n '^Fingerprint' $1 | \
  grep -i $2 | \
  awk -F ':' '{ print $1 }'` | sed 's/ /\\[100\\]|/g'
