#!/bin/sh

# Filters out a list of IP addresses and timestamps that should carry the
# fingerprints of a specific vendor.

MATCHED_FILE="somefile.lzma"
OSNAME="microsoft"  # just an example.

pv $MATCHED_FILE | \
  lzma -d | \
  egrep `./generate-fpdb-lines.sh nmap-os-db $OSNAME` | \
  awk '{ printf "%s\t%s", $1, $2 }' | \
  sort | \
  uniq
