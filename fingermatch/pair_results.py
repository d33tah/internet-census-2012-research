#!/usr/bin/env python

import sys

# Create a dictionary where line number is a key and the fingerprint as the
# value
fingerprints = dict(enumerate(open('nmap-os-db').readlines()))

for line in sys.stdin.readlines():
  columns = line.split()
  line_number = int(columns[1])-1
  fingerprint_name = fingerprints[line_number]
  fingerprint_name = fingerprint_name.lstrip("Fingerprint ")
  fingerprint_name = fingerprint_name.rstrip("\r\n")
  columns += [fingerprint_name]
  print('\t'.join(columns))
