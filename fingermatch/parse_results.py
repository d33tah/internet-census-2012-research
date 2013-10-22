#!/usr/bin/env python

import sys

# Create a dictionary where line number is a key and the fingerprint as the
# value
fingerprints = dict(enumerate(open('nmap-os-db').readlines()))

results = {}
for line in sys.stdin.readlines():
  columns = line.split()
  num_devices = int(columns[0])
  line_number = int(columns[1])-1
  fingerprint_name = fingerprints[line_number]
  fingerprint_name = fingerprint_name.lstrip("Fingerprint ")
  fingerprint_name = fingerprint_name.rstrip("\r\n")
  if not fingerprint_name in results:
    results[fingerprint_name] = num_devices
  else:
    results[fingerprint_name] += num_devices

results = reversed(sorted(results.iteritems(), key=lambda k: k[1]))
for fingerprint_name, num_devices in results:
  print("%s\t%s" % (num_devices, fingerprint_name))
