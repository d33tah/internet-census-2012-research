#!/usr/bin/python

# parse_results.py - read the uncompressed run-research.sh output from
# the standard input, extract and count the perfect matches and print the
# results to the standard output.
#
# For a 5x speedup, run this under pypy.

import sys

# Create a dictionary where line number is a key and the fingerprint as the
# value
fingerprints = dict(enumerate(open('nmap-os-db').readlines()))

results = {}
for line in sys.stdin:
  columns = line.rstrip("\r\n").split()
  try:
    matches = columns[2].split(',')
  except:
    continue
  for match in matches:
    if match.find('[100]') != -1:
      try:
        line_number = int(match.replace('[100]', ''))
      except:
        continue
      fingerprint_name = fingerprints[line_number-1]
      if fingerprint_name.find("Fingerprint") == -1:
        sys.exit(line)
      fingerprint_name = fingerprint_name.lstrip("Fingerprint ")
      fingerprint_name = fingerprint_name.rstrip("\r\n")
#      key = line_number
      key = fingerprint_name
      if not key in results:
        results[key] = 1
      else:
        results[key] += 1

results = reversed(sorted(results.iteritems(), key=lambda k: k[1]))
for fingerprint_line, num_devices in results:
  print("%s\t%s" % (num_devices, fingerprint_line))
