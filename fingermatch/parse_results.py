#!/usr/bin/python

"""
Reads the uncompressed run-research.sh output from
the standard input, extract and count the perfect matches and print the
results to the standard output.

For a speedup, run this under pypy.
"""

import sys
import argparse
import re

# for ip_to_u32
import socket
import struct

from fputils import print_stderr, percent_type

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--names', action='store_true', default=True,
                    help='group by names instead of line numbers')
parser.add_argument('--count_duplicates', action='store_true', default=False,
                    help='count duplicate hits of the results')
parser.add_argument('--first-word', action='store_true', default=False,
                    help='group the results by first word in fingerprint'
                    '(implies --names)')
parser.add_argument('--percentage', default=100, type=percent_type,
                    metavar='N',
                    help='minimum percentage needed to count the result')
parser.add_argument('--regex-group', default='', metavar='r1,r2', help='group '
                    'the results by comma-separated regular expressions '
                    '(case insensitive; example: Microsoft|Windows,BSD)')
args = parser.parse_args()
if args.first_word:
    args.names = True

regexes = []
if args.regex_group:
    args.names = True
    for regex in args.regex_group.split(','):
      regexes += [re.compile(regex, flags=re.IGNORECASE)]

if sys.stdin.isatty():
  sys.exit("ERROR: %s: the script expects feeder.py output as its "
           "standard input." % sys.argv[0])

if args.names:
  # Create a dictionary where line number is a key and the fingerprint as the
  # value
  f = open("nmap-os-db")
  line = f.readline()
  lineno = 0
  fingerprints = {}
  while line != '':
    if line.startswith("Fingerprint "):
      line = line[len("Fingerprint "):]
      line = line.rstrip("\r\n")
      fingerprints[lineno] = line
    line = f.readline()
    lineno += 1


def ip_to_u32(ip):
    """
    Translate an IP address to little endian unsigned 32-bit integer. This way
    I could save some memory, storing the integer in the dictionary instead of
    the string.
    """
    return struct.unpack("<I", socket.inet_aton(ip))[0]

results = {}
long_results = {}
if args.count_duplicates:
  ip_counts = {}
  duplicates = 0
for line in sys.stdin:
  columns = line.rstrip("\r\n").split()
  if len(columns) < 3:
    matches_column = ''
    matches = []
  else:
    matches_column = columns[2]
    if matches_column == '?':
      matches = []
    else:
      matches = matches_column.split(',')

  ip = ip_to_u32(columns[0])
  checked_hash = hash(matches_column)
  if args.count_duplicates:
    if ip in ip_counts and ip_counts[ip] == checked_hash:
      duplicates += 1
      continue
    elif matches_column not in ['?', '']:
      ip_counts[ip] = checked_hash

  for match in matches:
    line_number, percentage = map(int, match.rstrip(']').split('['))
    if percentage < args.percentage:
      continue
    score = 1
    if args.names:
      fingerprint_name = fingerprints[line_number - 1]
      if args.first_word:
        key = fingerprint_name.split()[0]
      else:
        key = fingerprint_name
      for regex in regexes:
        if regex.search(fingerprint_name):
          key = regex.pattern
      if not fingerprint_name in long_results:
        long_results[fingerprint_name] = score
      else:
        long_results[fingerprint_name] += score
    else:
      key = line_number
    if not key in results:
      results[key] = score
    else:
      results[key] += score

if args.count_duplicates:
  print_stderr("%s duplicates found" % duplicates)

results = list(reversed(sorted(results.iteritems(), key=lambda k: k[1])))
num_devices_sum = sum([i[1] for i in results])
for fingerprint_line, num_devices in results:
  if args.names and args.first_word:
    long_matches = None
    long_name = None
    long_matches_count = 0
    for key in long_results:
      if key.split()[0] == fingerprint_line:
        long_matches = long_results[key]
        long_name = key
        long_matches_count += 1
    if long_name is not None and long_matches == num_devices:
      fingerprint_line = long_name
    elif long_matches_count > 1:
      fingerprint_line += " [%s]" % long_matches_count
  percentage = float(num_devices) / num_devices_sum * 100
  print("%09s (%0.6f%%)\t%s" % (num_devices, percentage, fingerprint_line))
