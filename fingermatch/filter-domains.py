#!/usr/bin/pypy

"""
filter-domains.py - reads domain names from standard input and groups them by
TLD and second-level domain. The first column in the output is the number of
the domains that belong to the group, then there's a tab and the group name.
If there is only one domain, it is displayed without truncation.
"""

import sys
import collections
import argparse

parser = argparse.ArgumentParser()

parser.add_argument('path-to-slds-file',
                    help='Path to SLDs.csv file',
                    default='SLDs.csv')

parser.add_argument('--print-ips',
                    help='Print the IP addresses for the domains',
                    action='store_true')
args = parser.parse_args()
args_dict = vars(args)

domains = collections.defaultdict(list)
raw_domains = []

# get the SLDs.csv file from here:
# https://raw.github.com/gavingmiller/second-level-domains/
slds = []
for sld_line in open(args_dict['path-to-slds-file']).readlines():
  sld_columns = sld_line.split(',')
  slds += [sld_columns[1].rstrip('\r\n').lstrip('.')]

for line in sys.stdin.readlines():
  try:
    ip, domain = line.rstrip('\n').split()
  except:
    sys.exit("Invalid line: %s" % line)
  raw_domains += [domain]
  domain_short = domain.split('.')[-2:]
  key = '.'.join(domain_short)
  if key in slds:
    domain_short = domain.split('.')[-3:]
    key = '.'.join(domain_short)
  domains[key] += [ip]

for k, v in reversed(sorted(domains.items(), key=lambda x: len(x[1]))):
  if len(v) == 1:
    k = [domain for domain in raw_domains if domain.endswith(k)][0]
  if args.print_ips:
    print("%s\t%s\t%s" % (len(v), k, v))
  else:
    print("%s\t%s" % (len(v), k))
