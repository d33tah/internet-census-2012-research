#!/usr/bin/python

"""
filter-domains.py - reads domain names from standard input and groups them by
TLD and second-level domain. The first column in the output is the number of
the domains that belong to the group, then there's a tab and the group name.
If there is only one domain, it is displayed without truncation.
"""

import sys
import collections

domains = collections.defaultdict(int)
raw_domains = []

# get the SLDs.csv file from here:
# https://raw.github.com/gavingmiller/second-level-domains/
slds = []
for sld_line in open("SLDs.csv").readlines():
  sld_columns = sld_line.split(',')
  slds += [sld_columns[1].rstrip('\r\n').lstrip('.')]

for line in sys.stdin.readlines():
  domain = line.rstrip('\n')
  raw_domains += [domain]
  domain_short = domain.split('.')[-2:]
  key = '.'.join(domain_short)
  if key in slds:
    domain_short = domain.split('.')[-3:]
    key = '.'.join(domain_short)
  domains[key] += 1

for k, v in reversed(sorted(domains.items(), key=lambda x: x[1])):
  if v == 1:
    k = [domain for domain in raw_domains if domain.endswith(k)][0]
  print("%s\t%s" % (v, k))
