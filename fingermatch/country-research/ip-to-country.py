#!/usr/bin/python

import os
import iptools
from collections import defaultdict

by_country_list = defaultdict(list)

for filename in os.listdir("csv"):
  country = filename.split('.csv')[0]
  for line in open("csv" + os.sep + filename).readlines():
    line = line.rstrip('\r\n')
    if line == '':
      continue
    columns = line.split(',')
    start = columns[0]
    end = columns[1]
    by_country_list[country] += [iptools.IpRange(start, end)]

#by_country = { k : iptools.IpRangeList(v) for k, v in by_country_list.items() }

by_country = defaultdict(iptools.IpRangeList)
for k, v in by_country_list.items():
  by_country[k].ips = by_country_list[k]

print("done")
while True:
  a = raw_input()
  for k, v in by_country.items():
    if a in v:
      print(k)
