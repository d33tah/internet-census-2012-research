#!/usr/bin/pypy

import sys

linux_vendors = open("linux-fps").read().split("\n")
windows_vendors = open("ms-fps").read().split("\n")

l, w, o = 0, 0, 0

while True:
  line = sys.stdin.readline()
  if line == '':
    break
  line = line.rstrip('\r\n')
  if line in linux_vendors:
    l += 1
  elif line in windows_vendors:
    w += 1
  else:
    o += 1

print(l,w,o)
