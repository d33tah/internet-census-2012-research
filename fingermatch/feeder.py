#!/usr/bin/python

"""
Fingermatch

A helper tool used to extract Internet Census 2012. Runs fingermatch and feeds
it with the TCP/IP fingerprints, parsing the fingermatch's output.
"""

import subprocess
import sys

if len(sys.argv) != 2:
  usage = """Usage: %s <internetcensusfile>
  """ % sys.argv[0]
  sys.exit(usage)

f = open(sys.argv[1])

while True:
  line = f.readline()
  if line == '':
    break
  p = subprocess.Popen(["./fingermatch", "-f", "../nmap-os-db"],
                       stdin=subprocess.PIPE,
                       stdout=subprocess.PIPE)
  fingerprint_column = line.split("\t")[2]
  fingerprint = fingerprint_column.replace(",", "\n")
  p.stdin.write(fingerprint)
  p.stdin.flush()
  p.stdin.close()
  print(p.stdout.read())
  p.terminate()
