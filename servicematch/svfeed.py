#!/usr/bin/python -u
# -*- coding: utf-8 -*-

import subprocess
import fcntl
import os
import time
import sys


FP_START = "SF-Port110-TCP:V=6.40%I=7%D=1/20%Time=52DD2F2C%" \
           "P=x86_64-redhat-linux-gnu%r(" + "GenericLines" +","

def process_line(p, line):
  ret = []
  if not (
          line.startswith("FAILED") or
          line.startswith("MATCHED") or
          line.startswith("SOFT MATCH") or
          line.startswith("WARNING")
         ):
    sys.stderr.write("WARNING: UNEXPECTED LINE: %s\n" % line)

  if p.poll():
    sys.exit("Process died.")
  if line.startswith("MATCHED"):
    pattern_lineno = line.split()[1].split(':')[1]
    ret += [pattern_lineno]
  return ret

def read_response(p):
  ret = []
  # Skip over the WARNING about truncation.
  while True:
    line = p.stdout.readline().rstrip("\r\n")
    if not line.startswith("WARNING"):
      break
  ret += process_line(p, line)

  # Now, read any remaining matches.
  fd = p.stdout.fileno()
  fl = fcntl.fcntl(fd, fcntl.F_GETFL)
  fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
  while True:
    try:
      line = p.stdout.readline().rstrip("\r\n")
      ret += process_line(p, line)
    except IOError:
      break
  fd = p.stdout.fileno()
  fl = fcntl.fcntl(fd, fcntl.F_GETFL)
  fcntl.fcntl(fd, fcntl.F_SETFL, fl & ~os.O_NONBLOCK)

  return ret

def main():
  p = subprocess.Popen("stdbuf -o 0 ./servicematch ../nmap-service-probes",
                       stdin=subprocess.PIPE,
                       stdout=subprocess.PIPE,
                       bufsize=0,
                       shell=True,
                      )
  p.stdout.readline() # skip "hello" message
  f2 = open("out", "w")
  lineno = 0
  with open("/dev/stdin") as f:
    while True:
      fp_raw = f.readline()
      lineno += 1
      if fp_raw == '':
        break
      fp_columns = fp_raw.split("\t")
      fp_reply_raw = fp_columns[3].rstrip('\r\n')
      fp_reply = fp_reply_raw.replace('=', '\\x')
      fp_reply = fp_reply.replace('\\', '\\x5c')
      fp_reply = fp_reply.replace('"', '\\x22')
      fp_reply = fp_reply[:800]
      fp = '%s%d,"%s");' % (FP_START, len(fp_reply), fp_reply)
      p.stdin.write(fp)
      p.stdin.write("\n\n")
      p.stdin.flush()
      ret = read_response(p)
      print('\t'.join(fp_columns[:-1] + [','.join(ret)]))

if __name__ == "__main__":
  main()
