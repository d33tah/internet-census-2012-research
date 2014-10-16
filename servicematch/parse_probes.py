#!/usr/bin/python

import StringIO
import os

def get_whitespace(f):
  while True:
    b = f.read(1)
    if b == "":
      raise EOFError()
    if b != " ":
      f.seek(-1, os.SEEK_CUR)
      break

def get_regex(f):
  ret = ""
  delim = f.read(1)
  were_escaping = False
  # read the regex body
  while True:
    b = f.read(1)
    if b == "":
      raise EOFError()
    if b == delim and not were_escaping:
      break
    ret += b
    were_escaping = b == "\\" and not were_escaping


  # read the regex modifiers
  while True:
    b = f.read(1)
    if b == " ":
      f.seek(-1, os.SEEK_CUR)
      break
    if b == "":
      break
    assert(b in ['s', 'a', 'i'])  # no idea what 'a' or 'i' does.
  return ret

def get_pattern_name(f):
  ret = ""
  while True:
    b = f.read(1)
    if b == "":
      raise EOFError()
    if b == " ":
      break
    assert(b.isalnum() or b in ['-', '_', '.', '/'])
    ret += b
  return ret

def parse_line(line):
  f = StringIO.StringIO(line)
  assert(f.read(5) == "match")
  get_whitespace(f)
  pattern_name = get_pattern_name(f)
  found_regex = {}
  while True:
    regex_type = f.read(1)
    assert(regex_type in ['m', 'p', 'v', 'i', 'c', 'o', 'h', 'd'])
    if regex_type == "c":
      assert(f.read(3) == "pe:")
    if regex_type in found_regex and regex_type != 'c':
      raise ValueError("Found redefinition of regex %s in line %s" %
        (regex_type, repr(line)))
    regex = get_regex(f)
    found_regex[regex_type] = regex
    try:
      get_whitespace(f)
    except EOFError:
      break
  return pattern_name, found_regex

def main(filename):
  with open(filename) as f:
    for line_raw in f:
      if line_raw.startswith("match"):
        line = line_raw.rstrip("\r\n")
        print("Processing line %s" % line)
        pattern_name, found_regex = parse_line(line)

if __name__ == "__main__":
  main("../nmap-service-probes")
