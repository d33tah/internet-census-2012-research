#!/usr/bin/python

import sys
from fputils import print_stderr

# Generated using dump_matchpoints().
known_tests = {
  'ECN': ['CC', 'DF', 'O', 'Q', 'R', 'T', 'TG', 'W'],
   'IE': ['CD', 'DFI', 'R', 'T', 'TG'],
  'OPS': ['O1', 'O2', 'O3', 'O4', 'O5', 'O6'],
  'SEQ': ['CI', 'GCD', 'II', 'ISR', 'SP', 'SS', 'TI', 'TS'],
   'T1': ['A', 'DF', 'F', 'Q', 'R', 'RD', 'S', 'T', 'TG'],
   'T2': ['A', 'DF', 'F', 'O', 'Q', 'R', 'RD', 'S', 'T', 'TG', 'W'],
   'T3': ['A', 'DF', 'F', 'O', 'Q', 'R', 'RD', 'S', 'T', 'TG', 'W'],
   'T4': ['A', 'DF', 'F', 'O', 'Q', 'R', 'RD', 'S', 'T', 'TG', 'W'],
   'T5': ['A', 'DF', 'F', 'O', 'Q', 'R', 'RD', 'S', 'T', 'TG', 'W'],
   'T6': ['A', 'DF', 'F', 'O', 'Q', 'R', 'RD', 'S', 'T', 'TG', 'W'],
   'T7': ['A', 'DF', 'F', 'O', 'Q', 'R', 'RD', 'S', 'T', 'TG', 'W'],
   'U1': ['DF', 'IPL', 'R', 'RID', 'RIPCK',
          'RIPL', 'RUCK', 'RUD', 'T', 'TG', 'UN'],
  'WIN': ['W1', 'W2', 'W3', 'W4', 'W5', 'W6'],
}


class Fingerprint:
  def __init__(self):
    self.name = ""
    self.classes = ""
    self.cpe = ""
    self.probes = {}


def get_matchpoints(f):
  matchpoints = {}
  max_points = 0
  while True:
    line = f.readline()
    if line == '\n':
      break
    group_name, tests = line.split('(')
    assert(group_name not in matchpoints)
    assert(group_name in known_tests)
    matchpoints[group_name] = {}
    for test in tests.rstrip(')\n').split('%'):
      test_name, test_points = test.split('=')
      assert(test not in matchpoints[group_name])
      assert(test_name in known_tests[group_name])
      matchpoints[group_name][test_name] = int(test_points)
      max_points += int(test_points)
  return max_points, matchpoints


def dump_matchpoints(matchpoints):
  print('{')
  for k in sorted(matchpoints):
    line = '  %5s: %s,' % (repr(k), sorted(matchpoints[k]))
    print(line)
  print('}')


def get_test_names(test):
  ret = []
  i = 0
  start = i
  while test[i] != '=':
    while test[i].isalnum():
      i += 1
    test_name = test[start:i]
    ret += [test_name]
    start = i
    assert(test[i] in ['=', '|'])
    if test[i] == '|':
      i += 1
      start += 1
  return ret, test[i:]

fingerprints = []
f = open('nmap-os-db2')
got_fp = False
fp = Fingerprint()
while True:
  line = f.readline()
  if line == '\n' or line == '':
    if got_fp:
      assert(all(test in fp.probes for test in known_tests))
      fingerprints += [fp]
      fp = Fingerprint()
    if line == '':
      break
  elif line[0] == '#':
    continue
  elif line.startswith("MatchPoints"):
    max_points, matchpoints = get_matchpoints(f)
    # dump_matchpoints(matchpoints)
    p = {}
  elif line.startswith("Fingerprint "):
    fp.name = line[len("Fingerprint "):]
  elif line.startswith("Class "):
    fp.clases = line[len("Class "):]
  elif line.startswith("CPE "):
    fp.cpe = line[len("CPE "):]
  elif any(line.startswith(k + "(") for k in known_tests):
    group_name, tests = line.split('(')
    assert(group_name not in fp.probes)
    assert(group_name in known_tests)
    fp.probes[group_name] = {}
    for test in tests.rstrip(')\n').split('%'):
      if test == '':
        fp.probes[group_name] = None
        continue
      test_names, test_exp = get_test_names(test)
      for test_name in test_names:
        assert(test_exp.startswith('='))
        if test_name == 'R' and test_exp == "=N":
          fp.probes[group_name] = None
          continue
        if test_name in ['W0', 'W7', 'W8', 'W9']:
          pass
        else:
          assert(test_name in known_tests[group_name])
    got_fp = True
  else:
    sys.exit("Strange line: '%s'" % repr(line))

print_stderr("Loaded %d fingerprints." % len(fingerprints))
