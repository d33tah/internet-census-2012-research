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
    self.line = 0


class PrettyLambda:
  def __init__(self, expr, str_show):
    self.l = eval(expr)
    self.expr = expr
    self.str_show = repr(str_show)
  def __call__(self, *args, **kwargs):
    return self.l(*args, **kwargs)
  def __repr__(self):
    return self.str_show

def get_matchpoints(f):
  matchpoints = {}
  max_points = 0
  lines_read = 0
  while True:
    line = f.readline()
    lines_read += 1
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
  return max_points, matchpoints, lines_read


def sorted_dict_repr(dict_, sep=' '):
  ret = []
  for k in sorted(dict_):
    ret += ["%s: %s" % (repr(k), repr(dict_[k]))]
  return '{' + (','+sep).join(ret) + '}'


def dump_matchpoints(matchpoints, sep=' '):
  print('{')
  for k in sorted(matchpoints):
    if isinstance(matchpoints[k], list):
      desc = sorted(matchpoints[k])
    elif isinstance(matchpoints[k], dict):
      desc = sorted_dict_repr(matchpoints[k], sep)
    else:
      desc = repr(matchpoints[k])
    line = '  %5s: %s,' % (repr(k), desc)
    print(line)
  print('}')


def is_hex(x):
  try:
    int(x, 16)
    return True
  except ValueError:
    return False


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

  test_exp = test[i+1:]
  exps = test_exp.split('|')
  lambda_code = 'lambda x: '
  lambda_exps = []
  for exp in exps:
    if exp == '':
      exp = "''"
    if exp[0] in ['>', '<']:
      lambda_exps += ['x %s "%s"' % (exp[0], exp[1:])]
    elif exp.find('-') != -1:
      lower_bound_hex, upper_bound_hex = exp.split('-')
      lower_bound = int(lower_bound_hex, 16)
      upper_bound = int(upper_bound_hex, 16)
      lambda_exps += ['is_hex(x) and int(x, 16) >= %d and int(x, 16) <= %d' % (lower_bound, upper_bound)]
    else:
      lambda_exps += ['x == "%s"' % exp[1:]]
  lambda_code += ' or '.join(lambda_exps)
  test_lambda = PrettyLambda(lambda_code, test_exp)
  return ret, test_exp, test_lambda

fingerprints = []
f = open('nmap-os-db2')
got_fp = False
fp = Fingerprint()
lineno = 0
while True:
  line = f.readline()
  lineno += 1
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
    max_points, matchpoints, lines_read = get_matchpoints(f)
    lineno += lines_read
    # dump_matchpoints(matchpoints)
    p = {}
  elif line.startswith("Fingerprint "):
    fp.name = line[len("Fingerprint "):]
    fp.line = lineno
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
      test_names, test_exp, test_lambda = get_test_names(test)
      for test_name in test_names:
        #assert(test_name not in fp.probes[group_name])
        #assert(test_exp.startswith('='))
        if test_name == 'R' and test_exp == "N":
          fp.probes[group_name] = None
          continue
        if test_name in ['W0', 'W7', 'W8', 'W9']:
          pass
        else:
          assert(test_name in known_tests[group_name])
        fp.probes[group_name][test_name] = test_lambda
    got_fp = True
  else:
    sys.exit("Strange line: '%s'" % repr(line))

print_stderr("Loaded %d fingerprints." % len(fingerprints))
