#!/usr/bin/env python

import sys


def percent_type(n):
  error_msg = "%s must be a number between 1 and 100" % n
  try:
    n = int(n)
  except ValueError:
    raise argparse.ArgumentTypeError(error_msg)
  if n < 1 or n > 100:
    raise argparse.ArgumentTypeError(error_msg)
  return n


def print_stderr(str_):
  sys.stderr.write("%s\n" % str_)
  sys.stderr.flush()

if __name__ == "__main__":
  raise RuntimeError("This is a library file - should not be run directly.")
