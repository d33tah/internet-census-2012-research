#!/usr/bin/env python


def print_stderr(str_):
  sys.stderr.write("%s\n" % str_)
  sys.stderr.flush()

if __name__ == "__main__":
  raise RuntimeError("This is a library file - should not be run directly.")
