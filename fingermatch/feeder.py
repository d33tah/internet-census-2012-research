#!/usr/bin/python

description = """
A helper tool used to extract Internet Census 2012 data. Runs fingermatch and
feeds it with the TCP/IP fingerprints, parsing the fingermatch's output.
"""

import subprocess
import sys
import re
import fcntl
import os
import threading
import Queue
import argparse

ignored_warnings = [
  "Adjusted fingerprint due to \d+ duplicated tests",

  # This one also says that it could be caused by bad network.
  "This fingerprint contains T attributes whose value is greater than 0xFF.",

  #"line is missing",
  "(SEQ|OPS|WIN|ECN|T1|T2|T3|T4|T5|T6|T7|U1|IE) line is missing",
]

ignored_warnings_re = map(re.compile, ignored_warnings)

stdout_lock = threading.Lock()


def process_line(line, p):

  columns = line.split("\t")
  ip_column = columns[0]
  timestamp_column = columns[1]
  fingerprint_column = columns[2]
  fingerprint = fingerprint_column.replace(",", "\n")

  p.stdin.write(fingerprint)
  p.stdin.write("\n")
  p.stdin.flush()

  program_output = p.stdout.readline().rstrip("\r\n")

  try:
    error_output = p.stderr.read()
  except IOError:
    error_output = ''
  if error_output != '':
    is_ignored = False
    for ignored_warning in ignored_warnings_re:
      if ignored_warning.search(error_output):
        is_ignored = True
        break
    if not is_ignored:
      sys.stderr.write('Warning: %s\n' % error_output)
      sys.stderr.flush()

  stdout_lock.acquire()
  print("%s\t%s\t%s" % (ip_column, timestamp_column, program_output))
  stdout_lock.release()


def worker(wait_timeout, match_threshold, add_arguments):
  cmd = "./fingermatch --match %s --quiet --fp-file ../nmap-os-db %s" % (
    str(match_threshold), add_arguments)
  p = subprocess.Popen(cmd, shell=True,
                       stdin=subprocess.PIPE,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE
  )

  # Switch the process's stderr to non-blocking mode
  # (might not work on Windows)
  fd = p.stderr.fileno()
  fl = fcntl.fcntl(fd, fcntl.F_GETFL)
  fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

  try:
    while True:
        line = q.get(timeout=wait_timeout)
        process_line(line, p)
        q.task_done()
  except Queue.Empty:
    pass
  except IOError:  # broken pipe due to CTRL+C
    pass
  finally:
    p.stdin.close()
    p.terminate()


def get_processor_count():
  # not using check_output to make it compatible with Python 2.6
  nproc_p = subprocess.Popen("nproc", stdout=subprocess.PIPE)
  nproc_p.wait()
  return int(nproc_p.stdout.read())


def percent_type(n):
  error_msg = "%s must be a number between 1 and 100" % n
  try:
    n = int(n)
  except ValueError:
    raise argparse.ArgumentTypeError(error_msg)
  if n < 1 or n > 100:
    raise argparse.ArgumentTypeError(error_msg)
  return n

if __name__ == "__main__":

  formatter_class = argparse.ArgumentDefaultsHelpFormatter
  parser = argparse.ArgumentParser(description=description,
                                   formatter_class=formatter_class)
  parser.add_argument('--threads', metavar='N', type=int,
                      default=get_processor_count(),
                      help="Maximum number of worker threads")
  parser.add_argument('--wait-timeout', metavar='N', type=float, default=0.1,
                      help="Maximum time to parse a fingerprint")
  parser.add_argument('--add-args', metavar='ARGS', type=str, default=None,
                      help="Add additional arguments for fingermatch (remember"
                      " to use --add-args=--something instead of --add-args --something)")
  parser.add_argument('-m', '--match', metavar='N', type=percent_type,
                      default=100, help="Set the guess threshold to n percent")
  parser.add_argument('internet-census-file', help='Internet Census 2012 '
                      'TCP/IP fingerprint file. A dash ("-") means '
                      'standard input.')
  args = parser.parse_args()
  args_dict = vars(args)

  filename = args_dict['internet-census-file']
  if filename != '-':
    f = open(filename)
  else:
    f = sys.stdin
  q = Queue.Queue(maxsize=args.max_threads + 2)

  threads = []
  for i in range(args.max_threads):
    t = threading.Thread(target=worker, args=[args.wait_timeout, args.match,
                                              args.add_args])
    t.daemon = True
    t.start()
    threads += [t]

  while True:
    line = f.readline()
    if line == '':
      break
    q.put(line)

  q.join()
  for thread in threads:
    thread.join()
