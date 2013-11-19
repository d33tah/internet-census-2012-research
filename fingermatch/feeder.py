#!/usr/bin/python

"""
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
import time
import math

from fputils import print_stderr, percent_type

ignored_warnings = [
  "Adjusted fingerprint due to \d+ duplicated tests",

  # This one also says that it could be caused by bad network.
  "This fingerprint contains T attributes whose value is greater than 0xFF.",

  #"line is missing",
  "(SEQ|OPS|WIN|ECN|T1|T2|T3|T4|T5|T6|T7|U1|IE) line is missing",

  # These doesn't make fingerprints any more accurate anyway.
  "Warning: Cannot find nmap-mac-prefixes: Ethernet vendor correlation "
  "will not be performed",
  "[INFO] Vendor Info: ",
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
      print_stderr('Warning: %s' % error_output)

  stdout_lock.acquire()
  print("%s\t%s\t%s\t%s" % (ip_column, timestamp_column,
                            fingerprint_column.rstrip('\r\n'),
                            program_output))
  stdout_lock.release()


def spawn_process(match_threshold, add_arguments):
  cmd = "./fingermatch --match %s --quiet --fp-file ../nmap-os-db %s" % (
    str(match_threshold), add_arguments)
  p = subprocess.Popen(cmd, shell=True,
                       stdin=subprocess.PIPE,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE,
  )

  # Switch the process's stderr to non-blocking mode
  # (might not work on Windows)
  fd = p.stderr.fileno()
  fl = fcntl.fcntl(fd, fcntl.F_GETFL)
  fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
  return p


def worker(wait_timeout, match_threshold, add_arguments):
  p = spawn_process(match_threshold, add_arguments)
  try:
    while True:
        batch = q.get(timeout=wait_timeout)
        if len(batch) > 2:
          print_stderr("len(batch)=%s" % len(batch))
        exception = None
        for line in batch:
          try:
            process_line(line, p)
          except Exception, e:
            print_stderr("Caught an exception: ")
            print_stderr(e)
            exception = e
            p = spawn_process(match_threshold, add_arguments)
        q.task_done()
        if exception is not None:
          raise exception
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


def spawn_thread(worker_args):
    t = threading.Thread(target=worker, args=worker_args)
    t.daemon = True
    t.start()
    return t


def reviwer(threads, max_threads, worker_args):
  while keep_reviwing:
    remove_threads = []
    for t in threads:
      if not t.is_alive():
        remove_threads += [t]
    for t in remove_threads:
      threads.remove(t)
    if len(threads) < max_threads:
      for i in range(max_threads - len(threads)):
        threads += [spawn_thread(worker_args)]
    time.sleep(1)
  print_stderr("stopped reviwing.")

if __name__ == "__main__":

  formatter_class = argparse.ArgumentDefaultsHelpFormatter
  parser = argparse.ArgumentParser(description=__doc__,
                                   formatter_class=formatter_class)
  # make the maximum thread count 20% higher than the number of processors.
  max_threads = int(math.ceil(get_processor_count() * 1.2))
  parser.add_argument('-t', '--threads', metavar='N', type=int,
                      default=max_threads,
                      help="maximum number of worker threads")
  parser.add_argument('--wait-timeout', metavar='N', type=float, default=0.1,
                      help="maximum time to parse a fingerprint")
  parser.add_argument('--add-args', metavar='ARGS', type=str, default=None,
                      help="add additional arguments for fingermatch (remember"
                      " to use --add-args=--something instead of"
                      " --add-args --something)")
  parser.add_argument('-m', '--match', metavar='N', type=percent_type,
                      default=100, help="set the guess threshold to n percent")
  parser.add_argument('internet-census-file', help='Internet Census 2012 '
                      'TCP/IP fingerprint file. A dash ("-") means '
                      'standard input.')
  args = parser.parse_args()
  args_dict = vars(args)

  max_threads = args_dict['threads']
  match_threshold = args_dict['match']
  add_args = args_dict['add_args']
  if add_args is None:
    add_args = '-l -r 3'
  wait_timeout = args_dict['wait_timeout']
  filename = args_dict['internet-census-file']

  if filename != '-':
    f = open(filename)
  else:
    f = sys.stdin

  q = Queue.Queue(maxsize=max_threads * 2)

  worker_args = [wait_timeout, match_threshold, add_args]

  threads = []
  for i in range(max_threads):
    threads += [spawn_thread(worker_args)]

  keep_reviwing = True
  reviwer_args = [threads, max_threads, worker_args]
  threading.Thread(target=reviwer, args=reviwer_args).start()

  batch = []
  last_ip = None
  line = f.readline()
  while True:
    ip = line.split()[0]
    if ip != last_ip:
      last_ip = ip
      q.put(batch)
      batch = []
    batch += [line]
    line = f.readline()
    if line == '':
      q.put(batch)
      break

  keep_reviwing = False
  q.join()
  for thread in threads:
    thread.join()
