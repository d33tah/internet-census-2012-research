#!/usr/bin/python

"""
Fingermatch

A helper tool used to extract Internet Census 2012 data. Runs fingermatch and
feeds it with the TCP/IP fingerprints, parsing the fingermatch's output.
"""

import subprocess
import sys
import re
import fcntl
import os
import threading
from Queue import Queue

ignored_warnings = [
  "Adjusted fingerprint due to \d+ duplicated tests",

  # This one also says that it could be caused by bad network.
  "This fingerprint contains T attributes whose value is greater than 0xFF.",

  #"line is missing",
  "(SEQ|OPS|WIN|ECN|T1|T2|T3|T4|T5|T6|T7|U1|IE) line is missing",
]

#ignored_warnings_re = map(lambda x: re.compile(x, flags=re.MULTILINE), ignored_warnings)
ignored_warnings_re = map(re.compile, ignored_warnings)

stdout_lock = threading.Lock()

def process_line(line, p):

  columns = line.split("\t")
  fingerprint_column = columns[2]
  ip_column = columns[0]
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
  print("%s\t%s" % (columns[0], program_output))
  stdout_lock.release()


def worker():
  p = subprocess.Popen(["./fingermatch", "-q", "-f", "../nmap-os-db"],
                       stdin=subprocess.PIPE,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE
  )

  # Switch the process's stderr to non-blocking mode - might not work on Windows
  fd = p.stderr.fileno()
  fl = fcntl.fcntl(fd, fcntl.F_GETFL)
  fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

  while True:
    line = q.get()
    process_line(line, p)
    q.task_done()

  p.stdin.close()
  p.terminate()

if __name__ == "__main__":

  if len(sys.argv) < 2 or len(sys.argv) > 3:
    usage = """Usage: %s <internetcensusfile> <maxthreads-optional>
    """ % sys.argv[0]
    sys.exit(usage)

  f = open(sys.argv[1])
  if len(sys.argv) == 3:
    max_threads = int(sys.argv[3])
  else:
    # not using check_output to make it compatible with Python 2.6
    nproc_p = subprocess.Popen("nproc", stdout=subprocess.PIPE)
    nproc_p.wait()
    max_threads = int(nproc_p.stdout.read())

  q = Queue(maxsize=max_threads + 2)

  for i in range(max_threads):
    t = threading.Thread(target=worker)
    t.daemon = True
    t.start()

  while True:
    line = f.readline()
    if line == '':
      break
    q.put(line)

  sys.stderr.write('Waiting for the remaining tasks to finish...')
  sys.stderr.flush()
  q.join()
