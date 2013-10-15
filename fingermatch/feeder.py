#!/usr/bin/python

"""
Fingermatch

A helper tool used to extract Internet Census 2012. Runs fingermatch and feeds
it with the TCP/IP fingerprints, parsing the fingermatch's output.
"""

import subprocess
import sys
import re
import fcntl
import os
import threading
from Queue import Queue

if len(sys.argv) < 2 or len(sys.argv) > 3:
  usage = """Usage: %s <internetcensusfile> <maxthreads>
  """ % sys.argv[0]
  sys.exit(usage)

f = open(sys.argv[1])
if len(sys.argv) == 3:
  max_threads = int(sys.argv[3])
else:
  max_threads = int(subprocess.check_output("nproc"))

ignored_warnings = [
  "Adjusted fingerprint due to \d+ duplicated tests",

  # This one also says that it could be caused by bad network.
  "This fingerprint contains T attributes whose value is greater than 0xFF.",

  #"line is missing",
  "(SEQ|OPS|WIN) line is missing",
]

#ignored_warnings_re = map(lambda x: re.compile(x, flags=re.MULTILINE), ignored_warnings)
ignored_warnings_re = map(re.compile, ignored_warnings)

p = subprocess.Popen(["./fingermatch", "-q", "-f", "../nmap-os-db"],
                     stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE
)

# Switch the process's stderr to non-blocking mode - might not work on Windows
fd = p.stderr.fileno()
fl = fcntl.fcntl(fd, fcntl.F_GETFL)
fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

def process_line(line):
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

  print("%s\t%s" % (columns[0], program_output))

q = Queue(maxsize=max_threads + 2)
def worker():
  while True:
    line = q.get()
    process_line(line)
    q.task_done()

for i in range(max_threads):
  t = threading.Thread(target=worker)
  t.start()

while True:
  line = f.readline()
  if line == '':
    break
  q.put(line)

sys.stderr.write('Waiting for the remaining tasks to finish...')
sys.stderr.flush()
q.join()

p.stdin.close()
p.terminate()
