#!/usr/bin/python

"""
Fingermatch

A helper tool used to extract Internet Census 2012. Runs fingermatch and feeds
it with the TCP/IP fingerprints, parsing the fingermatch's output.
"""

import subprocess
import sys
import re
import threading
from Queue import Queue

if len(sys.argv) != 2:
  usage = """Usage: %s <internetcensusfile>
  """ % sys.argv[0]
  sys.exit(usage)

f = open(sys.argv[1])

ignored_warnings = [
  "Adjusted fingerprint due to \d+ duplicated tests",

  # This one also says that it could be caused by bad network.
  "This fingerprint contains T attributes whose value is greater than 0xFF.",

  #"line is missing",
  "(SEQ|OPS|WIN) line is missing",
]

#ignored_warnings_re = map(lambda x: re.compile(x, flags=re.MULTILINE), ignored_warnings)
ignored_warnings_re = map(re.compile, ignored_warnings)

def process_line(line):
  p = subprocess.Popen(["./fingermatch", "-q", "-f", "../nmap-os-db"],
                       stdin=subprocess.PIPE,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
  columns = line.split("\t")
  fingerprint_column = columns[2]
  ip_column = columns[0]
  fingerprint = fingerprint_column.replace(",", "\n")

  p.stdin.write(fingerprint)
  p.stdin.flush()
  p.stdin.close()

  program_output = p.stdout.read()

  error_output = p.stderr.read()
  if error_output != '':
    is_ignored = False
    for ignored_warning in ignored_warnings_re:
      if ignored_warning.search(error_output):
        is_ignored = True
        break
    if not is_ignored:
      sys.stderr.write('Warning: %s\n' % error_output)
      sys.stderr.flush()

  print("%s\t%s" % (columns[0], program_output.strip()))
  # TODO: This should be called even if there was an exception.
  p.terminate()

q = Queue(maxsize=10)
def worker():
  while True:
    line = q.get(10)
    process_line(line)
    q.task_done()

for i in range(8):
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
