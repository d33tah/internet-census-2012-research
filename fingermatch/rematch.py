#!/usr/bin/python

"""
Repeats an OS detection attempt and compares the results with a given Internet
Census 2012 TCP/IP fingerprinting data.
"""

import xml.etree.ElementTree as ET
import subprocess
import sys
import pipes
import tempfile
from fputils import print_stderr

ic_line = sys.stdin.readline()
columns = ic_line.split()
fp = columns[2]
fp_lines = fp.split(',')

# extract the data about the closed and open TCP ports and the closed UDP port
# and build a command line based on them.
cmd_args = {}

scan_line = fp_lines[0]
for atom in scan_line.split('%'):
  key, val = atom.split('=')
  if key == 'CT':
    cmd_args['closed_tcp'] = int(val)
  elif key == 'OT':
    cmd_args['open_tcp'] = int(val)
  elif key == 'CU':
    cmd_args['closed_udp'] = int(val)

cmd_args['ip'] = pipes.quote(columns[0])

cmd = ("sudo nmap {ip} "
       "-p T:{open_tcp},T:{closed_tcp},U:{closed_udp}"  # scan only these ports
       " -n"     # disable reverse DNS queries
       " -O"     # enable OS fingerprinting
       " -vv"    # add extra verbosity
       " -oX -"  # output data in XML format to the standard output
                 # of the default Nmap format)
       ).format(**cmd_args)
print_stderr("Will run %s" % cmd)
p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
xmlout = p.communicate()[0]

t = ET.fromstring(xmlout)
assert(len(t.findall('./host')) == 1)
os = t.findall('./host[0]/os/osfingerprint')
new_fp = os[0].get('fingerprint')
new_fp_lines = new_fp.split('\n')

tmp1 = tempfile.NamedTemporaryFile()
tmp2 = tempfile.NamedTemporaryFile()

tmp1.write('\n'.join(new_fp_lines))
tmp2.write('\n'.join(fp_lines))

tmp1.flush()
tmp2.flush()

subprocess.call(["vimdiff", tmp1.name, tmp2.name])
