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


if sys.stdin.isatty():
  print_stderr("Enter a line from IC TCP/IP fingerprints data set.")
ic_line = sys.stdin.readline()
columns = ic_line.split()
fp = columns[2]
fp_lines = fp.split(',')

# extract the data about the closed and open TCP ports and the closed UDP port
# and build a command line based on them.
cmd_args = {}

port_cmdline = ''
scan_line = fp_lines[0]
for atom in scan_line.split('%'):
  key, val = atom.split('=')
  if key == 'CT':
    if port_cmdline != '' and val != '':
      port_cmdline += ','
      port_cmdline += 'T:%d' % int(val)
  elif key == 'OT':
    if port_cmdline != '' and val != '':
      port_cmdline += ','
    port_cmdline += 'T:%d' % int(val)
  elif key == 'CU':
    if port_cmdline != '' and val != '':
      port_cmdline += ','
      port_cmdline += 'U:%d' % int(val)

if port_cmdline != '':
  port_cmdline = '-p ' + port_cmdline
else:
  print('\t'.join(columns + ['(NO PORTS TO SCAN)', '(NO PORTS TO SCAN)']))
  sys.exit()

cmd_args['ip'] = pipes.quote(columns[0])


cmd = ("sudo nmap {ip} " +
       port_cmdline +
       " -sSU"    # enable UDP scanning
       " -n"     # disable reverse DNS queries
       " -Pn"    # assume that the host is up
       " -O"     # enable OS fingerprinting
       " -vv"    # add extra verbosity
       " -oX -"  # output data in XML format to the standard output
                 # of the default Nmap format)
       ).format(**cmd_args)
print_stderr("Will run %s" % cmd)
p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
xmlout = p.communicate()[0]  # read the Nmap XML output

# parse the XML output
t = ET.fromstring(xmlout)
assert(len(t.findall('./host')) == 1)  # make sure there's only one host

# make sure we have one open and one closed port
state_nodes = t.findall("./host[0]/ports/port/state")
found_tcp_closed = False
found_tcp_open = False
for port in state_nodes:
  state = port.get('state')
  if state == 'closed':
    found_tcp_closed = True
  elif state == 'open':
    found_tcp_open = True

comment = ''
if not found_tcp_open:
  comment += "Failed to find one open TCP port. "

if not found_tcp_closed:
  comment += "Failed to find one closed TCP port."

if comment == '':
  comment = 'OK'

# extract the raw fingerprint from the XML data
fingerprint_node = t.findall('./host[0]/os/osfingerprint')
new_fp = fingerprint_node[0].get('fingerprint')
new_fp_lines = new_fp.split('\n')
if new_fp_lines[-1] == '':
  new_fp_lines = new_fp_lines[:-1]

columns += [','.join(new_fp_lines), comment]
print('\t'.join(columns))
