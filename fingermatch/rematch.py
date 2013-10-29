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

ic_line = sys.stdin.readline()
columns = ic_line.split()
ip = columns[0]
fp = columns[2]
fp_lines = fp.split(',')

cmd = "sudo nmap %s -p T:179,T:21,U:43477 -O -n -vv -oX -" % pipes.quote(ip)
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
