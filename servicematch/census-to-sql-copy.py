#!/usr/bin/python

import os
import sys
import datetime
import md5
import base64
import re

filename = sys.argv[1]
#filename = "995-TCP_GetRequest-34.gz"
last_part = filename.split(os.sep)[-1]
port, probe_and_proto, rest = re.findall("^(.*?)-(.*)-(.*?)$", last_part)[0]
proto = probe_and_proto[0:3]
probe = probe_and_proto[4:]
assert(proto in ['TCP', 'UDP'])
is_tcp = '1' if proto == 'TCP' else '0'

def handle_line(line, is_tcp, port, probe):
    # fun fact - split() would fail here because there's at least one line
    # where a space is not escaped.
    input_columns = line.split('\t')
    ip = input_columns[0]
    epoch = int(input_columns[1])
    time_taken = datetime.datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S')
    statuscode = input_columns[2]
    if len(input_columns) == 3:
        fingerprint = ''
    else:
        if len(input_columns) != 4:
            sys.stderr.write('Strange line: %s\n' % repr(line))
        fingerprint = input_columns[3]

    # The fingerprints are stripped to a hard limit of 4500 bytes. This might
    # lead to corrupt entries at the end, like '=a' or even just '='. Let's
    # detect and strip that.
    last_escape_pos = fingerprint.rfind('=')
    if last_escape_pos != -1 and len(fingerprint) - last_escape_pos < 3:
        fingerprint = fingerprint[:last_escape_pos]

    if statuscode != 3 and fingerprint == '':
        return
    fingerprint = fingerprint.replace('\\', '\\\\')
    fingerprint = fingerprint.replace('=', '\\x')
    fingerprint = fingerprint.decode('string-escape')
    fingerprint_md5 = md5.md5(fingerprint).digest()

    fingerprint = "\\\\x" + base64.b16encode(fingerprint).lower()
    fingerprint_md5 = "\\\\x" + base64.b16encode(fingerprint_md5).lower()
    print('\t'.join([ip,port,is_tcp,time_taken,statuscode,probe,fingerprint_md5,fingerprint]))

#line = '44.183.115.216\t1344537900\t5\t\x06x.jtxt.me=20ESMTP=20Exim=204.Probe TCP Help \n'
#handle_line(line, is_tcp, port, probe)

print('copy service_probe from stdin;')
for line in sys.stdin:
    line = line.rstrip("\r\n")
    try:
        handle_line(line, is_tcp, port, probe)
    except ValueError, e:
        sys.stderr.write('%s: %s\n' % (str(e), repr(line)))
print('\.')
