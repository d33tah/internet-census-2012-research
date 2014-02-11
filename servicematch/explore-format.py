#!/usr/bin/pypy

"""

explore-format.py

Usage:

python explore-format.py <input file> <output file>

Build a binary database of Internet Census 2012 service fingerprint data set.
"""

import socket
import struct
import sys
import zlib
import collections
from StringIO import StringIO
import md5


def decode_fp(fp):
    global known_chars
    ret = ""
    f = StringIO(fp)
    try:
        while True:
            b = f.read(1)
            if b == '':
                break
            if b != '=':
                ret += b
            else:
                ret += chr(int(f.read(2), 16))
    except ValueError:
        pass
    return ret


def run_pdb_hook(*args, **kwargs):
    import pdb
    import traceback
    traceback.print_exception(*args, **kwargs)
    pdb.pm()

sys.excepthook = run_pdb_hook

sizes = collections.defaultdict(int)
outfile = open(sys.argv[2], "w")
onebyte_file = open("by-size/1", "w")
#for line in sys.stdin:
for line in open(sys.argv[1]):
    ip, timestamp, status, fp = line.split("\t")
    ip = socket.inet_aton(ip)
    timestamp = struct.pack("<I", int(timestamp))
    status = chr(int(status))
    if fp:
        fp = decode_fp(fp)
        #fp = zlib.compress(fp, 9)
        sizes[len(fp)] += 1
    fp_len = len(fp)
    if fp_len > 1:
        fp_md5 = md5.md5(fp).digest()
        out = "%s%s%s%s" % (ip, timestamp, status, fp_md5)
        outfile.write(out)
        outfile.flush()
        f = open("by-size/%d" % len(fp), "a")
        f.write("%s%s" % (fp_md5, fp))
        f.close()
    elif fp_len == 1:
        out = "%s%s%s%s" % (ip, timestamp, status, fp)
        onebyte_file.write(out)
        onebyte_file.flush()
    else:
        pass  # no fingerprint, do nothing for now
