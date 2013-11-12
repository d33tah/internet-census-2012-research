#!/usr/bin/python

"""
Hashes the Internet Census 2012 Fingerprint data so that the IP addresses
are useless, but the same IP address will always have the same hash.
"""

import md5
import sys

random_salt = open('/dev/urandom').read(512)
sys.stderr.write("random_salt=%s\n" % repr(random_salt))
sys.stderr.flush()

for line in sys.stdin.xreadlines():
  split = line.split()
  ip_hash = md5.md5(random_salt + split[0]).hexdigest()
  new_ip_octets = ["%s" % int(ip_hash[i * 2:i * 2 + 2], 16) for i in range(4)]
  new_ip = '.'.join(ip_octets)
  print(new_ip + "\t" + "\t".join(split[1:]))
