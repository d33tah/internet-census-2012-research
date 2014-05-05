#!/usr/bin/env python
# -*- coding: latin-1 -*-
"""
1. Dump binary data to the following text format:

00000000: 00 00 00 5B 68 65 78 64  75 6D 70 5D 00 00 00 00  ...[hexdump]....
00000010: 00 11 22 33 44 55 66 77  88 99 AA BB CC DD EE FF  .."3DUfw........

It is similar to the one used by:
Scapy
00 00 00 5B 68 65 78 64 75 6D 70 5D 00 00 00 00  ...[hexdump]....
00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF  .."3DUfw........

Far Manager
000000000: 00 00 00 5B 68 65 78 64 ¦ 75 6D 70 5D 00 00 00 00     [hexdump]
000000010: 00 11 22 33 44 55 66 77 ¦ 88 99 AA BB CC DD EE FF   ?"3DUfwˆ™ª»ÌÝîÿ


2. Restore binary data from the formats above as well
   as from less exotic strings of raw hex

"""

__version__ = '2.0'
__author__  = 'anatoly techtonik <techtonik@gmail.com>'
__license__ = 'Public Domain'

__history__ = \
"""
2.0 (2014-02-02)
 * add --restore option to command line mode to get
   binary data back from hex dump
 * support saving test output with `--test logfile`
 * restore() from hex strings without spaces
 * restore() now raises TypeError if input data is
   not string
 * hexdump() and dumpgen() now don't return unicode
   strings in Python 2.x when generator is requested

1.0 (2013-12-30)
 * length of address is reduced from 10 to 8
 * hexdump() got new 'result' keyword argument, it
   can be either 'print', 'generator' or 'return'
 * actual dumping logic is not in new dumpgen()
   generator function
 * new dump(binary) function that takes binary data
   and returns string like "66 6F 72 6D 61 74"
 * new genchunks(mixed, size) function that chunks
   both sequences and file like objects

0.5 (2013-06-10)
 * hexdump is now also a command line utility (no
   restore yet)

0.4 (2013-06-09)
 * fix installation with Python 3 for non English
   versions of Windows, thanks to George Schizas

0.3 (2013-04-29)
 * fully Python 3 compatible

0.2 (2013-04-28)
 * restore() to recover binary data from a hex dump in
   native, Far Manager and Scapy text formats (others
   might work as well)
 * restore() is Python 3 compatible

0.1 (2013-04-28)
 * working hexdump() function for Python 2
"""

import binascii  # binascii is required for Python 3
import sys

from django import template
register = template.Library()

# --- constants
PY3K = sys.version_info >= (3, 0)

# --- helpers
def int2byte(i):
  '''convert int [0..255] to binary byte'''
  if PY3K:
    return i.to_bytes(1, 'little')
  else:
    return chr(i)

# --- - chunking helpers
def chunks(seq, size):
  '''Generator that cuts sequence (bytes, memoryview, etc.)
     into chunks of given size. If `seq` length is not multiply
     of `size`, the lengh of the last chunk returned will be
     less than requested.

     >>> list( chunks([1,2,3,4,5,6,7], 3) )
     [[1, 2, 3], [4, 5, 6], [7]]
  '''
  d, m = divmod(len(seq), size)
  for i in range(d):
    yield seq[i*size:(i+1)*size]
  if m:
    yield seq[d*size:]

def chunkread(f, size):
  '''Generator that reads from file like object. May return less
     data than requested on the last read.'''
  c = f.read(size)
  while len(c):
    yield c
    c = f.read(size)

def genchunks(mixed, size):
  '''Generator to chunk binary sequences or file like objects.
     The size of the last chunk returned may be less than
     requested.'''
  if hasattr(mixed, 'read'):
    return chunkread(mixed, size)
  else:
    return chunks(mixed, size)
# --- - /chunking helpers

# --- hex stuff
def dump(binary):
  '''
  Convert `binary` bytes (Python 3) or str (Python 2) to
  hex string:

  00 00 00 00 00 00 00 00 00 00 00 ...
  '''
  hexstr = binascii.hexlify(binary)
  if PY3K:
    hexstr = hexstr.decode('ascii')
  return ' '.join(chunks(hexstr.upper(), 2))

@register.filter(name='hexdump')
def dumpgen(data):
  '''
  Generator that produces strings:

  '00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................'
  '''
  ret = ""
  generator = genchunks(data, 16)
  for addr, d in enumerate(generator):
    # 00000000:
    line = '%08X: ' % (addr*16)
    # 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 
    dumpstr = dump(d)
    line += dumpstr[:8*3]
    if len(d) > 8:  # insert separator if needed
      line += ' ' + dumpstr[8*3:]
    # ................
    # calculate indentation, which may be different for the last line
    pad = 2
    if len(d) < 16:
      pad += 3*(16 - len(d))
    if len(d) <= 8:
      pad += 1
    line += ' '*pad

    for byte in d:
      # printable ASCII range 0x20 to 0x7E
      if not PY3K:
        byte = ord(byte)
      if 0x20 <= byte <= 0x7E:
        line += chr(byte)
      else:
        line += '.'
    ret += line + '\n'
  return ret
