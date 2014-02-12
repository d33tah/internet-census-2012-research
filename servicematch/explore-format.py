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
from StringIO import StringIO
import md5
import argparse


PROBE_NAMES = [
    "TCP_afp",
    "TCP_ajp",
    "TCP_apple-iphoto",
    "TCP_Arucer",
    "TCP_couchbase-data",
    "TCP_crossdomainxml",
    "TCP_DistCCD",
    "TCP_DNSStatusRequest",
    "TCP_DNSVersionBindReq",
    "TCP_drda",
    "TCP_EMPTY_PROBE",
    "TCP_epmd",
    "TCP_firebird",
    "TCP_FourOhFourRequest",
    "TCP_GenericLines",
    "TCP_GetRequest",
    "TCP_Hello",
    "TCP_Help",
    "TCP_HELP4STOMP",
    "TCP_hp-pjl",
    "TCP_HTTPOptions",
    "TCP_ibm-db2",
    "TCP_ibm-db2-das",
    "TCP_ibm-mqseries",
    "TCP_informix",
    "TCP_JavaRMI",
    "TCP_Kerberos",
    "TCP_LANDesk-RC",
    "TCP_LDAPBindReq",
    "TCP_LPDString",
    "TCP_Memcache",
    "TCP_memcached",
    "TCP_metasploit-xmlrpc",
    "TCP_mongodb",
    "TCP_ms-sql-s",
    "TCP_NCP",
    "TCP_NotesRPC",
    "TCP_OfficeScan",
    "TCP_oracle-tns",
    "TCP_pervasive-btrieve",
    "TCP_pervasive-relational",
    "TCP_Radmin",
    "TCP_redis-server",
    "TCP_riak-pbc",
    "TCP_RPCCheck",
    "TCP_RTSPRequest",
    "TCP_SIPOptions",
    "TCP_SMBProgNeg",
    "TCP_Socks4",
    "TCP_Socks5",
    "TCP_SqueezeCenter_CLI",
    "TCP_SSLSessionReq",
    "TCP_SSLv23SessionReq",
    "TCP_tarantool",
    "TCP_TerminalServer",
    "TCP_Verifier",
    "TCP_VerifierAdvanced",
    "TCP_vmware-esx",
    "TCP_vp3",
    "TCP_WMSRequest",
    "TCP_X11Probe",
    "TCP_ZendJavaBridge",
    "UDP_AFSVersionRequest",
    "UDP_Citrix",
    "UDP_DNS-SD",
    "UDP_DNSStatusRequest",
    "UDP_DNSVersionBindReq",
    "UDP_Help",
    "UDP_ibm-db2-das-udp",
    "UDP_Kerberos",
    "UDP_memcached",
    "UDP_NBTStat",
    "UDP_NTPRequest",
    "UDP_pc-anywhere",
    "UDP_pc-duo",
    "UDP_pc-duo-gw",
    "UDP_RPCCheck",
    "UDP_serialnumberd",
    "UDP_SIPOptions",
    "UDP_SNMPv1public",
    "UDP_SNMPv3GetRequest",
    "UDP_Sqlping",
    "UDP_SqueezeCenter",
    "UDP_sybaseanywhere",
    "UDP_vuze-dht",
    "UDP_xdmcp",
]


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


def main(infile, outfile, port_no, probe_name):
    probe_dir = "%s-%s" % (port_no, probe_name)
    outfile = open(outfile, "w")
    onebyte_file = open("%s/1" % probe_dir, "w")
    port_no_bin = struct.pack("<h", port_no)
    probe_byte = chr(PROBE_NAMES.index(probe_name))
    #for line in sys.stdin:
    for line in open(infile):
        ip, timestamp, status, fp = line.split("\t")
        ip = socket.inet_aton(ip)
        timestamp = struct.pack("<I", int(timestamp))
        status = chr(int(status))
        if fp:
            fp = decode_fp(fp)
            #fp = zlib.compress(fp, 9)
        fp_len = len(fp)
        if fp_len > 1:
            fp_md5 = md5.md5(fp).digest()
            out = "%s%s%s%s%s%s" % (ip, port_no_bin, probe_byte, timestamp,
                                    status, fp_md5)
            outfile.write(out)
            outfile.flush()
            f = open("%s/%d" % (probe_dir, len(fp)), "a")
            f.write("%s%s%s" % (fp_md5, probe_byte, fp))
            f.close()
        elif fp_len == 1:
            out = "%s%s%s%s" % (ip, timestamp, status, fp)
            onebyte_file.write(out)
            onebyte_file.flush()
        else:
            pass  # no fingerprint, do nothing for now

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('--infile', required=True)
    parser.add_argument('--outfile', required=True)
    parser.add_argument('--dirname', required=True)
    args = parser.parse_args()

    dirname_split = args.dirname.split('-')
    port_no = int(dirname_split[0])
    probe_name = '-'.join(dirname_split[1:])

    sys.excepthook = run_pdb_hook
    main(args.infile, args.outfile, port_no, probe_name)
