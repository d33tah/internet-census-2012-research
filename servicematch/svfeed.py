#!/usr/bin/env python

import sys
import subprocess
import re
import copy
import base64

#from svfeed_config import PG_SERVICEMATCH_CMD, PG_WAIT_TIMEOUT
PG_SERVICEMATCH_CMD = "stdbuf -o 0 ~/workspace/internet-census-2012-research/servicematch/servicematch ~/workspace/internet-census-2012-research/nmap-service-probes"
PG_WAIT_TIMEOUT = 1.0


INSERT_COLUMNS = ('service', 'product', 'version', 'info', 'cpe', 'os',
                  'hostname', 'devicetype')


FP_START1 = "SF-Port110-%s"
FP_START2 = ":V=6.40%I=7%D=1/20%Time=52DD2F2C%" \
           "P=x86_64-redhat-linux-gnu%r"

MATCH_PATTERN = ('^MATCHED [^ :]+?:(?P<lineno>\\d+)' +
                 '( \\(FALLBACK: [^ ]+\\))?' +
                 ' svc (?P<service>[^ ]+)' +
                 '( p\\|(?P<product>[^\\|]+)\\|)?' +
                 '( v\\|(?P<version>[^\\|]+)\\|)?' +
                 '( i\\|(?P<info>[^\\|]+)\\|)?' +
                 '( h\\|(?P<hostname>[^\\|]+)\\|)?' +
                 '( o\\|(?P<os>[^\\|]+)\\|)?' +
                 '( d\\|(?P<devicetype>[^\\|]+)\\|)?' +
                 '( (?P<cpe>.*?))?$')


def print_stderr(s):
    sys.stderr.write("%s" % s)
    sys.stderr.flush()


class Worker():

    def __init__(self):

        self.match_pattern = re.compile(MATCH_PATTERN)
        self.fp_start1 = copy.copy(FP_START1)
        self.fp_start2 = copy.copy(FP_START2)
        self.timeout = copy.copy(PG_WAIT_TIMEOUT)

        self.p = subprocess.Popen(PG_SERVICEMATCH_CMD,
                                  stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE,
                                  bufsize=0,
                                  shell=True,
                                  )
        self.p.stdout.readline()  # skip the "hello" message



    def process_line(self, line):
        ret = []
        if not (
                line.startswith("FAILED") or
                line.startswith("MATCHED") or
                line.startswith("SOFT MATCH") or
                line.startswith("WARNING")
                ):
            pid = self.p.pid
            sys.stderr.write("WARNING [%d]: UNEXPECTED LINE: '%s'\n" % (pid,
                                                                        line))

        if line.startswith("MATCHED"):
            result = self.match_pattern.match(line)
            assert(result)
            result_dict = result.groupdict()
            for key in result_dict:
                if result_dict[key] is not None:
                    result_dict[key] = repr(result_dict[key])[1:-1]
            ret += [result_dict]
        return ret


    def read_response(self):
        ret = []
        # Now, read any remaining matches.
        while True:
            line = self.p.stdout.readline().rstrip("\r\n")
            if line == "DONE":
                break
            ret += self.process_line(line)
        return ret

    def handle_record(self, fp_reply, fp_md5, probe_type, is_tcp):
        #fp_reply = fp_reply.replace('\\', '\\x5c')
        #fp_reply = fp_reply.replace('=', '\\x')
        #fp_reply = fp_reply.replace('"', '\\x22')
        fp_reply_len = hex(len(fp_reply)).upper()[2:]
        proto = "TCP" if int(is_tcp) else "UDP"
        fp = '%s%s(%s,%s,"%s");' % (self.fp_start1 % proto, self.fp_start2,
                                  probe_type, fp_reply_len, fp_reply)
        #print(fp)
        self.p.stdin.write(fp)
        self.p.stdin.write("\n\n")
        self.p.stdin.flush()
        for match in self.read_response():
            for key in match:
                if match[key] is None:
                    match[key] = '\\N'
                else:
                    match[key] = repr(match[key])[1:-1]
#service, product, version, info, cpe, os, hostname, devicetype
# 'info' 'product': 'SSLv3', 'service': 'ssl', 'hostname' 'cpe': '', 'version' 'devicetype' 'lineno': '10434', 'os': None
            print('\t'.join([fp_md5, match['service'], match['product'],
                             match['version'], match['info'], match['cpe'],
                             match['os'], match['hostname'], match['devicetype']]))


    def start(self):

        for line in sys.stdin:
            fingerprint, fingerprint_md5, probe, is_tcp = line.split('\t')
            probe = probe.rstrip("\r\n")
            fingerprint = re.sub('(..)', '\\x\\1', fingerprint[3:])
            self.handle_record(fingerprint, fingerprint_md5, probe, is_tcp)



try:
    t = Worker()
    t.start()
except KeyboardInterrupt:
    print_stderr("Caught a KeyboardInterrupt.\n")
    sys.exit(1)
