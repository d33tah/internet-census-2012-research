#!/usr/bin/env python

import sys
import psycopg2 as DBAPI
import time
import locale
import subprocess
import re

from svfeed_config import PG_SELECT_PORT, PG_SELECT_HOST, PG_SELECT_USER
from svfeed_config import PG_INSERT_PORT, PG_INSERT_HOST, PG_INSERT_USER
from svfeed_config import PG_SERVICEMATCH_CMD


SELECT_QUERY = """
SELECT fingerprint, fingerprint_md5, probe
FROM service_probe
WHERE fingerprint_md5 NOT IN (SELECT fingerprint_md5 FROM service_probe_match)
GROUP BY fingerprint_md5, fingerprint, probe
ORDER BY COUNT(*)
;
"""

INSERT_QUERY = """
INSERT INTO service_probe_match (fingerprint_md5, service, product, version,
                                 info, cpe, os, hostname, devicetype)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
"""

INSERT_COLUMNS = ('service', 'product', 'version', 'info', 'cpe', 'os',
                  'hostname', 'devicetype')


FP_START = "SF-Port110-TCP:V=6.40%I=7%D=1/20%Time=52DD2F2C%" \
           "P=x86_64-redhat-linux-gnu%r"

MATCH_PATTERN = ('^MATCHED [^ :]+?:(?P<lineno>\d+)' +
                 '( \(FALLBACK: [^ ]+\))?' +
                 ' svc (?P<service>[^ ]+)' +
                 '( p\|(?P<product>[^\|]+)\|)?' +
                 '( v\|(?P<version>[^\|]+)\|)?' +
                 '( i\|(?P<info>[^\|]+)\|)?' +
                 '( h\|(?P<hostname>[^\|]+)\|)?' +
                 '( o\|(?P<os>[^\|]+)\|)?' +
                 '( d\|(?P<devicetype>[^\|]+)\|)?' +
                 '( (?P<cpe>.*?))?$')


def print_stderr(s):
    sys.stderr.write("%s" % s)
    sys.stderr.flush()


def process_line(p, line):
    ret = []
    if not (
            line.startswith("FAILED") or
            line.startswith("MATCHED") or
            line.startswith("SOFT MATCH") or
            line.startswith("WARNING")
            ):
        sys.stderr.write("WARNING: UNEXPECTED LINE: %s\n" % line)

    if p.poll():
        sys.exit("Process died.")
    if line.startswith("MATCHED"):
        result = re.match(MATCH_PATTERN, line)
        assert(result)
        result_dict = result.groupdict()
        for key in result_dict:
            if result_dict[key] is not None:
                result_dict[key] = repr(result_dict[key])[1:-1]
        ret += [result_dict]
    return ret


def read_response(p):
    ret = []
    # Now, read any remaining matches.
    while True:
        try:
            line = p.stdout.readline().rstrip("\r\n")
            #print(line)
            if line == "DONE":
                break
            ret += process_line(p, line)
        except IOError:
            break
    return ret


def main():
    global select_conn, insert_conn, insert_cur, select_cur

    locale.setlocale(locale.LC_ALL, '')
    select_conn = DBAPI.connect(user=PG_SELECT_USER, port=PG_SELECT_PORT,
                                host=PG_SELECT_HOST)
    # We're creating two DB connections in order to be able to commit INSERT
    # queries without invalidating the server-side cursor. Take a look here:
    # http://stackoverflow.com/q/12233115/1091116
    insert_conn = DBAPI.connect(user=PG_INSERT_USER, port=PG_INSERT_PORT,
                                host=PG_INSERT_HOST)

    p = subprocess.Popen(PG_SERVICEMATCH_CMD,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         bufsize=0,
                         shell=True,
                         )
    p.stdout.readline()  # skip the "hello" message

    insert_cur = insert_conn.cursor()
    first = True

    # create a named cursor - this forces it to be server-side.
    select_cur = select_conn.cursor(name="select")
    print_stderr("Fetching the TO-DO fingerprint list...")
    t = time.time()
    select_cur.execute(SELECT_QUERY)

    for record in select_cur:
        if first:
            done_seconds = locale.format("%.2f", time.time() - t, 1)
            print_stderr("\tDone in %s seconds.\n" % done_seconds)
            first = False
        fp_reply = record[0]
        fp_md5 = record[1]
        print(fp_md5)
        probe_type = record[2]
        fp_reply = fp_reply.replace('\\', '\\x5c')
        fp_reply = fp_reply.replace('=', '\\x')
        fp_reply = fp_reply.replace('"', '\\x22')
        fp = FP_START + '%s(%s,%d,"%s");' % (FP_START, probe_type,
                                             len(fp_reply), fp_reply)
        p.stdin.write(fp)
        p.stdin.write("\n\n")
        p.stdin.flush()
        ret = read_response(p)
        if not ret:
            # insert a NULL entry
            insert_cur.execute("""INSERT INTO service_probe_match
                                (fingerprint_md5)
                                VALUES (%s)""", (fp_md5,))
        else:
            for match in ret:
                insert_args = (fp_md5, ) + (match[column]
                                            for column in INSERT_COLUMNS)
                insert_cur.execute(INSERT_QUERY, insert_args)
        insert_conn.commit()

try:
    main()
except KeyboardInterrupt:
    print_stderr("Caught a KeyboardInterrupt.\n")
    sys.exit(1)
finally:
    insert_conn.commit()
    insert_cur.close()
    select_cur.close()
    select_conn.close()
    insert_conn.close()
