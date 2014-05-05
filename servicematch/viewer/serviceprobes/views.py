import subprocess
from django.http import HttpResponse
from django.shortcuts import render
import psycopg2
import psycopg2.extras
import iptools


def run_query(conn, sql, args):

    ret = []

    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(sql, args)

    columns = []
    for col in cur.description:
        columns += [col[0]]

    for row in cur:
        row_dict = {}
        for i in range(len(columns)):
            row_dict[columns[i]] = row[i]
        ret += [row_dict]
    return ret


def index(request):
    return render(request, 'index.html',
                  {'title': 'Service Fingerprint Viewer'})


def show_ip(request):

    ip = request.GET['ip']
    title = 'Details about IP range %s' % ip
    iprange = iptools.IpRange(ip)
    if len(iprange) > 256**2:
        return HttpResponse("Sorry, IP range too big.")
    start_ip = iptools.ipv4.long2ip(iprange.startIp)
    end_ip = iptools.ipv4.long2ip(iprange.endIp)

    conn = psycopg2.connect(user="d33tah", port=5432, host="localhost")
    rows = run_query(conn,
                     """SELECT DISTINCT r.rdns, s.ip, s.portno, s.is_tcp,
                          encode(s.fingerprint_md5, 'hex') fingerprint_md5,
                          s.fingerprint, (
                             SELECT product
                             FROM service_probe_match m
                             WHERE m.fingerprint_md5=s.fingerprint_md5
                             LIMIT 1)
                         FROM service_probe s
                         JOIN rdns2 r ON s.ip=r.ip
                         WHERE s.ip>=%s AND s.ip<=%s""", (start_ip, end_ip))

    return render(request, 'show_ip.html', {'rows': rows,
                                            'ip': ip,
                                            'title': title})


def one_ip(request):

    ip = request.GET['ip']
    title = 'Details about IP address %s' % ip

    conn = psycopg2.connect(user="d33tah", port=5432, host="localhost")
    fingerprint_rows = run_query(conn,
                     """SELECT s.*, m.*,
                          encode(s.fingerprint_md5, 'hex') fingerprint_md5
                         FROM service_probe s
                         JOIN service_probe_match m
                             ON m.fingerprint_md5=s.fingerprint_md5
                         WHERE s.ip=%s""", (ip,))

    rdns_rows = run_query(conn, "SELECT r.rdns FROM rdns2 r WHERE r.ip=%s",
                          (ip,))
    if len(rdns_rows) > 0:
        rdns = rdns_rows[0]['rdns']
        title += ' (%s)' % rdns

    rows_dict = {}
    for row in fingerprint_rows:
      key = (row['portno'], row['fingerprint_md5'])
      product_tuple = tuple(row[k] for k in ['service', 'product', 'version',
                                             'info', 'cpe', 'os', 'hostname',
                                             'devicetype'])

      product_dict = {k: row[k] for k in ['service', 'product', 'version',
                                          'info', 'cpe', 'os', 'hostname',
                                          'devicetype']}
      if key not in rows_dict:
        rows_dict[key] = row
        rows_dict[key]['probes'] = []
        rows_dict[key]['times_taken'] = []
        rows_dict[key]['products'] = []
        rows_dict[key]['product_tuples'] = []

      rows_dict[key]['probes'] += [row['probe']]
      rows_dict[key]['times_taken'] += [row['time_taken']]
      if not product_tuple in rows_dict[key]['product_tuples']:
          rows_dict[key]['products'] += [product_dict]
          rows_dict[key]['product_tuples'] += [product_tuple]

    rows = rows_dict.values()

    return render(request, 'one_ip.html', {'rows': rows,
                                            'ip': ip,
                                            'title': title})


def show_fp(request):
    fp = request.GET['fp']
    title = 'Details about fingerprint ID %s' % fp
    conn = psycopg2.connect(user="d33tah", port=5432, host="localhost")
    rows = run_query(conn,
                     """SELECT DISTINCT *
                        FROM service_probe_match
                        WHERE fingerprint_md5=decode(%s, 'hex')""", (fp,))
    fingerprint_rows = run_query(conn,
                     """SELECT fingerprint from service_probe
                        WHERE fingerprint_md5=decode(%s, 'hex')
                        LIMIT 1""", (fp,))
    fingerprint = fingerprint_rows[0]['fingerprint']
    return render(request, 'show_fp.html', {'rows': rows,
                                            'fp': fp,
                                            'title': title,
                                            'fingerprint': fingerprint,
                                            'fingerprint_md5': fp})

def get_pcap(request):
    fp = request.GET['fp']
    conn = psycopg2.connect(user="d33tah", port=5432, host="localhost")
    rows = run_query(conn,
                     """SELECT fingerprint, portno
                        FROM service_probe
                        WHERE fingerprint_md5=decode(%s, 'hex')
                        LIMIT 1""", (fp,))

    port = rows[0]['portno']
    buf = str(rows[0]['fingerprint'])

    p = subprocess.Popen("hexdump -C | text2pcap -T %d,%d - -" % (port, port),
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         shell=True)
    p.stdin.write(buf)
    p.stdin.flush()
    p.stdin.close()

    ret = HttpResponse(p.stdout.read(), content_type='application/cap')
    ret['Content-disposition'] = 'attachment; filename="%s.pcap"' % fp
    return ret
