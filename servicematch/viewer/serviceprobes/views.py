import subprocess
import iptools

from django.http import HttpResponse
from django.shortcuts import render
from django.db import connection as conn


def run_query(conn, sql, args=()):

    ret = []

    cur = conn.cursor()
    cur.execute("SET enable_seqscan = off")
    cur.execute("SET enable_indexscan = off")
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

def do_hexdump(buf):
    p = subprocess.Popen(["hexdump", "-C"], stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE)
    p.stdin.write(buf)
    p.stdin.close()
    return p.stdout.read()

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
    rows = run_query(conn,
                     """SELECT fingerprint, portno
                        FROM service_probe
                        WHERE fingerprint_md5=decode(%s, 'hex')
                        LIMIT 1""", (fp,))

    port = rows[0]['portno']
    buf = str(rows[0]['fingerprint'])

    p = subprocess.Popen(["text2pcap", "-T", "%d,%d" % (port, port), "-", "-",
                          "-q"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    p.stdin.write(do_hexdump(buf))
    p.stdin.close()

    ret = HttpResponse(p.stdout.read(), content_type='application/cap')
    ret['Content-disposition'] = 'attachment; filename="%s.pcap"' % fp
    return ret

def product_list(request):
    rows = run_query(conn, "SELECT * FROM product_rdns_aggregate")
    result = []
    for row in rows:
        if not (row['product'] and row['product'].startswith("Konica Minolta bizhub BT")):
            result += [row]
    return render(request, 'product_list.html', {'rows': result,
                                                 'title': 'Products list'})

def view_product(request):
    product = request.GET['product']
    title = '"%s" - product details' % product
    rows = run_query(conn,
                     """SELECT * FROM product_rdns_count
                        WHERE product=%s
                        ORDER BY count DESC""",
                     (product, ))
    return render(request, 'view_product.html', {'rows': rows,
                                                 'product': product,
                                                 'title': title})

def show_sld(request):

    sld = request.GET['sld']
    product = request.GET['product']
    title = 'Details about SLD %s' % sld

    rows = run_query(conn,
                     """SELECT DISTINCT r.rdns, s.ip, s.portno, s.is_tcp,
                          encode(s.fingerprint_md5, 'hex') fingerprint_md5,
                          s.fingerprint, (
                             SELECT product
                             FROM service_probe_match m
                             WHERE m.fingerprint_md5=s.fingerprint_md5
                             LIMIT 1)
                         FROM service_probe s
                         JOIN service_probe_match m
                             ON m.fingerprint_md5=s.fingerprint_md5
                         JOIN rdns2 r ON s.ip=r.ip
                         WHERE r.sld=%s AND m.product=%s""", (sld, product))

    return render(request, 'show_ip.html', {'rows': rows,
                                            'ip': '',
                                            'title': title})
