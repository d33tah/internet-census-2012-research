import subprocess
import iptools

from django.http import HttpResponse
from django.shortcuts import render
from serviceprobes.models import run_query
from django.db import connection as conn


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
                          f.fingerprint, (
                             SELECT p.product
                             FROM match m
                             JOIN product_proxy pp
                                 ON m.product_proxy_id=pp.product_proxy_id
                             JOIN product p ON pp.product_id=p.product_id
                             WHERE m.fingerprint_md5=s.fingerprint_md5
                             LIMIT 1)
                         FROM probe s
                         LEFT JOIN rdns r ON s.ip=r.ip::inet
                         LEFT JOIN fingerprint f
                           ON s.fingerprint_md5=f.fingerprint_md5
                         WHERE s.ip>=%s AND s.ip<=%s""", (start_ip, end_ip))

    return render(request, 'show_ip.html', {'rows': rows,
                                            'ip': ip,
                                            'title': title})


# TODO: test what happens if we hit a product_proxy item that has a null
# product_id
def one_ip(request):

    ip = request.GET['ip']
    title = 'Details about IP address %s' % ip

    fingerprint_rows = run_query(conn,
                     """
                     SELECT probe.*, m.*, s.*, p.*, o.*, d.*, pld.payload, f.*,
                       encode(probe.fingerprint_md5, 'hex') fingerprint_md5
                     FROM probe
                     LEFT JOIN match m
                       ON m.fingerprint_md5=probe.fingerprint_md5
                     LEFT JOIN fingerprint f
                       ON probe.fingerprint_md5=f.fingerprint_md5
                     LEFT JOIN service s ON m.service_id=s.service_id
                     LEFT JOIN product_proxy pp
                         ON m.product_proxy_id=pp.product_proxy_id
                     LEFT JOIN product p ON pp.product_id=p.product_id
                     LEFT JOIN os o ON m.os_id=o.os_id
                     LEFT JOIN devicetype d ON p.devicetype_id=d.devicetype_id
                     LEFT JOIN payload pld ON probe.payload_id=pld.payload_id
                     WHERE probe.ip=%s""", (ip,))

    rdns_rows = run_query(conn, "SELECT r.rdns FROM rdns r WHERE r.ip=%s",
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
        rows_dict[key]['payloads'] = []
        rows_dict[key]['times_taken'] = []
        rows_dict[key]['products'] = []
        rows_dict[key]['product_tuples'] = []

      rows_dict[key]['payloads'] += [row['payload']]
      rows_dict[key]['times_taken'] += [row['time_taken']]
      if not product_tuple in rows_dict[key]['product_tuples']:
          rows_dict[key]['products'] += [product_dict]
          rows_dict[key]['product_tuples'] += [product_tuple]

    rows = rows_dict.values()

    return render(request, 'one_ip.html', {'rows': rows,
                                            'ip': ip,
                                            'title': title})

# TODO: see the query above.
def show_fp(request):
    fp = request.GET['fp']
    title = 'Details about fingerprint ID %s' % fp
    rows = run_query(conn,
                     """
                     SELECT DISTINCT *
                     FROM match m
                     LEFT JOIN service s ON m.service_id=s.service_id
                     LEFT JOIN product_proxy pp
                         ON m.product_proxy_id=pp.product_proxy_id
                     LEFT JOIN product p ON pp.product_id=p.product_id
                     LEFT JOIN os o ON m.os_id=o.os_id
                     LEFT JOIN devicetype d ON p.devicetype_id=d.devicetype_id
                     WHERE fingerprint_md5=decode(%s, 'hex')
                     """, (fp,))
    fingerprint_rows = run_query(conn,
                                 """SELECT fingerprint from fingerprint
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
    port = int(run_query(conn, """SELECT portno
                                  FROM probe
                                  WHERE fingerprint_md5=decode(%s, 'hex')
                                  LIMIT 1""", (fp,)
                          )[0]['portno'])
    buf = str(run_query(conn,
                        """SELECT fingerprint
                           FROM fingerprint
                           WHERE fingerprint_md5=decode(%s, 'hex')
                           LIMIT 1""", (fp,))[0]['fingerprint'])

    p = subprocess.Popen(["text2pcap", "-T", "%d,%d" % (port, port + 1),
                          "-", "-", "-q"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    p.stdin.write(do_hexdump(buf))
    p.stdin.close()

    ret = HttpResponse(p.stdout.read(), content_type='application/cap')
    ret['Content-disposition'] = 'attachment; filename="%s.pcap"' % fp
    return ret

def product_list(request):
    rows = run_query(conn, """
        SELECT p.product, agg.*
        FROM precomputed_product_rdns_aggregate agg
        LEFT JOIN product p ON p.product_id=agg.product_id
        """)
    result = []
    for row in rows:
        if not (row['product'] and row['product'].startswith("Konica Minolta bizhub BT")):
            result += [row]
    return render(request, 'product_list.html', {'rows': result,
                                                 'title': 'Products list'})

def view_product(request):
    product_id = request.GET['product_id']
    product_name = run_query(conn,
                             "SELECT product FROM product WHERE product_id=%s",
                             (product_id, ))[0]['product']
    rows = run_query(conn, """
        SELECT p.product, cnt.*
        FROM precomputed_product_rdns_count cnt
        LEFT JOIN product p ON p.product_id=cnt.product_id
        WHERE p.product_id=%s
        ORDER BY cnt.count DESC
        """, (product_id, ))
    title = '"%s" - product details' % product_name
    return render(request, 'view_product.html', {'rows': rows,
                                                 'product': product_name,
                                                 'product_id': product_id,
                                                 'title': title})

def by_eld(request):
    eld = request.GET['eld']
    title = '"%s" - products by entity domain' % eld
    rows = run_query(conn, """
        SELECT p.product, cnt.*
        FROM precomputed_product_rdns_count cnt
        LEFT JOIN product p ON p.product_id=cnt.product_id
        WHERE sld=%s
        ORDER BY cnt.count DESC
        """, (eld, ))
    return render(request, 'by_eld.html', {'rows': rows,
                                           'eld': eld,
                                           'title': title})

def devicetypes_by_eld(request):
    eld = request.GET['eld']
    title = '"%s" - devicetypes by entity domain' % eld
    rows = run_query(conn, """
        SELECT cnt.*, d.devicetype
        FROM precomputed_devicetype_eld_count cnt
        LEFT JOIN devicetype d ON d.devicetype_id=cnt.devicetype_id
        WHERE sld=%s
        ORDER BY cnt.eld_count DESC
        """, (eld, ))
    return render(request, 'devicetypes_by_eld.html', {'rows': rows,
                                           'eld': eld,
                                           'title': title})


# TODO: see a TODO above
def show_sld(request):

    sld = request.GET['sld']
    product_id = request.GET['product_id']
    title = 'Details about SLD %s' % sld

    rows = run_query(conn,
                     """

SELECT DISTINCT r.rdns, s.ip, s.portno, s.is_tcp,
                          encode(s.fingerprint_md5, 'hex') fingerprint_md5,
                          f.fingerprint, (
                             SELECT p.product
                             FROM match m
                             JOIN product_proxy pp
                             JOIN product p ON m.product_id=p.product_id
                             WHERE m.fingerprint_md5=s.fingerprint_md5
                             LIMIT 1)
                         FROM probe s
                         LEFT JOIN fingerprint f
                           ON s.fingerprint_md5=f.fingerprint_md5
                         LEFT JOIN match m
                             ON m.fingerprint_md5=s.fingerprint_md5
                         LEFT JOIN rdns r ON s.ip=r.ip
                         WHERE r.sld=%s AND m.product_id=%s
""", (sld, product_id))

    return render(request, 'show_ip.html', {'rows': rows,
                                            'ip': '',
                                            'title': title})

def distinct_products_for_rdns_by_kw(request):

    kw = request.GET['kw']
    title = 'Top 100 domains with distinct product types for keyword "%s"' % kw
    kw_wildcard = "%%%s%%" % kw

    rows = run_query(conn,
                     """
                     SELECT
                       sld
                     , count ( distinct p.product_id )
                     FROM precomputed_product_rdns_count pr
                     JOIN product p
                      ON pr.product_id=p.product_id
                     WHERE p.product ILIKE %s
                     GROUP BY pr.sld
                     ORDER BY count ( distinct p.product_id ) DESC
                     LIMIT 100;
                     """, (kw_wildcard, ), disable_seqscan=False)

    return render(request, 'distinct_products_for_rdns_by_kw.html',
                  {'rows': rows, 'title': title})
