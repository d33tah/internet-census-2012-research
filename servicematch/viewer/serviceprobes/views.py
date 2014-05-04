from django.http import HttpResponse
from django.shortcuts import render
import psycopg2
import psycopg2.extras
import iptools


def run_query(sql, args):

    ret = []

    conn = psycopg2.connect(user="d33tah", port=5432, host="localhost")
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
    return render(request, 'index.html')


def show_ip(request):

    ip = request.GET['ip']
    iprange = iptools.IpRange(ip)
    if len(iprange) > 256**2:
        return HttpResponse("Sorry, IP range too big.")
    start_ip = iptools.ipv4.long2ip(iprange.startIp)
    end_ip = iptools.ipv4.long2ip(iprange.endIp)

    rows = run_query("""SELECT DISTINCT r.rdns, s.ip, s.portno,
                                        s.fingerprint_md5, s.fingerprint, (
                             SELECT product
                             FROM service_probe_match m
                             WHERE m.fingerprint_md5=s.fingerprint_md5
                             LIMIT 1)
                         FROM service_probe s
                         JOIN rdns2 r ON s.ip=r.ip
                         WHERE s.ip>=%s AND s.ip<=%s""", (start_ip, end_ip))

    return render(request, 'show_ip.html', {'rows': rows, 'ip': ip})


def show_fp(request):
    fp = request.GET['fp']
    rows = run_query("""SELECT DISTINCT *
                                 FROM service_probe_match
                                 WHERE fingerprint_md5=%s""", (fp,))
    return render(request, 'show_fp.html', {'rows': rows, 'fp': fp})
