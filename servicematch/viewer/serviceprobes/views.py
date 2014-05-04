from django.http import HttpResponse
from django.utils.html import escape
import psycopg2
import psycopg2.extras
import iptools


def escaped_repr(s):
    return escape(repr(str(s))[1:-1])


def escape_fp(fp):
    hexed = "\\x"
    for c in fp:
        hexed += ('%2s' % hex(ord(c))[2:]).replace(' ', '0')
    return hexed


def default_process(row):
    for i in range(len(row)):
        row[i] = escaped_repr(row[i])
    return row


def show_query(sql, args, process=default_process,
               process_columns=lambda x: x, horizontal=True):

    ret = ""

    conn = psycopg2.connect(user="d33tah", port=5432, host="localhost")
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(sql, args)

    if cur.rowcount != -1:
        ret += "<h1>Got %s rows" % cur.rowcount
    columns = process_columns(cur.description)

    if horizontal:
        ret += "<table border=1><tr>\n"
        for column in columns:
            ret += ("<th>" + column[0] + "</th>")
        ret += "</tr>"

    for row in cur:
        row_processed = process(row)
        if horizontal:
            ret += "<tr><td>" + "</td><td>".join(row_processed) + "</tr>\n"
        else:
            ret += '<table>'
            for i in range(len(columns)):
                ret += "<tr><th>%s</th><td>%s</td></tr>" % (columns[i][0],
                                                            row_processed[i])
            ret += '</table>'

    if horizontal:
        ret += '</table>'

    return ret


def index(request):
    return HttpResponse("<form action='show_ip'><input name='ip' /></form>")


def show_ip(request):
    ip = request.GET['ip']
    iprange = iptools.IpRange(ip)
    if len(iprange) > 255**2:
        return HttpResponse("Sorry, IP range too big.")
    start_ip = iptools.ipv4.long2ip(iprange.startIp)
    end_ip = iptools.ipv4.long2ip(iprange.endIp)

    def process_columns(columns):
        ret = list(columns)
        del ret[3]  # proto
        del ret[4]  # statuscode
        del ret[5]  # fingerprint_md5
        return ret

    def process(row):
        url = "/show_fp?fp=" + escape_fp(row[7])
        del row[7]
        row[2] = escaped_repr(row[2]) + "/" + "TCP" if row[3] else "UDP"
        del row[3]
        del row[4]
        for i in range(len(row)):
            if i == 6:
                row[i] = "<a href='%s'>%s</a>" % (url, escaped_repr(row[i]))
            else:
                row[i] = escaped_repr(row[i])
        return row

    ret = "<form action='show_ip'><input name='ip' /></form>\n"
    ret += show_query("""
                         SELECT r.rdns, s.*, (
                             SELECT product
                             FROM service_probe_match m
                             WHERE m.fingerprint_md5=s.fingerprint_md5
                             LIMIT 1)
                         FROM service_probe s
                         JOIN rdns2 r ON s.ip=r.ip
                         WHERE s.ip>=%s AND s.ip<=%s""", (start_ip, end_ip),
                      process, process_columns)
    return HttpResponse(ret)


def show_fp(request):
    fp = request.GET['fp']

    ret = "<form action='show_fp'><input name='fp' /></form>"
    ret += show_query("""SELECT DISTINCT *
                         FROM service_probe_match
                         WHERE fingerprint_md5=%s""", (fp,))
    return HttpResponse(ret)
