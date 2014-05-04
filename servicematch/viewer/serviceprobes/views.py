from django.http import HttpResponse
import psycopg2
import psycopg2.extras
import iptools

def index(request):
    return HttpResponse("<form action='show_ip'><input name='ip' /></form>")

def escape(s):
    return repr(str(s))[1:-1].replace('<', '&gt;').replace('>', '&lt;')

def escape_fp(fp):
    return '\\x' + ''.join(('%2s' % hex(ord(c))[2:]).replace(' ', '0') for c in fp)

def default_process(k):
    for i in range(len(k)):
        k[i] = escape(k[i])
    return k

def show_query(sql, args, process=default_process, process_columns=lambda x: x):
    conn = psycopg2.connect(user="d33tah", port=5432, host="localhost")
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(sql, args)
    ret = ""
    if cur.rowcount != -1:
        ret += "<h1>Got %s rows" % cur.rowcount
    ret += "<table border=1><tr>\n"
    for k in process_columns(cur.description):
        ret += ("<th>" + k[0] + "</th>")
    ret += "</tr>"
    for k in cur:
        k = process(k)
        ret += "<tr><td>" + "</td><td>".join(k) + "</tr>\n"
    return ret

def show_ip(request):
    ip = request.GET['ip']
    iprange = iptools.IpRange(ip)
    if len(iprange) > 255**2:
        return HttpResponse("Sorry, IP range too big.")
    start_ip = iptools.ipv4.long2ip(iprange.startIp)
    end_ip = iptools.ipv4.long2ip(iprange.endIp)

    def process_columns(k):
        ret = list(k)
        del ret[3] # proto
        del ret[4] # statuscode
        del ret[5] # fingerprint_md5
        return ret

    def process(k):
        url = "/show_fp?fp=" + escape_fp(k[7])
        del k[7]
        k[2] = escape(k[2]) + "/" + "TCP" if k[3] else "UDP"
        del k[3]
        del k[4]
        for i in range(len(k)):
            if i == 6:
                k[i] = "<a href='%s'>%s</a>" % (url, escape(k[i]))
            else:
                k[i] = escape(k[i])
        return k

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
    ret += show_query("SELECT DISTINCT * FROM service_probe_match WHERE fingerprint_md5=%s", (fp,))
    return HttpResponse(ret)
