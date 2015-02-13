from django.db import models
from django.db import connection as conn

import logging
logger = logging.getLogger(__name__)

def run_query(conn, sql, args=()):

    logger.error("run_query(sql=%s, args=%s)" % (sql, repr(args)))

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

class OperatingSystem(models.Model):

    class Meta:
        db_table = 'os'
        ordering = ['os']

    os_id = models.AutoField(primary_key=True)
    os = models.TextField()

    def __str__(self):
        return str(self.os)
    __repr__ = __str__

class Vendor(models.Model):

    class Meta:
        db_table = 'vendor'
        ordering = ['vendor']

    vendor_id = models.AutoField(primary_key=True)
    vendor = models.TextField()

    def __str__(self):
        return str(self.vendor)
    __repr__ = __str__

class DeviceType(models.Model):

    class Meta:
        db_table = 'devicetype'
        ordering = ['devicetype']

    devicetype_id = models.AutoField(primary_key=True)
    devicetype = models.TextField()

    def __str__(self):
        return str(self.devicetype)
    __repr__ = __str__

class Service(models.Model):

    class Meta:
        db_table = 'service'
        ordering = ['service']

    service_id = models.AutoField(primary_key=True)
    service = models.TextField()

    def __str__(self):
        return str(self.service)
    __repr__ = __str__

class Payload(models.Model):

    class Meta:
        db_table = 'payload'
        ordering = ['payload']

    payload_id = models.AutoField(primary_key=True)
    payload = models.TextField()

    def __str__(self):
        return str(self.payload)
    __repr__ = __str__

class Product(models.Model):

    class Meta:
        db_table = 'product'
        ordering = ['product']

    product_id = models.AutoField(primary_key=True)
    product = models.TextField()
    devicetype = models.ForeignKey('Devicetype', blank=True, null=True)
    vendor = models.ForeignKey('Vendor', blank=True, null=True)

    def __str__(self):
       return str(self.product)
    __repr__ = __str__

    def pattern_lines(self):
       extract_values = lambda x: x.values()
       lines = map(extract_values, run_query(conn, """SELECT DISTINCT lineno
                                                      FROM match
                                                      WHERE product_id=%s""",
                                             [self.product_id]))
       lines_flattened = map(sum, lines)
       return lines_flattened
