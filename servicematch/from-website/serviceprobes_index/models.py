from django.db import models

class TableEntry(models.Model):
  portno = models.IntegerField(db_index=True)
  is_tcp = models.BooleanField(db_index=True)
  servicename = models.CharField(max_length=255,db_index=True, blank=True)
  product_name = models.CharField(max_length=255,db_index=True,blank=True)
  product_version = models.CharField(max_length=255,db_index=True,blank=True)
  info = models.CharField(max_length=255,db_index=True,blank=True)
  os_name = models.CharField(max_length=255,db_index=True,blank=True)
  devicetype = models.CharField(max_length=255,db_index=True,blank=True)
  count = models.IntegerField()
