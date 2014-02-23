#!/usr/bin/env pypy

import os
import time
import pickle
import collections
import sys

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "serviceprobes_index.settings")
from serviceprobes_index.models import TableEntry

total_items = []

for filename in os.listdir("raw"):
  with open(os.sep.join(["raw", filename])) as f:
    for line in f:
      if line.startswith("<tr><td>"):

        # convert the row to a sequence
        item = line[len("<tr><td>"):-len("</td></tr>\n")].split("</td><td>")

        entry = TableEntry()
        portno_and_proto = filename.split("_full.html")[0]
        entry.portno = portno_and_proto.split('_')[0]
        entry.is_tcp = portno_and_proto.split('_')[1] == "TCP"
        entry.servicename = item[0]
        entry.product_name = item[1]
        entry.product_version = item[2]
        entry.info = repr(item[3])
        entry.os_name = item[4]
        entry.devicetype = item[5]
        entry.count = item[6]
        entry.save()

        sys.stdout.write("\x00")
        sys.stdout.flush()
