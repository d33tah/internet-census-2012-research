#!/usr/bin/python

from lxml import html
import subprocess

t = html.parse("http://www.nirsoft.net/countryip/")
for el in t.xpath('//a [not(contains(@href, "/"))]'):
  if el.get('href') is None:
    continue
  country, rest = el.get('href').split(".")
  assert(rest == "html")
  assert(country.isalnum())
  url = "http://www.nirsoft.net/countryip/%s.csv" % country
  subprocess.call("wget -P csv " + url, shell=True)
