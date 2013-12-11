#!/bin/bash
(
  for country in `cat countrycodes.txt`; do
    echo -n "$country: ";
    gunzip < thirdTry-goodonly-countrycodes.gz | \
      pv -l -s 20685990 | \
      awk "\$NF==\"$country\" { print $4; }" | \
      tr ',' '\n' | \
      grep '\[100\]' | \
      sed 's/\[100\]//g' | \
      pypy count-vendors.py
    ; done
) > by-country.txt
