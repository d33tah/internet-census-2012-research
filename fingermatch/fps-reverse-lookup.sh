#!/bin/bash

# Re-matches a subset of Internet Census data, filtering out the results that
# don't belong to a particular vendor.

INPUT_FILE="somefile.gz"
NMAP_OS_DB="../nmap-os-db"
VENDOR="microsoft"  # just an example.

LINES=`gunzip < $INPUT_FILE | \
  grep --line-buffered -v 'CT=%' | \
  grep --line-buffered -v 'OT=%' | \
  grep --line-buffered -v 'CU=%' | \
  wc -l`

gunzip < $INPUT_FILE | \
grep --line-buffered -v 'CT=%' | \
grep --line-buffered -v 'OT=%' | \
grep --line-buffered -v 'CU=%' | \
pv -l -s $LINES | \
while read line; do
  FP=`echo $line |
  awk '{ print $3 }' | \
  sed -e 's/$/\n/g' -e 's/,/\n/g'`

   if echo $FP | \
       ../fingermatch -f $NMAP_OS_DB -l 2>>error-log | \
      egrep -q `./generate-fpdb-lines.sh $NMAP_OS_DB $VENDOR`; then
    echo $line
  fi
done
