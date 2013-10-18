#!/bin/bash

# run-research.sh - a simple script to run the Internet Census 2012 TCP/IP
# fingerprints research, compress its output and log script's standard error.

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <outfile.gz> <internet-census-fp-files>"
  exit 1;
fi

LOGFILE="research-log.txt"
OUTFILE=$1
shift

echo "Outfile = $OUTFILE"

tail -f --follow=name $LOGFILE &
TAIL_PID=$!

gunzip -c $@ | \
  python feeder.py --add-args="-r 3 -l" -m 90 - 2>research-log.txt | \
  pv -i 5 -l -s $(( 80652851 ))  | \
  gzip -1 > "$OUTFILE"

kill $TAIL_PID
