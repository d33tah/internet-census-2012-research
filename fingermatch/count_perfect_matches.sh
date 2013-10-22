#!/bin/sh

# count_perfect_matches.sh - read the uncompressed run-research.sh output from
# the standard input, extract and count the perfect matches and print the
# results to the standard output.

cut -f3 - \
  | tr ',' '\n' \
  | grep '\[100\]' \
  | sed 's/\[100\]//' \
  | uniq --count \
  | sort -n -r
