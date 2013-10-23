#!/bin/sh

# pep8.sh
#
# A tool I used to validate code quality.

for file in *.py; do
  pep8 $file --ignore=E111,E121
done
