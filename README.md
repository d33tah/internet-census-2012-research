internet-census-2012-research
=============================

This is README for internet-census-2012-research.
This repository contains tools related to analysing
Internet Census 2012 data set, namely OS and service
fingerprints.

You can find the relevant code in *fingermatch* and
*servicematch* directories. It is embedded in Nmap's
source tree due to dependencies - you cannot build
servicematch/fingermatch without Nmap's source code.

To build the tools, just run:

  ./configure && make
  
You will find "servicematch" binary in "servicematch"
directory. Same goes for "fingermatch".
