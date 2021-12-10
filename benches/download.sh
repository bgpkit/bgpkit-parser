#!/bin/bash

RIB_LOCAL=/tmp/rib-example.bz2
RIB_REMOTE=https://spaces.bgpkit.org/parser/rib-example.bz2

UPD_LOCAL=/tmp/update-example.gz
UPD_REMOTE=https://spaces.bgpkit.org/parser/update-example.gz

if test -f "$RIB_LOCAL"; then
    echo "rib file already exist: $RIB_LOCAL"
  else
    curl --silent $RIB_REMOTE -o $RIB_LOCAL
    echo "rib file downloaded to: $RIB_LOCAL"
fi

if test -f "$UPD_LOCAL"; then
    echo "rib file already exist: $UPD_LOCAL"
  else
    curl --silent $UPD_REMOTE -o $UPD_LOCAL
    echo "rib file downloaded to: $UPD_LOCAL"
fi
