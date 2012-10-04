#!/bin/sh
# We do this because we want to make sure the dependencies
# are also included in the browser applet. There may be
# a better way :)
cp -r ../../scuba/scuba_sc_j2se/src/* .
cp -r ../../scuba/scuba_smartcards/src/* .
cp -r ../../scuba/scuba_util/src/* .
