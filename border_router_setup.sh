#!/bin/bash

cwd=$(pwd)
echo "change dir"
cd ../contiki-ng-konrad/examples/rpl-border-router
echo "set target"
make TARGET=openmote-cc2538 savetarget
echo "set board revision"
echo "BOARD_REVISION = REV_A1" >> Makefile.target
echo "upload"
make border-router.upload
echo "connect"
make connect-router | ts | tee $cwd/border_router.log
