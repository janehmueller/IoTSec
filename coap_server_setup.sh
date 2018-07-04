#!/bin/bash

cwd=$(pwd)
echo "change dir"
cd ../contiki-ng-konrad/examples/coap/coap-example-server
echo "set target"
make TARGET=openmote-cc2538 savetarget
echo "set board revision"
echo "BOARD_REVISION = REV_A1" >> Makefile.target
echo "upload"
make coap-example-server.upload MOTE=1
echo "connect"
make login MOTE=1 | ts | tee $cwd/coap_server_log.txt
