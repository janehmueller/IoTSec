#!/bin/bash

contiki_path=$1
cwd=$(pwd)
echo "Changing directory..."
cd "$contiki_path/examples/coap/coap-example-server"
echo "Activating python environment..."
source activate iot
make clean
echo "Setting target...." && \
    make TARGET=openmote-cc2538 savetarget && \
    echo "Setting board revision..." && \
    echo "BOARD_REVISION = REV_A1" >> Makefile.target && \
    echo "Uploading..." && \
    make coap-example-server.upload MOTE=1 && \
    echo "Connecting to router..." && \
    make login MOTE=1 | ts | tee $cwd/coap_server.log
