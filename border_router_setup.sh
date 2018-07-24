#!/bin/bash

contiki_path=$1
cwd=$(pwd)
echo "Changing directory..."
cd "$contiki_path/examples/rpl-border-router"
echo "Activating python environment..."
source activate iot
make clean
echo "Setting target...." && \
    make TARGET=openmote-cc2538 savetarget && \
    echo "Setting board revision..." && \
    echo "BOARD_REVISION = REV_A1" >> Makefile.target && \
    echo "Uploading..." && \
    make border-router.upload && \
    echo "Connecting to router..." && \
    make connect-router | ts | tee $cwd/border_router.log
