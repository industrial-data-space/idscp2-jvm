#!/bin/bash

report="/tmp/IAS_REPORT"
sig="/tmp/IAS_SIG"
quote="/tmp/QUOTE"

touch $report
touch $sig

if [ ! -f $quote ]; then
    echo 2
    exit
fi

# Use Linkable Primary Key
res1=$(gramine-sgx-ias-request report -q $quote -k $1 -r $report -s $sig)
res2=$(gramine-sgx-ias-verify-report -r $report -s $sig --allow-outdated-tcb)

if [[ $res2 == *"IAS report: signature verified correctly"* ]]; then
    echo 1
    exit
else
    echo $res1 >> IAS_OUTPUT
    echo $res2 > IAS_OUTPUT
    echo 0
    exit
fi
