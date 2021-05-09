#!/bin/bash
for VARIABLE in 1 2 3 4;
do
    if  [[ $VARIABLE == 1 ]]
    then
    gtimeout 20 tcpdump -i en0 -w $VARIABLE.pcap
    else 
    a=$((VARIABLE-1))
    echo "$a"
    python3 ics_detection.py $a.pcap
    sleep 20 &
    gtimeout 20 tcpdump -i en0 -w $VARIABLE.pcap
    fi
done