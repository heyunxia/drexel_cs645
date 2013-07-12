#!/bin/bash
# A simple script that can be used, along with
# e.g., atoi(argv[1]), to brute-force solutions with an altering single byte
i=0
for i in $(seq 1 1 256)  ; do
echo "Testing $i"
./sploit3 $i
done
