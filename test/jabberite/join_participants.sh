#!/bin/bash

a=0
b=$1
c=0
while [ $a -lt $b ]
do
    echo "joining participant$a"
    ./jabberite --account=participant$a@localhost --password="" --server=conference.localhost --room=np1sectestroom &
    s=`expr $a \* $c`
    sleep $c
    a=`expr $a + 1`
done

