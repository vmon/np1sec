#!/bin/bash

a=0
b=$1
c=0.1
while [ $a -lt $b ]
do
    echo "joining participant$a"
    ./jabberite --account=participant$a@localhost --password="" --server=conference.localhost --room=np1sectestroom &
    s=`echo $a \* $c \* $a \* $c + $a \* $c + 1 | bc -l`
    echo $s
    sleep $s
    a=`expr $a + 1`
done

