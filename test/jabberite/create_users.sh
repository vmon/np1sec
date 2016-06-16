#!/bin/bash

#!/bin/bash
a=0
b=$1
while [ $a -lt $b ]
do
   echo "Adding participant$a"
   prosodyctl adduser participant$a@localhost < empty_pass.txt
   a=`expr $a + 1`
done

