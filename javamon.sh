#!/bin/ksh
#
#       Used to
#       top -H -b -p the editorial process
#       jstack it too
#
#       sticking the output into a timestamped file
#
export TZ=GB
source $HOME/.bashrc
MONDIR=/log/javamon/$1
OWNER=asadmin
DSTAMP=$(date +%Y_%m_%d)
#TSTAMP=$(date +%H:%M:%S)
PATH=/usr/jdk/latest/bin:/usr/local/bin:/usr/sbin:$PATH
export PATH
#
#       find the PID
#

PID=$(pgrep -o -f $1)

if [ -z "$PID" ]
then
        exit 1
fi

if [ ! -d ${MONDIR}/${DSTAMP} ]
then
        mkdir -p ${MONDIR}/${DSTAMP}
fi

cd ${MONDIR}/${DSTAMP}
#
#       Now get the info
#
#	processes
top -n 1  -H -b -p $PID > top.$(date +%H:%M:%S).txt
ps  -o pid,tid,pcpu,rss,size,start_time:10,time,vsize -L -p $PID > ps-Lp.$(date +%H:%M:%S).txt
#netstat -anp > netstat-ap.$(date +%H:%M:%S).txt

##
#	networks and nfs
netstat -i > netstat-i.$(date +%H:%M:%S).txt
netstat -tanp 2>/dev/null | grep $PID  > netstat-tanp.$(date +%H:%M:%S).txt
nfsstat -o all > nfsstat.$(date +%H:%M:%S).txt
nfsiostat-sysstat  > nfsiostat.$(date +%H:%M:%S).txt

#
#	jstacks
let i=0
while (( i < 4 ))
do
        FILE=jstack.$(date +%H:%M:%S).txt
        jstack $PID > $FILE
        sleep 15
        let i=i+1
done

#
#       Get the GC data
#

FILE=jstat.$(date +%H:%M:%S).txt
jstat  -gcutil  $PID 1s 10 > $FILE


