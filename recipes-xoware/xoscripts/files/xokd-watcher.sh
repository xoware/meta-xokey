#!/bin/sh

PID_FILE='/tmp/xokd.pid'

#deamonize so we close stdout, if you want to see the debug you can remove '-d'
xokd -P ${PID_FILE} -d
sleep 3

#XOKD_PID=`ps |grep xokd |grep -v S80 |grep -v watcher|grep -v grep |awk '{ print $1}'|head -n1`

if [ -e ${PID_FILE} ]
then 
	XOKD_PID=`cat ${PID_FILE}`
else
	logger "xokd PID FILE ${PID_FILE} not found" 
	sleep 20
	reboot
	exit
fi

# stay here while xokd running
while [ -e /proc/${XOKD_PID} ]; do
	sleep 2 
done

# allow a debug connection on crash
telnetd -l /bin/sh

logger "xokd ${XOKD_PID} exited"
logread | gzip -c  > /storage/core/log.gz

#sleep to allow deugging
sleep 20
#if xokd exits reboot, ideally watchdog should do this
reboot
