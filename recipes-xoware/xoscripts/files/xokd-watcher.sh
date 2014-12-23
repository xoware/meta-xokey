#!/bin/sh

#deamonize so we close stdout, if you want to see the debug you can remove '-d'
xokd -d
sleep 3

XOKD_PID=`ps |grep xokd |grep -v S80 |grep -v watcher|grep -v grep |awk '{ print $1}'|head -n1`


# stay here while xokd running
while [ -e /proc/${XOKD_PID} ]; do
	sleep 2 
done

logger "xokd ${XOKD_PID} exited"

#sleep to allow deugging
sleep 20
#if xokd exits reboot, ideally watchdog should do this
reboot
