#!/bin/sh

set -x
exec >& /tmp/openvpn.up.log
echo ARGS=$@
env


iptables -t nat -I POSTROUTING -o $dev -j MASQUERADE
