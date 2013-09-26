#!/bin/sh

set -x
exec >& /tmp/openvpn.down.log
echo ARGS=$@
env


iptables -t nat -D POSTROUTING -o $dev -j MASQUERADE
