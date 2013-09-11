#!/bin/sh

if  [ -e /xokcfg/server.key ]; then
#	echo "key exists"
	exit 
fi

cd /xokcfg

openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout server.key -out server.crt -subj '/C=US/ST=California/L=Sunnyvale/CN=xo1.xoware.com'
