#!/bin/sh

generate_certs () {
	echo "GENERATE CERTS"
	cd /xokcfg
	rm -f  server.key server.crt
	openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout server.key -out server.crt -subj '/C=US/ST=California/L=Sunnyvale/CN=xo1.xoware.com'
}


openssl rsa -in  /xokcfg/server.key  -noout
if [ "$?" -ne 0 ]
then
	logger -s "KEY invalid.. regenerate"
	generate_certs
fi


openssl x509 -in /xokcfg/server.crt  -noout
if [ "$?" -ne 0 ]
then
	logger -s "cert bad.. regenerate"
	generate_certs
fi