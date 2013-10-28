
Table of Contents
=================
1. Pre-requisites 
2. Building Turbossl for vega 
3. Loading Turbossl on vega board
4. Supported Features


 1. Pre-requisites
 ================================================
    a) This document assumes that nitrox driver is already compiled and booted
	in vega board with ssl microcode according to the readme provided in the dri    ver package. 

2.Building Turbossl for vega
============================
	Copy TurboSSL-0.9.8j /cavium/software/apps/
	       # cd TurboSSL-0.9.8j/
		   # ./Configure compiler:arm-linux-gcc no-asm no-threads cavium
		   # make clean
		   # make
	The openssl binary will be generated in ./apps/ directory	   

3. Loading TurboSSL on vega board
=========================================
		Load the nitrox driver.Transfer the apps and certs directory of TurboSSL to vega board.
		To run server
		# cd apps/
		# ./openssl s_server -cert <certificate> -key <key file> -msg 
		To run client( on the host machine)
        # /usr/bin/openssl s_client -connect <IP Addr>:<Port> -cipher AES128-SHA -tls1 (or ssl3) -msg
        By default openssl s_server listens on port 4433.

NOTE: Only server mode is presently supported on vega board.Since microcode
doesn't support client mode doesn't work in vega board. 
NOTE: This package is customized for vega board Nitrox-Px card.

 4. Supported Features
 =====================
 TurboSSL Features:
 +--------------------------+---------------------------------------------+
 |      Name                |       Supported                             |
 +--------------------------+---------------------------------------------+
 | Protocol versions        |   ssl3 and tls1                             |
 +------------------------------------------------------------------------+
 | Server mode              |   Y                                         |
 +--------------------------+---------------------------------------------+
 | Client mode              |   N                                         |
 +------------------------------------------------------------------------+
 | Cipher suite             |  AES128-SHA                                 |
 |                          |  AES256-SHA                                 |
 |                          |  RC4-MD5                                    |
 |                          |  RC4-SHA                                    |
 |                          |  DES-CBC-SHA                                |
 |                          |  DES-CBC3-SHA                               |
 |                          |  EXP-RC4-MD5                                |
 |                          |  EXP-DES-CBC-SHA                            |
 +------------------------------------------------------------------------+
 |                          |  AES128,AES256                              |
 | Offloaded Crypto         |  RC4                                        |
 |                          |  DES/DES3                                   |
 +------------------------------------------------------------------------+
 | Offloaded Digest         |  MD5                                        |
 |                          |  SHA1                                       |
 +------------------------------------------------------------------------+
 | Server certificates size |  Upto 2K (For Nitrox-I / Nitrox-Lite)       |
 |                          |  Upto 4K (For Nitrox-Px)                    |
 +------------------------------------------------------------------------+
 | Client Authentication    |  Y                                          |
 +------------------------------------------------------------------------+
 | Session Resumption       |  Y                                          |
 +------------------------------------------------------------------------+
 | Renegotiation            |  Y                                          |
 +------------------------------------------------------------------------+
 | TLS Ticket Option        |  N                                          |
 +------------------------------------------------------------------------+


