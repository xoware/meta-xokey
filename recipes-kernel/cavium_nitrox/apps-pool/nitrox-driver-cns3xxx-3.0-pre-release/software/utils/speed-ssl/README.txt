File: README.txt
Copyright Cavium Networks


Contents
========
1. What is Speed Test
2. System Requirements
3. Pre-Requisites
4. Performance measurement of different Nitrox APIs
5. Running Nitrox chip performance benchmarks 
6. Running Nitrox Non-Blocking application benchmarks 
7. Known Issues


1. What is Speed Test
=======================
  Speedtest is a test program for Nitrox to exercise the different SSL 
  operations for measuring performance of the Nitrox SSL APIs.
  
  There are two ways of measuring performance of the Nitrox for SSL protocol.

a) Nitrox Chip performance :
   It is used for measuring Nitrox SSL APIs chip performance. This can be 
   measured by the time taken between "the submission of fully loaded 
   command queue of the Nitrox and its completion". In this mode, SSL 
   requests keeps on hitting the Nitrox with fully loaded command queue 
   until specified time.

   This is the maximum performance one can get with the Nitrox chip. 

b) Nitrox API performance:
   It is used for measuring the Nitrox SSL APIs in Non-Blocking fashion at the
   application level. This is a time based performance measurement tool. 
   This can be measured from the "submission of the multiple 
   SSL requests from application continuously and polling for those SSL 
   requests for its completion in a specified amount of time duration". 
   At the end, throughput is calculated based on the amount of SSL requests 
   completed by Nitrox in a specified time duration by an application.



2. System Requirements
=======================
  This application should be run when the system is idle. It is recommended to
  use these applications on high end servers to get the desired performance of
  the Nitrox APIs.
  
  This application should run only on MAIN microcode.


3. Pre-Requisites
=================
    * It is assumed that Nitrox board is inserted in the host machine server
      as per the specifications outlined in the 'Hardware Quick Start Guide'.

    * Nitrox driver is compiled and loaded onto the host server machine. 
      For information on building and loading the Nitrox driver can be found
      at cavium/software/linux_install_driver.txt.



4. Performance measurement of different Nitrox APIs
===================================================
  There are two Speedtest applications available for measuring the SSL
  performance using Nitrox APIs.
    * speed_ssl.c      used for measuring Nitrox chip performance
    * nb_app_perf.c    used for measuring Non-Blocking API performance 

  Using above two applications, the following SSL operations can be run for
  measuring the performance of different Nitrox APIs.

    * SSL Record Processing
    * SSL Crypto Processing
    * RSA Operations with CRT, Non-CRT and ModExp
    * SSL Handshakes

  Edit the following parameters in the Makefile for different test combinations.

      CIPHER = AES128           # or AES256/DES3/RC4
      DIGEST = SHA1             # or MD5
      NB_TEST_DURATION = 2      # Non-Blocking test duration in seconds
      PKT_SIZES = 32 64 ...     # Different packet sizes used for record/crypto
                                # processing  tests
      RSA = RSA_CRT ...         # Different RSA operations
      MOD_LEN = 64 128 256      # Different Modulus length 
      HANDSHAKE = RSASERVERFULL # Only RSASERVERFULL is supported



5. Running Nitrox chip performance benchmarks 
============================================
  Use the following commands to run different SSL operations for measuring the 
  Nitrox chip performance.

    For SSL record processing
    bash #  make -s run_record      

    For SSL Crypto processing
    bash # make -s run_crypto

    For RSA operations 
    bash # make -s run_rsa

    For RSA SERVER FULL Handshakes 
    bash # make -s run_handshake
    
            OR

    Use the following command to run all the above tests
    bash # make -s run_all
    
  The above SSL Nitrox benchmarks can also be run using time based 
  performance approach. 

    bash # echo <Time in Sec> > /proc/cavium/speed_timeout

  After writing the time duration (in seconds) in /proc/cavium/speed_timeout, 
  using any of the above commands will run the respective benchmark tests for 
  specified amount of time duration.



6. Running Nitrox Non-Blocking application benchmarks 
======================================================
  Use the following commands to run different SSL operations for measuring the 
  Non-Blocking SSL API performance.

    For SSL Non-Blocking record processing benchmarks
    bash # make -s run_nb_record

    For SSL Non-Blocking Crypto processing benchmarks
    bash # make -s run_nb_crypto

    For RSA Non-Blocking operations benchmarks
    bash # make -s run_nb_rsa

    For RSA Non-Blocking SERVER FULL Handshakes benchmarks
    bash # make -s run_nb_handshakes

           OR 

    Use the following command to run all the above tests
    bash # make -s run_nb_all


7. Known Issues
===============
  a) If SSL and IPSec speed test run in parallel on Nitrox-PX 4x part, 
     some times driver shows 'failed to copy from kernel to user space'
  b) This utility works only when mainline microcode is loaded.

<EOF>
