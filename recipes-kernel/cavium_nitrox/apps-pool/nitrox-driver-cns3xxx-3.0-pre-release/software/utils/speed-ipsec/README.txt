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
  Speedtest is a test program for Nitrox to exercise the different IPSec
  operations for measuring performance of the Nitrox IPSec APIs.
  
  There are two ways of measuring performance of the Nitrox for IPSec protocol.

a) Nitrox Chip performance :
   It is used for measuring Nitrox IPSec APIs chip performance. This can be 
   measured by the time taken between "the submission of fully loaded 
   command queue of the Nitrox and its completion". In this mode, IPSec 
   requests keeps on hitting the Nitrox with fully loaded command queue 
   until specified time.

   This is the maximum performance one can get with the Nitrox chip. 

b) Nitrox API performance:
   It is used for measuring the Nitrox IPSec APIs in Non-Blocking fashion at the
   application level. This is a time based performance measurement tool. 
   This can be measured from the "submission of the multiple 
   IPSec requests from application continuously and polling for those IPSec 
   requests for its completion in a specified amount of time duration". 
   At the end, throughput is calculated based on the amount of IPSec requests 
   completed by Nitrox in a specified time duration by an application.



2. System Requirements
=======================
  This application should be run when the system is idle. It is recommended to
  use these applications on high end servers to get the desired performance of
  the Nitrox APIs.



3. Pre-Requisites
=================
    * It is assumed that Nitrox board is inserted in the host machine server
      as per the specifications outlined in the 'Hardware Quick Start Guide'.

    * Nitrox driver is compiled and loaded onto the host server machine. 
      For information on building and loading the Nitrox driver can be found
      at cavium/software/linux_install_driver.txt.



4. Performance measurement of different Nitrox APIs
===================================================
  There are two Speedtest applications available for measuring the IPSec
  performance using Nitrox APIs.
    * ipsec_speed.c      used for measuring Nitrox chip performance
    * ipsec_speednb.c    used for measuring Non-Blocking API performance 

  Using above two applications, the following IPSec operations can be run for
  measuring the performance of different Nitrox APIs.

    * IPSec Outbound Processing 
    * ESP/AH IPSec protocols
    * Tunnel/Transport mode of IPSec operations

  Edit the following parameters in the Makefile for different test combinations.

      PKT_SIZES     = 64 128 ...  # Different packet sizes to be tested 
      IPSEC_PROCESS = OUTBOUND    # Currently only Outbound is supported 
      IPSEC_PROTO   = ESP         # Or AH
      IPSEC_ALGO    = AES128      # Or AES192, AES256, DESCBC, DES3CBC
      IPSEC_AUTH    = SHA1        # Or MD5 
      IPSEC_MODE    = TUNNEL      # Or TRANSPORT
      NB_TEST_DURATION = 2        # Non-Blocking test duration in seconds



5. Running Nitrox chip performance benchmarks 
============================================
  Use the following command to run IPSec outbound processing for measuring the 
  Nitrox chip performance.

    For IPSec outbound processing
    bash #  make -s run

  The above IPSec Nitrox benchmarks can also be run using time based 
  performance approach. 

    bash # echo <Time in Sec> > /proc/cavium/speed_timeout

  After writing the time duration (in seconds) in /proc/cavium/speed_timeout, 
  using any of the above commands will run the respective benchmark tests for 
  specified amount of time duration.



6. Running Nitrox Non-Blocking application benchmarks 
======================================================
  Use the following command to run IPSec outbound processing for measuring the 
  Non-Blocking IPSec API performance.

    For Non-Blocking IPSec outbound processing
    bash # make -s run_nb


7. Known Issues
===============
  a) If SSL and IPSec speed test run in parallel on Nitrox-PX 4x part, 
     some times driver shows 'failed to copy from kernel to user space'
  b) This utility works only when mainline microcode is loaded.
<EOF>
