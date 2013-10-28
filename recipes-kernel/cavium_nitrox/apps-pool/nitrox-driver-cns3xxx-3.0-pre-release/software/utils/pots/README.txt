File README.txt
Copyright Cavium Networks

Table of contents
=================
1. What is POTS?
2. Pre requisites
3. Build and execute POTS 
4. POTS result logs


1. What is POTS? 
=================
  The Power-on-Test-Suite (or POTS) is a diagnostic tool to verify the health 
  of Nitrox hardware, be it a custom-designed board or a Cavium supplied PCI 
  adapter card. 
  
  POTS is strictly designed for hardware diagnostic and trouble-shooting 
  purposes. Discontinue the use of POTS once you have determined that the
  hardware is functioning properly. Use microcode and drivers from the
  standard SDK.
  
  POTS is a user-mode application that has been tested under Linux OS and 
  FreeBSD OS.
  On need basis, porting may be required to migrate it to other flavors of
  Linux operating systems.


2. Pre requisites
=================
  a) This document assumes that the Nitrox Board(s) is already inserted in the
     host machine server.
  b) The Cavium driver for Nitrox is built and installed.
     (Refer cavium/software/linux_install_driver.txt for Linux, or
      Refer cavium/software/FreeBSD_install_driver.txt for FreeBSD
      for building and installing the Nitrox driver).


3. Build and execute POTS 
============================
  The POTS can be invoked using the following command.

  By compiling the driver will automatically build the pots.

  NOTE: If you want to build 32bit binaries on 64bit kernel,
        Please enable CFLAGS_LOCAL32 and LDFLAGS_LOCAL32 in
        the correspongind Makefile.

  # ./pots_main

  Once the above command is executed an interactive menu will be displayed,
  wherein one need to enter the option number and press <Enter>, 
  results will be displayed as PASSED/FAILED.

  User needs to scroll up to view the results.

  Note : If the host server machine has Nitrox-multi cards (2 Nitrox cards),
         after invoking "./pots_main", user has to select on which card the
         pots test need to be run.


4. POTS result logs
====================
  Pots program creates several output files under ./logs directory.
      - results.log (prints out results of each test run)
      - pots.log (contains detailed log, debug and diagnostic info)
      - rc4.log (for detailed rc4 test results)
      - hmac.log (for sha-1 and md5 detailed test results)
      - 3des.log (for detailed 3des test results)
      - modex.log (for detailed mod exp test results)
      - aes.log (for detailed aes test results)
