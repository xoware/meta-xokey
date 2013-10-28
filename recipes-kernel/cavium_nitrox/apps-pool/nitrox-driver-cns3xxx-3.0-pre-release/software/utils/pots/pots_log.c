/*
 * pots_log.c:
 *   Contains functions for logging info to log file
 */
 /*
 * Copyright (c) 2003-2005, Cavium Networks. All rights reserved.
 *
 * This Software is the property of Cavium Networks. The Software and all 
 * accompanying documentation are copyrighted. The Software made available here 
 * constitutes the proprietary information of Cavium Networks. You agree to take * 
 * reasonable steps to prevent the disclosure, unauthorized use or unauthorized 
 * distribution of the Software. You shall use this Software solely with Cavium 
 * hardware. 
 *
 * Except as expressly permitted in a separate Software License Agreement 
 * between You and Cavium Networks, You shall not modify, decompile, 
 * disassemble, extract, or otherwise reverse engineer this Software. You shall
 * not make any copy of the Software or its accompanying documentation, except 
 * for copying incident to the ordinary and intended use of the Software and 
 * the Underlying Program and except for the making of a single archival copy.
 *
 * This Software, including technical data, may be subject to U.S. export 
 * control laws, including the U.S. Export Administration Act and its 
 * associated regulations, and may be subject to export or import regulations 
 * in other countries. You warrant that You will comply strictly in all 
 * respects with all such regulations and acknowledge that you have the 
 * responsibility to obtain licenses to export, re-export or import the 
 * Software.
 *
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" AND 
 * WITH ALL FAULTS AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR WARRANTIES, 
 * EITHER EXPRESS,IMPLIED, STATUTORY,OR OTHERWISE, WITH RESPECT TO THE SOFTWARE,
 * INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR DESCRIPTION, 
 * OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM SPECIFICALLY 
 * DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY, 
 * NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE,LACK OF VIRUSES,ACCURACY OR
 * COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO 
 * DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE OF THE 
 * SOFTWARE LIES WITH YOU.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <string.h>

#include "pots.h"

extern pots_sts pots_st;


/*
 * pots_open_file:
 *       - Opens the log file 
 *       - Returns the FILE *, or NULL on error
 */
FILE *pots_open_file(char *fname)
{
   
   FILE *fp;

   if ((fp = fopen(fname, "w+")) == NULL ) {
      printf("pots_open_file(): fopen(%s) failed %s <%d>\n",
            fname, strerror(errno), errno);
      return(NULL);
   }
   
   setbuf(fp, NULL);

   return(fp);

} /* end pots_open_file() */


/*
 * pots_close_log:
 *    - Closes the log file.
 */
void pots_close_log(FILE *fp)
{
   fclose(fp);
}


/*
 * pots_should_log:
 *    - Returns 1 if the msg should be written to the log file, else 0
 */
int pots_should_log(int prog_loglvl, int cur_lvl)
{
   if ( prog_loglvl & cur_lvl )
      return(1);
   return(0);
}


/* 
 * get_time:
 *        - Formats the current time into the buffer.
 */
char *get_time(char *dp)
{
   time_t t;
   struct tm *tm_ptr;

   if ( time(&t) == -1 ) {
      strcpy(dp, "time() failed");
      return(dp);
   }

   if ((tm_ptr = localtime(&t)) == NULL)  {
      strcpy(dp, "localtime() failed");
      return(dp);
   }
   
   sprintf(dp, "%02d/%02d/%02d %02d:%02d:%02d", 
         tm_ptr->tm_mon,
         tm_ptr->tm_mday,
         tm_ptr->tm_year,
         tm_ptr->tm_hour,
         tm_ptr->tm_min,
         tm_ptr->tm_sec);

   return(dp);

} // end get_time()


/* 
 * pots_log:
 *       - Checks if msg should be written to log file.
 *          - If yes writes msg.
 *       - Returns 1 if msg is written, 0 if not.
 */
int pots_log(int cur_lvl, char *fmt, ...)
{
   char datebuf[100];
   va_list ap;
   
   if ( pots_should_log(pots_st.pt_prog_loglvl, cur_lvl) ) {
      fprintf(pots_st.pt_lfp, "%s: ", get_time(datebuf));
      va_start(ap, fmt);
      vfprintf(pots_st.pt_lfp, fmt, ap);
      va_end(ap);
      return(1);
   }

   return(0);

} /* end pots_log() */


/*
 * Same as above, except, this does not print date/time.
 */
int pots_log0(int cur_lvl, char *fmt, ...)
{
   va_list ap;
   
   if ( pots_should_log(pots_st.pt_prog_loglvl, cur_lvl) ) {
      va_start(ap, fmt);
      vfprintf(pots_st.pt_lfp, fmt, ap);
      va_end(ap);
      return(1);
   }

   return(0);

} /* end pots_log0() */


/* also prints msg on stdout */
int pots_log2(int cur_lvl, char *fmt, ...)
{
   char datebuf[100];
   va_list ap;
   
   if ( pots_should_log(pots_st.pt_prog_loglvl, cur_lvl) ) {
      fprintf(pots_st.pt_lfp, "%s: ", get_time(datebuf));
      va_start(ap, fmt);
      vfprintf(pots_st.pt_lfp, fmt, ap);
      printf(fmt, ap);
      va_end(ap);
      return(1);
   }

   return(0);

} /* end pots_log2() */


/*
 * $Id: pots_log.c,v 1.3 2008/10/24 08:43:51 ysandeep Exp $
 * $Log: pots_log.c,v $
 * Revision 1.3  2008/10/24 08:43:51  ysandeep
 * NPLUS support added
 *
 * Revision 1.2  2008/03/10 10:22:58  kkiran
 *  - Cavium Copyright added.
 *
 * Revision 1.1  2007/02/20 23:43:29  panicker
 * * Utilities checked in
 *
 * Revision 1.2  2005/08/31 17:21:40  bimran
 * Fixed a lot of warnings.
 *
 * Revision 1.1  2004/04/15 22:40:51  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

