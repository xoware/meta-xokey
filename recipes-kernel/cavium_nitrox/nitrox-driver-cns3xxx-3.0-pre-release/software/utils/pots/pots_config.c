/*
 * pots_config.c:
 *      - Used for configuring pots program
 *
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "cavium_sysdep.h"
#include "cavium_common.h"

#include "pots.h"
#include "pots_proto.h"

static int get_intval(char *str, int *intvalp);

int pots_config(pots_sts *pots_stp)
{
   
   char *fname = "pots_config()";
   int i;
   int rc;
   char rbuf[1024];
   int tk_index;
   char *sptr;
   int test_id;
   char test_name[36];
   int start_key_sz;
   int end_key_sz;
   int key_incr;
   int start_msg_sz;
   int end_msg_sz;
   int msg_incr;


   /* open the configuration file. */
   if ((pots_stp->pt_cfp = fopen(PT_CONF_FNAME, "r")) == NULL ) {
      pots_log(PT_LOG_ERROR,
            "%s: fopen(%s) failed %s <%d>\n",
            PT_CONF_FNAME, strerror(errno), errno);
      return(-1);
   }


   /* 
    * Read lines from pots configuration file.
    * This has lines having the following format:
    * TEST_DESC = test_id, test_name, start_key_sz, end_key_sz,
    *             start_input_buf_sz, end_input_buf_sz
    */
   while ( fgets(rbuf, 1024, pots_stp->pt_cfp) != NULL ) {

      /* 
       * does the line that we read have a "TEST_DESC" 
       * starting token.
       */
      if ( (sptr = strtok(rbuf, " ,\r\n")) == NULL) {
         // skip this line
         continue;
      }

      /* got some token */
      if ( strncmp("TEST_DESC", sptr, 9) != 0 ) {
         /* first token is not TEST_DESC, go to next line */
         continue;
      }

      /* first token is TEST_DESC, parse the line */
      tk_index = 0;   // next token id to look for 
      while ( (sptr = strtok(NULL, " ,\r\n")) != NULL) {
         
         /* get 
          *       test_id
          *       test_name
          *       start_key_sz 
          *       end_key_sz
           *       start_input_buf_sz
          *       end_input_buf_sz
          */
         switch (tk_index) {

         case 0:
            /* get the test_id */
            if ( (rc = get_intval(sptr, &test_id)) == -1 ) {
               // error in getting test_id
               pots_log(PT_LOG_ERROR, 
                     "%s: invalid test_id = %d\n",
                     fname, test_id);
               return(-1);
            }

            tk_index++;
            break;

         case 1:
            /* get the test name */
            strcpy(test_name, sptr);
            tk_index++;
            break;

         case 2:
            /* get the start_key_sz */
            if ( (rc = get_intval(sptr, &start_key_sz)) == -1 ) {
               // error in getting test_id
               pots_log(PT_LOG_ERROR, 
                     "%s: invalid start_key_sz = %d, %s\n",
                     fname, start_key_sz, test_name);
               return(-1);
            }

            // save this in pots_stp->pt_test_stp->...
            tk_index++;
            break;

         case 3:
            /* get the end_key_sz */
            if ( (rc = get_intval(sptr, &end_key_sz)) == -1 ) {
               // error in getting test_id
               pots_log(PT_LOG_ERROR, 
                     "%s: invalid end_key_sz = %d, %s\n",
                     fname, end_key_sz, test_name);
               return(-1);
            }

            // save this in pots_stp->pt_test_stp->...
            tk_index++;
            break;

         case 4:
            /* get the key_incr */
            if ( (rc = get_intval(sptr, &key_incr)) == -1 ) {
               // error in getting test_id
               pots_log(PT_LOG_ERROR, 
                     "%s: invalid key_incr = %d, %s\n",
                     fname, key_incr, test_name);
               return(-1);
            }

            // save this in pots_stp->pt_test_stp->...
            tk_index++;
            break;

         case 5:
            /* get the start_msg_sz */
            if ( (rc = get_intval(sptr, &start_msg_sz)) == -1 ) {
               // error in getting test_id
               pots_log(PT_LOG_ERROR, 
                     "%s: invalid start_msg_sz = %d, %s\n",
                     fname, start_msg_sz, test_name);
               return(-1);
            }

            // save this in pots_stp->pt_test_stp->...
            tk_index++;
            break;

         case 6:
            /* get the end_msg_sz */
            if ( (rc = get_intval(sptr, &end_msg_sz)) == -1 ) {
               // error in getting test_id
               pots_log(PT_LOG_ERROR, 
                     "%s: invalid end_msg_sz = %d, %s\n",
                     fname, end_msg_sz, test_name);
               return(-1);
            }

            // save this in pots_stp->pt_test_stp->...
            tk_index++;
            break;

         case 7:
            /* get the msg_incr */
            if ( (rc = get_intval(sptr, &msg_incr)) == -1 ) {
               // error in getting test_id
               pots_log(PT_LOG_ERROR, 
                     "%s: invalid msg_incr = %d, %s\n",
                     fname, msg_incr, test_name);
               return(-1);
            }

            // save this in pots_stp->pt_test_stp->...
            tk_index++;
            break;

         default:
            pots_log(PT_LOG_ERROR, 
               "%s invalid token # %d, %s\n", 
                  fname, tk_index, test_name);

         } // end switch

      } // end strtok()

      if ( tk_index != 8 ) {
         pots_log(PT_LOG_ERROR, 
            "%s invalid # of tokens %d, %s\n", 
            fname, tk_index, test_name);
         continue;   // skip this test
      }
      else {

         // check that these values are ok for the test 
         // ADD CODE!
         rc = check_test_values(pots_stp, test_id, test_name, 
                           start_key_sz, end_key_sz, key_incr,
                           start_msg_sz, end_msg_sz, msg_incr);
         if ( rc == -1 ) {
            pots_log(PT_LOG_DEBUG, 
                  "%s: invalid test values for %s\n", 
                  fname, test_name);
            continue;   // skip these test values 
         }
         else {

            // test values are ok, save these
            rc = save_test_values(pots_stp, test_id, test_name, 
                              start_key_sz, end_key_sz, key_incr,
                              start_msg_sz, end_msg_sz, msg_incr);

            pots_log(PT_LOG_INFO, "%s: TEST_DESC:\n", fname);
            pots_log0(PT_LOG_INFO, "\ttest_id = %d\n", test_id);
            pots_log0(PT_LOG_INFO, "\ttest_name = %s\n", test_name);
            pots_log0(PT_LOG_INFO, "\tstart_key_sz = %d\n", start_key_sz);
            pots_log0(PT_LOG_INFO, "\tend_key_sz = %d\n", end_key_sz);
            pots_log0(PT_LOG_INFO, "\tkey_incr = %d\n", key_incr);
            pots_log0(PT_LOG_INFO, "\tstart_msg_sz = %d\n", start_msg_sz);
            pots_log0(PT_LOG_INFO, "\tend_msg_sz = %d\n", end_msg_sz);
            pots_log0(PT_LOG_INFO, "\tmsg_incr = %d\n", msg_incr);
         
         }
      }

   } // end while fgets

   return(0);


} // end pots_config()
            

static int get_intval(char *str, int *intvalp)
{
   
   *intvalp = atoi(str);

   return(0);

}

int check_test_values(   pots_sts *pots_stp,
               int test_id, 
               char *test_name, 
               int start_key_sz, 
               int end_key_sz, 
               int key_incr,
               int start_msg_sz, 
               int end_msg_sz, 
               int msg_incr)
{

   
   struct pots_crypto_test_cnf *cptr;

   if ( test_id < 0 || test_id > PT_TESTID_MOD_EX ) {
      pots_log(PT_LOG_DEBUG, "check_test_values(): invalid test_id %d\n",
            test_id);
      return(-1);
   }
   
   cptr = &pots_stp->pt_test_cnf[test_id];

   if ( strcmp(cptr->cc_test_name, test_name) != 0 ) {
      pots_log(PT_LOG_DEBUG, "check_test_values(): invalid test_name %s\n",
            test_name);
      return(-1);
   }

   if ( start_key_sz < 0 || start_key_sz > MAX_CRYPTO_KEY_SZ) {
      pots_log(PT_LOG_DEBUG, "check_test_values(): invalid start_key_sz %d\n",
            start_key_sz);
      return(-1);
   }

   if ( end_key_sz < 0 || end_key_sz > MAX_CRYPTO_KEY_SZ) {
      pots_log(PT_LOG_DEBUG, "check_test_values(): invalid end_key_sz %d\n",
            end_key_sz);
      return(-1);
   }

   if ( key_incr <= 0 || key_incr > MAX_CRYPTO_KEY_SZ) {
      pots_log(PT_LOG_DEBUG, "check_test_values(): invalid key_incr %d\n",
            key_incr);
      return(-1);
   }

      
   if ( start_msg_sz < 0 || start_msg_sz > MAX_CRYPTO_MSG_SZ) {
      pots_log(PT_LOG_DEBUG, "check_test_values(): invalid start_msg_sz %d\n",
            start_msg_sz);
      return(-1);
   }

   if ( end_msg_sz < 0 || end_msg_sz > MAX_CRYPTO_MSG_SZ) {
      pots_log(PT_LOG_DEBUG, "check_test_values(): invalid end_msg_sz %d\n",
            end_msg_sz);
      return(-1);
   }

   if ( msg_incr <= 0 || msg_incr > MAX_CRYPTO_MSG_SZ) {
      pots_log(PT_LOG_DEBUG, "check_test_values(): invalid msg_incr %d\n",
            msg_incr);
      return(-1);
   }
   
   return(0);

} // end check_test_values()


int save_test_values(   pots_sts *pots_stp,
               int test_id, 
               char *test_name, 
               int start_key_sz, 
               int end_key_sz, 
               int key_incr,
               int start_msg_sz, 
               int end_msg_sz, 
               int msg_incr)
{

   struct pots_crypto_test_cnf *cptr;

   cptr = &pots_stp->pt_test_cnf[test_id];

   cptr->cc_test_id = test_id;
   strcpy(cptr->cc_test_name, test_name);
   cptr->cc_start_key_sz = start_key_sz;
   cptr->cc_end_key_sz = end_key_sz;
   cptr->cc_key_incr = key_incr;
   cptr->cc_start_msg_sz = start_msg_sz;
   cptr->cc_end_msg_sz = end_msg_sz;
   cptr->cc_msg_incr = msg_incr;

   return(0);

}


/*
 * $Id: pots_config.c,v 1.3 2008/10/24 08:43:51 ysandeep Exp $
 * $Log: pots_config.c,v $
 * Revision 1.3  2008/10/24 08:43:51  ysandeep
 * NPLUS support added
 *
 * Revision 1.2  2008/03/10 10:22:58  kkiran
 *  - Cavium Copyright added.
 *
 * Revision 1.1  2007/02/20 23:43:29  panicker
 * * Utilities checked in
 *
 * Revision 1.3  2006/08/22 06:06:46  kchunduri
 * included "string.h" for declaration of "strtok()"
 *
 * Revision 1.2  2005/08/31 17:21:40  bimran
 * Fixed a lot of warnings.
 *
 * Revision 1.1  2004/04/15 22:40:51  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

