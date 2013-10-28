/* cavium_common.c */
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

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#undef	NO_ERROR

int	open (const char *, int);
int	close (int);
int	ioctl (int, int, ...);
#endif
#include<string.h>
#include <cavium_sysdep.h>
#include <cavium_common.h>
#include <cavium_ioctl.h>
#include <cavium_endian.h>
#ifndef SSL
#define OP_WRITE_IPSEC_SA         0x14
#define OP_IPSEC_PACKET_INBOUND       0x10
#define OP_IPSEC_PACKET_OUTBOUND      0x11
#define OP_WRITE_INBOUND_IPSEC_SA      0x2014
#define OP_WRITE_OUTBOUND_IPSEC_SA      0x4014
#define OP_ERASE_CONTEXT         0x114
#define IPv4    0
#endif

#define AESXCBC_BLOCK_SIZE 16

#ifndef UINT64_C 
#define UINT64_C(x)   ((unsigned long long) (x ## ull))
#endif

int CSP1_driver_handle=-1;
Csp1DmaMode global_dma_mode=CAVIUM_DIRECT; /* default mode */

#ifdef CAVIUM_MULTICARD_API
int gpkpdev_cnt=0;
int gpkpdev_hdlr[MAX_DEV_CNT]={-1,-1,-1,-1};
int default_device;
#endif


static int
#ifdef CAVIUM_MULTICARD_API
CSP1_open_device_file(int dev_id)
#else
CSP1_open_device_file()
#endif
{
	char   name[32];

	strcpy(name, "/dev/pkp_dev");

#ifdef CAVIUM_MULTICARD_API
    if(dev_id)
       sprintf(name,"%s%d",name,dev_id);
       
#endif
	return open(name, O_RDWR);
}




/*+****************************************************************************
 *
 * Csp1Initialize
 *
 * Prepares the aplication.
 *
 * Input 
 *      dma_mode = CAVIUM_DIRECT or CAVIUM_SCATTER_GATHER
 * 
 * Return Value
 *   completion code = 0 (for success) 
 *                   > 0 (for failure) 
 *
 *-***************************************************************************/

#ifdef CAVIUM_MULTICARD_API
Uint32
Csp1Initialize(Csp1DmaMode dma_mode, Uint32 dev_id)
#else
Uint32
Csp1Initialize(Csp1DmaMode dma_mode)
#endif
{
   Uint32 cond_code = 0;
   int dev_handle = -1;

#ifdef CAVIUM_MULTICARD_API
   dev_handle = gpkpdev_hdlr[dev_id]; 
#else
   dev_handle = CSP1_driver_handle;
#endif

   if(dev_handle < 0)
   {
#ifdef CAVIUM_MULTICARD_API
      dev_handle = CSP1_open_device_file(dev_id);
      gpkpdev_hdlr[dev_id]=dev_handle;
#else
      dev_handle = CSP1_open_device_file();
      CSP1_driver_handle = dev_handle;
#endif

      if (dev_handle < 0) 
         cond_code = errno;
      else {
         global_dma_mode = dma_mode;
         cond_code = 0;
      }
   }

   return cond_code;
}


/*+****************************************************************************
 *
 * Csp1Shutdown
 *
 * Cleanup the driver.
 *
 * Return Value
 *   0  = success 
 * >0 = failure or pending
 *
 *-***************************************************************************/
Uint32 
#ifdef CAVIUM_MULTICARD_API
Csp1Shutdown(Uint32 dev_id)
#else
Csp1Shutdown(void)
#endif
{
   Uint32 cond_code = 0;

#ifdef CAVIUM_MULTICARD_API
   if(gpkpdev_hdlr[dev_id] != -1)
      close(gpkpdev_hdlr[dev_id]);

   gpkpdev_hdlr[dev_id] = -1;
#else
   if(CSP1_driver_handle != -1)
      close(CSP1_driver_handle);

   CSP1_driver_handle = -1;
#endif

   global_dma_mode=CAVIUM_DIRECT; /*default mode */

   return cond_code;
}

/*+****************************************************************************
 *
 * Csp1CheckForCompletion
 *
 * Checks the status of the request.
 *
 * Input 
 *   request_id.
 *
 * Output
 *   none.
 *
 * Return Value
 * 0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32
#ifdef CAVIUM_MULTICARD_API
Csp1CheckForCompletion(Uint32 request_id,Uint32 dev_id)
#else
Csp1CheckForCompletion(Uint32 request_id)
#endif
{
   Uint32 cond_code;
   Uint32 ret_val;
   Csp1RequestStatusBuffer reqStatus;
   memset(&reqStatus,0,sizeof(Csp1RequestStatusBuffer));

   reqStatus.request_id = request_id;
   reqStatus.status = 0;
#ifdef CAVIUM_MULTICARD_API
   cond_code = ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_POLL_CODE, &reqStatus);
#else
   cond_code = ioctl(CSP1_driver_handle, IOCTL_N1_POLL_CODE, &reqStatus);
#endif
   if(cond_code)
      ret_val = cond_code; /*return err val*/
   else
      ret_val = reqStatus.status;/*return status of request:'0' or 'EAGAIN'*/ 

   return ret_val;
}


/*+****************************************************************************
 *
 * Csp1FlushAllRequests
 *
 * Removes all pending requests for the calling process. This call can make the 
 * current process go to sleep. The driver will wait for all pending requests 
 * to complete or timeout.
 *
 * Input 
 *   none.
 *
 * Output
 *   none.
 *
 * Return Value
 * 0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
#ifdef CAVIUM_MULTICARD_API
Uint32 
Csp1FlushAllRequests(Uint32 dev_id)
#else
Uint32 
Csp1FlushAllRequests(void)
#endif
{
   Uint32 cond_code;
   
#ifdef CAVIUM_MULTICARD_API
   cond_code = ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_FLUSH_ALL_CODE);
#else
   cond_code = ioctl(CSP1_driver_handle, IOCTL_N1_FLUSH_ALL_CODE);
#endif

   return cond_code;
}



/*+****************************************************************************
 *
 * Csp1FlushRequest
 *
 * Removes the request for the calling process. This call can make the 
 * current process go to sleep. The driver will wait for the request 
 * to complete or timeout.
 *
 * Input 
 *   request_id.
 *
 * Output
 *    none.
 *
 * Return Value
 * 0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32 
#ifdef CAVIUM_MULTICARD_API
Csp1FlushRequest(Uint32 request_id,Uint32 dev_id)
#else
Csp1FlushRequest(Uint32 request_id)
#endif
{
   Uint32 cond_code;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
      ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_FLUSH_CODE, (Uint32)request_id);
#else
      ioctl(CSP1_driver_handle, IOCTL_N1_FLUSH_CODE, (Uint32)request_id);
#endif
   return cond_code;
}


/*+****************************************************************************
 *
 * Csp1AllocContext
 *
 * Allocates a context segment (in the local DDR DRAM or the host memory 
 * depending on the system) and returns its handle that will be passed to the 
 * processor in the final 8 bytes of the request as Cptr.
 *
 * Input 
 *   cntx_type = CONTEXT_SSL or CONTEXT_IPSEC
 *
 * Output
 *   context_handle = pointer to 8-byte address of the context for use by 
 *      the Cavium processor
 *
 * Return Value
 * 0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32 
#ifdef CAVIUM_MULTICARD_API
Csp1AllocContext(ContextType cntx_type, 
       Uint64 *context_handle,Uint32 dev_id)
#else
Csp1AllocContext(ContextType cntx_type, 
       Uint64 *context_handle)
#endif
{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;
   n1_context_buf cbuf;

   memset(&buffer,0,sizeof(Csp1OperationBuffer));
   cbuf.type = cntx_type;

   buffer.opcode = 0;
   /* 
    * Set the context size to be allocated. 
    */
   buffer.size = cntx_type;
   buffer.param = 0;
   buffer.dlen = 0;
   buffer.rlen = 0;
   buffer.group = CAVIUM_GP_GRP;

   buffer.incnt = 0;      
   buffer.outcnt = 0;      
#ifdef CAVIUM_MULTICARD_API
   cond_code = ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_ALLOC_CONTEXT, (ptrlong)&cbuf);
#else
   cond_code = ioctl(CSP1_driver_handle, IOCTL_N1_ALLOC_CONTEXT, (ptrlong)&cbuf);
#endif

    if (cond_code) {
        ret_val=cond_code;
    } else { /* success*/   
        ret_val = 0;
        *context_handle = cbuf.ctx_ptr;
    }
   return ret_val;
}


/*+****************************************************************************
 *
 * Csp1FreeContext
 *
 * Free a context segment for use by another SSL connection/IPsec tunnel.
 *
 * Input
 *   cntx_type = CONTEXT_SSL or CONTEXT_IPSEC
 *   context_handle = 8-byte address of the context for use by 
 *      the Cavium processor
 *
 * Return Value
 * 0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32 
#ifdef CAVIUM_MULTICARD_API
Csp1FreeContext(ContextType cntx_type, 
      Uint64 context_handle,Uint32 dev_id)
#else
Csp1FreeContext(ContextType cntx_type, 
      Uint64 context_handle)
#endif
{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;
   n1_context_buf cbuf;


   memset(&buffer,0,sizeof(Csp1OperationBuffer));
   if ((context_handle & UINT64_C(0x8000000000000000)) != 0)
   {
      if ((context_handle & 0xf) != 0)
         return ERR_ILLEGAL_CONTEXT_HANDLE;
   }
   else
   {
      if ((context_handle & 0x7) != 0)
         return ERR_ILLEGAL_CONTEXT_HANDLE;
   }


   buffer.opcode = 0;
   /* 
    * Set the context type to be deallocated. 
    */
   buffer.size = cntx_type;
   buffer.param = 0;
   buffer.dlen = 0;
   buffer.rlen = 0;

   buffer.incnt = 0;      
   buffer.outcnt = 0;
   buffer.ctx_ptr = context_handle;      

   cbuf.type = cntx_type;
   cbuf.ctx_ptr = context_handle;
#ifdef CAVIUM_MULTICARD_API
   cond_code = ioctl(gpkpdev_hdlr[dev_id],IOCTL_N1_FREE_CONTEXT,(ptrlong)&cbuf);
#else
   cond_code = ioctl(CSP1_driver_handle,IOCTL_N1_FREE_CONTEXT,(ptrlong)&cbuf);
#endif

   if (cond_code)
      ret_val=cond_code;
   else /* success*/   
      ret_val = 0;

   return ret_val;
}


/*+****************************************************************************
 *
 * Csp1AllocKeyMem
 *
 * Acquires the handle to a key memory segment and returns a handle.
 *
 * Input
 *  key_material_loc = INTERNAL_SRAM, HOST_MEM, or LOCAL_DDR
 *
 * Output
 *   key_handle = pointer to 8-byte handle to key memory segment
 *
 * Return Value
 * 0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/

Uint32 
#ifdef CAVIUM_MULTICARD_API
Csp1AllocKeyMem(KeyMaterialLocation key_material_loc, Uint64 *key_handle,Uint32 dev_id)
#else
Csp1AllocKeyMem(KeyMaterialLocation key_material_loc, Uint64 *key_handle)
#endif
{
   Uint32 ret_val;
   n1_write_key_buf key_buf;
   memset(&key_buf,0,sizeof(n1_write_key_buf));

#ifdef CAVIUM_MULTICARD_API
   ret_val=ioctl(gpkpdev_hdlr[dev_id],IOCTL_N1_ALLOC_KEYMEM,(ptrlong)&key_buf);
#else
   ret_val=ioctl(CSP1_driver_handle,IOCTL_N1_ALLOC_KEYMEM, (ptrlong)&key_buf);
#endif
   *key_handle = key_buf.key_handle;
   return ret_val;
}

/*+****************************************************************************
 *
 * Csp1FreeKeyMem
 *
 * Free a key memory segment.
 *
 * Input
 *   key_handle = 8-byte handle to key memory segment
 *
 * Return Value
 * 0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/

Uint32 
#ifdef CAVIUM_MULTICARD_API
Csp1FreeKeyMem(Uint64 key_handle,Uint32 dev_id)
#else
Csp1FreeKeyMem(Uint64 key_handle)
#endif
{
   Uint32 ret_val;
   n1_write_key_buf key_buf;
   memset(&key_buf,0,sizeof(n1_write_key_buf));
#ifdef MC2
   /* turn off crt bit 49 */
   key_handle &= ((((Uint64)0xfffdffff) << 32) | (Uint64)0xffffffff);
#else
   /* turn off crt bit 48 */
   key_handle &= ((((Uint64)0xfffeffff) << 32) | (Uint64)0xffffffff);
#endif

   key_buf.key_handle = key_handle;
#ifdef CAVIUM_MULTICARD_API
   ret_val=ioctl(gpkpdev_hdlr[dev_id],IOCTL_N1_FREE_KEYMEM, (ptrlong)&key_buf);
#else
   ret_val = ioctl(CSP1_driver_handle,IOCTL_N1_FREE_KEYMEM, (ptrlong)&key_buf);
#endif
   return ret_val;
}


/*+****************************************************************************
 *
 * Csp1StoreKey
 *
 * Store a key to memory segment indicated by key handle.
 *
 * Input
 *   key_handle = 8-byte handle to key memory segment
 *   length = size of key in bytes
 *   key = pointer to key
 *   mod_ex_type = NORMAL_MOD_EX or CRT_MOD_EX
 *
 * Return Value
 * 0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/

Uint32 
#ifdef CAVIUM_MULTICARD_API
Csp1StoreKey(Uint64 *key_handle, 
    Uint16 length, 
    Uint8 *key, 
    RsaModExType mod_ex_type,Uint32 dev_id)
#else
Csp1StoreKey(Uint64 *key_handle, 
    Uint16 length, 
    Uint8 *key, 
    RsaModExType mod_ex_type)
#endif
{
    n1_write_key_buf key_buf;
    Uint32 ret_val;

   memset(&key_buf,0,sizeof(n1_write_key_buf));
#ifdef MC2
    /* turn off crt bit 49 */
    *key_handle &= ((((Uint64)0xfffdffff) << 32) | (Uint64)0xffffffff);
#else
    /* turn off crt bit 48 */
    *key_handle &= ((((Uint64)0xfffeffff) << 32) | (Uint64)0xffffffff);
#endif
    key_buf.key_handle = *key_handle;
    key_buf.length = length;
    key_buf.key = CAST_TO_X_PTR(key);
#ifdef CAVIUM_MULTICARD_API
    ret_val = ioctl(gpkpdev_hdlr[dev_id],IOCTL_N1_WRITE_KEYMEM,(ptrlong)&key_buf);
#else
    ret_val = ioctl(CSP1_driver_handle, IOCTL_N1_WRITE_KEYMEM, (ptrlong)&key_buf);
#endif

    if(!ret_val) {
   if (mod_ex_type == CRT_MOD_EX)
#ifdef MC2
      *key_handle |= (((Uint64)0x20000) << 32);
#else
      *key_handle |= (((Uint64)0x10000) << 32);
#endif
   }
   return ret_val;
}


/*****************************************************************************
 *
 * Csp1ReadEpci
 *
 * Routine to read the onchip SRAM memory
 *
 * input
 *    request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *    key_handle = 64-bit key handle pointer.
 *    length = size of data to read in bytes (8<length<=880, length%8=0).
 *
 * output
 *      data = Result data (size variable based on size)
 *      request_id = Unique ID for this request.
 *
 * Return Value
 * 0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 ****************************************************************************/
Uint32 
#ifdef CAVIUM_MULTICARD_API
Csp1ReadEpci(n1_request_type request_type,
    Uint64 *key_handle, 
    Uint16 length,
    Uint8 *data,
    Uint32 *request_id,Uint32 dev_id)
#else
Csp1ReadEpci(n1_request_type request_type,
    Uint64 *key_handle, 
    Uint16 length,
    Uint8 *data,
    Uint32 *request_id)
#endif
{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;

   memset(&buffer,0,sizeof(Csp1OperationBuffer));
   if ((length < 8) || (length > 880) || ((length & 0x7) != 0))
      return ERR_ILLEGAL_INPUT_LENGTH;

   buffer.opcode = (0x8<<8) | (global_dma_mode<<7) | MAJOR_OP_RANDOM_WRITE_CONTEXT;
#ifdef MC2
   buffer.size = length;
   buffer.param = 0;
   buffer.dlen = 8;
   buffer.rlen = length;
#else
   buffer.size = length>>3;
   buffer.param = 0x10;
   buffer.dlen = (8)>>3;
   buffer.rlen = (length + 8)>>3;
#endif
   buffer.ctx_ptr = 0;

   buffer.incnt = 1;      
   buffer.outcnt = 1;      

   buffer.group = CAVIUM_GP_GRP;

   buffer.inptr[0] = CAST_TO_X_PTR((Uint8 *)key_handle);
   buffer.insize[0] = 8;
   buffer.inoffset[0] = 8;
   buffer.inunit[0] = UNIT_64_BIT;

   buffer.outptr[0] = CAST_TO_X_PTR(data);
   buffer.outsize[0] = length;
   buffer.outoffset[0] = length;
   buffer.outunit[0] = UNIT_8_BIT;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;
   cond_code = 
#ifdef CAVIUM_MULTICARD_API
      ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
      ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif

   *request_id = buffer.request_id;

   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */
    
   return ret_val;
}


/*****************************************************************************
 *
 * Csp1WriteEpci
 * write data to onchip SRAM.
 *
 * input
 *    request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *    key_handle = 64-bit key handle pointer.
 *    length = size of data to write in bytes (8<length<=880, length%8=0).
 *      data =  input data 
 *
 * output
 *      request_id = Unique ID for this request.
 *
 * Return Value
 * 0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 ****************************************************************************/
Uint32 
#ifdef CAVIUM_MULTICARD_API
Csp1WriteEpci(n1_request_type request_type,
          Uint64 *key_handle, 
          Uint16 length,
          Uint8 *data,
          Uint32 *request_id,Uint32 dev_id)
#else

Csp1WriteEpci(n1_request_type request_type,
          Uint64 *key_handle, 
          Uint16 length,
          Uint8 *data,
          Uint32 *request_id)
#endif
{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;

   memset(&buffer,0,sizeof(Csp1OperationBuffer));
   if ((length < 8) || (length > 880) || ((length & 0x7) != 0))
      return ERR_ILLEGAL_INPUT_LENGTH;

   buffer.opcode = (0x0<<8) | (global_dma_mode<<7) | MAJOR_OP_RANDOM_WRITE_CONTEXT;
#ifdef MC2
   buffer.size = 0;
   buffer.param = 0;
   buffer.dlen = 8 + length;
   buffer.rlen = 0;
#else
   buffer.size = length>>3;
   buffer.param = 0x8;
   buffer.dlen = (8 + length)>>3;
   buffer.rlen = (8)>>3;
#endif
   buffer.ctx_ptr = 0;
   buffer.incnt = 2;      
   buffer.outcnt = 0;      

   buffer.group = CAVIUM_GP_GRP;

   buffer.inptr[0] = CAST_TO_X_PTR((Uint8 *)key_handle);
   buffer.insize[0] = 8;
   buffer.inoffset[0] = 8;
   buffer.inunit[0] = UNIT_64_BIT;
   buffer.inptr[1] = CAST_TO_X_PTR(data);
   buffer.insize[1] = length;
   buffer.inoffset[1] = length;
   buffer.inunit[1] = UNIT_8_BIT;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = CAVIUM_SCATTER_GATHER;
   buffer.status = 0;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif

   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */


   return ret_val;
}


/*****************************************************************************
 *
 * Csp1ReadContext
 *
 * Routine to read data from context.
 *
 * input
 *    request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *    context_handle = 64-bit context handle pointer.
 *    length = size of data to read in bytes (8<length<=1024, length%8=0).
 *
 * output
 *      data = Result data (size variable based on size)
 *      request_id = Unique ID for this request.
 *
 * Return Value
 * 0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 ****************************************************************************/
Uint32 
#ifdef CAVIUM_MULTICARD_API
Csp1ReadContext(n1_request_type request_type,
      Uint64 context_handle, 
      Uint16 length,
      Uint8 *data,
      Uint32 *request_id,Uint32 dev_id)
#else
Csp1ReadContext(n1_request_type request_type,
      Uint64 context_handle, 
      Uint16 length,
      Uint8 *data,
      Uint32 *request_id)
#endif
{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;

   memset(&buffer,0,sizeof(Csp1OperationBuffer));
   if ((length < 8) || (length > 1024) || ((length & 0x7) != 0)) 
      return ERR_ILLEGAL_INPUT_LENGTH;

   if ((context_handle & UINT64_C(0x8000000000000000)) != 0) {
      if ((context_handle & 0xf) != 0)
         return ERR_ILLEGAL_CONTEXT_HANDLE;

   } else {
      if ((context_handle & 0x7) != 0)
         return ERR_ILLEGAL_CONTEXT_HANDLE;
   }

   buffer.opcode = (0x4<<8) | (global_dma_mode<<7) | MAJOR_OP_RANDOM_WRITE_CONTEXT;
#ifdef MC2
   buffer.size = length;
#else
   buffer.size = length>>3;
#endif
   buffer.param = 0;
   buffer.dlen = 0;
#ifdef MC2
   buffer.rlen = length;
#else
   buffer.rlen = (length + 8)>>3;
#endif
   buffer.ctx_ptr = context_handle;

   buffer.incnt = 0;      
   buffer.outcnt = 1;      

   buffer.group = CAVIUM_GP_GRP;

   buffer.outptr[0] = CAST_TO_X_PTR(data);
   buffer.outsize[0] = length;
   buffer.outoffset[0] = length;
   buffer.outunit[0] = UNIT_8_BIT;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
      ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE,(ptrlong) &buffer);
#else
      ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE,(ptrlong) &buffer);
#endif

   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */


   return ret_val;
}

 
/*+****************************************************************************
 *
 * Csp1WriteContext
 *
 * Write data to context memory.
 *
 * Input
 *    request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *      context_handle = 64-bit context handle pointer (context_handle%8=0)
 *      length = size of the data in bytes (8<=length<=1024,length%8=0)
 *      data = pointer to length bytes of data to be stored
 *
 * output
 *    request_id = Unique ID for this request.
 *
 * Return Value
 *    0  = success 
 *    >0 = failure or pending
 *    see error_codes.txt
 *
 *-***************************************************************************/
Uint32 
#ifdef CAVIUM_MULTICARD_API
Csp1WriteContext(n1_request_type request_type,
       Uint64 context_handle, 
       Uint16 length,
       Uint8 *data,
       Uint32 *request_id,Uint32 dev_id)
#else
Csp1WriteContext(n1_request_type request_type,
       Uint64 context_handle, 
       Uint16 length,
       Uint8 *data,
       Uint32 *request_id)
#endif
{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;

   memset(&buffer,0,sizeof(Csp1OperationBuffer));
   if ((length < 8) || (length > 1024) || ((length & 0x7) != 0))
      return ERR_ILLEGAL_INPUT_LENGTH;
   
   if ((context_handle & UINT64_C(0x8000000000000000)) != 0) {
      if ((context_handle & 0xf) != 0)
         return ERR_ILLEGAL_CONTEXT_HANDLE;
   } else {
      if ((context_handle & 0x7) != 0)
         return ERR_ILLEGAL_CONTEXT_HANDLE;
   }
   

   buffer.opcode = (0x2<<8) | (global_dma_mode<<7) | MAJOR_OP_RANDOM_WRITE_CONTEXT;
#ifdef MC2
   buffer.size = 0;
#else
   buffer.size = (length>>3) - 1;
#endif
   buffer.param = 0;
#ifdef MC2
   buffer.dlen = length;
   buffer.rlen = 0;
#else
   buffer.dlen = (length)>>3;
   buffer.rlen = (8)>>3;
#endif
   buffer.ctx_ptr = context_handle;

   buffer.incnt = 1;      
   buffer.outcnt = 0;      

   buffer.group = CAVIUM_GP_GRP;

   buffer.inptr[0] = CAST_TO_X_PTR(data);
   buffer.insize[0] = length;
   buffer.inoffset[0] = length;
   buffer.inunit[0] = UNIT_8_BIT;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
      ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE,(ptrlong) &buffer);
#else
      ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE,(ptrlong) &buffer);
#endif

   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */


   return ret_val;
}

/*+****************************************************************************
 *
 * Csp1WriteIpsecSa
 *
 * Write Ipsec SA data to context memory.
 *
 * Input
 *    request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *    proto = ESP or AH
 *    inner_version = Protocol version of inner IP header.
 *    outer_version = Protocol version of outer IP header.
 *    mode = SA mode (TUNNEL or TRANSPORT)
 *    dir = Direction (INBOUND or OUTBOUND)
 *    cypher = Encryption algorithm 
 *        (DESCBC, DES3CBC, AES128CBC, AES192CBC, AES256CBC)
 *    auth = Authentication algorithm
 *      (MD5HMAC96 or SHA1HMAC96)
 *    template = Template for Outer IP header
 *    spi = 32 bit SPI value
 *    copy_df = 0 (copy the df bit for packet fragments) or 1 (do not copy)
 *    udp_encap = 0 (no UDP encapsulation) or 1 (UDP encapsulation)
 *    context_handle = 64-bit context handle pointer (context_handle%8=0)
 *    next_context_handle = context handle pointer for next SA.
 *
 * output
 *    request_id = Unique ID for this request.
 *
 * Return Value
 *    0  = success 
 *    >0 = failure or pending
 *    see error_codes.txt
 *
 *-***************************************************************************/
#ifdef IPSEC_TEST
#ifndef MC2
Uint32
Csp1WriteIpsecSa(IpsecProto proto,
      Version version,
      IpsecMode mode,
      Direction dir,
      EncType cypher,
      Uint8 *e_key,
      AuthType auth,
      Uint8 *a_key,
#ifndef IPV6_EXT_HEADER_SUPPORT
      Uint8 template[40],
#else
      Uint8 template[384],
#endif
      Uint32 spi,
      Uint8 copy_df,
      FragType ft,
      Uint16 inter_frag_padding,
      Uint8 udp_encap,
      Uint64 context_handle,
      Uint64 next_context_handle,
      int res_order,
      int req_queue,
      Uint32 *request_id)
#else
Uint32
Csp1WriteIpsecSa(n1_request_type request_type,
      IpsecProto proto,
      Version inner_version,
      Version outer_version,
      IpsecMode mode,
      Direction dir,
      EncType cypher,
      Uint8 *e_key,
      AuthType auth,
      Uint8 *a_key,
#ifndef IPV6_EXT_HEADER_SUPPORT
      Uint8 template[40],
#else
      Uint8 template[384],
#endif
      Uint32 spi,
      Uint8 copy_df,
      FragType ft,
      Uint16 inter_frag_padding,
      Uint8 udp_encap,
      Uint64 context_handle,
      Uint64 next_context_handle,
      Selector* selectors,  /* selectors, must match inner_version */
      int res_order,
      int req_queue,
      Uint32 *request_id)
#endif
{
   Uint8 *p;
   Uint16 *control;
   Csp1OperationBuffer buffer;
   Uint32 len;
   Uint32 cond_code;
   Uint32 ret_val;
   Uint32 in_buffer[512];
   int queue = req_queue;

   memset(in_buffer,0x00,512);

   p = (Uint8*)&in_buffer;
   control = (Uint16*)p;
   *control = 0;
    /* Populate the control structure as the MC2 microcode requires */
#ifndef MC2
   *control = (((dir&0x1) << IPSEC_DIRECTION_SHIFT) | 
      ((version & 0x1) << IPSEC_VERSION_SHIFT) |
      ((mode & 0x1) << IPSEC_MODE_SHIFT) |
      ((proto & 0x1) << IPSEC_PROT_SHIFT) |
      ((auth & 0x0f) << IPSEC_AUTH_SHIFT) |
      ((cypher & 0x0f) << IPSEC_CIPHER_SHIFT) |
      ((copy_df & 0x01) << IPSEC_DF_SHIFT) |
      ((udp_encap & 0x01) << IPSEC_UDP_SHIFT)); 
#else
   *control = (((dir& 0x1) << IPSEC_DIRECTION_SHIFT) |
      ((VALID_SA & 0x1) << IPSEC_VALID_SHIFT) | 
      ((outer_version & 0x1) << IPSEC_VERSION_SHIFT) |
      ((inner_version & 0x1) << (IPSEC_VERSION_SHIFT+1)) |
      ((mode & 0x1) << IPSEC_MODE_SHIFT) |
      ((proto & 0x1) << IPSEC_PROT_SHIFT) |
       ((udp_encap & 0x3) << IPSEC_ENCAP_SHIFT) |  
      ((cypher & 0x7) << IPSEC_CIPHER_SHIFT) |
      ((auth & 0x3) << IPSEC_AUTH_SHIFT) |
      ((dir==INBOUND) ? (0x0 << IPSEC_SELECTOR_SHIFT) : ((copy_df & 0x1) << IPSEC_DF_SHIFT)));
      if(dir == OUTBOUND)
        *control = *control | ((ft & 1) << IPSEC_FT_SHIFT);
      *control = *control | ((next_context_handle ? 1 : 0) << IPSEC_NEXT_SA_SHIFT);

#endif
   if(dir==INBOUND)
   {
     if(selectors) 
     {
       *control |= (0x1 << IPSEC_SELECTOR_SHIFT); /*Protocol selector is set by default 0 - proto selector enabled*/
       inter_frag_padding = 0x0;
       inter_frag_padding |= ((selectors->protocol & 0xff) << 8);
     }
   }
   *control = htobe16(*control);
//   cavium_dbgprint("write_ipsec_sa : control 0x%x\n", *control);

   p += 2; 
   if(dir == OUTBOUND)
     *(Uint16*)p = htobe16(inter_frag_padding);
   else //inbound
     *(Uint16*)p = (selectors)? (htobe16(inter_frag_padding)): 0x0000;//includes Protocol selector(1 byte) + Reserved(1 byte)
   p += 2;
   memcpy(p,&spi,4);
   p += 4;

   memset(p, 0, 32);
   if(cypher != NO_CYPHER)
      memcpy(p, e_key, 32);
   else
      memset(p, 0, 32);

   p += 32;

   memset(p,0,24);  
   switch (auth) {
      case SHA1HMAC96:
    memcpy(p,a_key,20);
      break;

      case MD5HMAC96:
    memcpy(p,a_key,16);
      break;

      default:
      case NO_AUTH:
    memset(p,0,24);
      break;
   }
   p += 24;

#ifndef MC2
   if (mode == 1 && dir == OUTBOUND)
#ifndef IPV6_EXT_HEADER_SUPPORT
      memcpy(p,template,40);
#else
      memcpy(p,template,384);
#endif
   memset(&buffer, 0, sizeof(buffer));

   buffer.opcode = OP_WRITE_IPSEC_SA; 
   buffer.size = 0;
   buffer.param = 0;
   buffer.dlen = 13;
   buffer.rlen = 1;
   buffer.reserved = 0;
   buffer.ctx_ptr = context_handle;

#else
   len = (Uint8*)p - (Uint8*)in_buffer;
   /* Since bundles is not yet implemented in this API, it returns -1 as error
    * if the next_context_handle field is not passed as 0 */
   if(next_context_handle!=0)
      return -1;

   p += 8;
   len+=8;

   if (dir == OUTBOUND) {
   if (mode==TUNNEL) {
      if (outer_version == IPv4) {
       if (!udp_encap) {
          /* Normal IPSec processing */
      memcpy(p,template,20);
           p+=20;
           len+=20;
          } else {
            /* UDP Encapsulation */
         memcpy(p,template,28);
         p+=28;
    len+=28;
          }
      } else {
    /* IPv6 */
        if(!udp_encap) {
#ifndef IPV6_EXT_HEADER_SUPPORT
          memcpy(p, template, 40);
          p+=40;
          len+=40;
#else
          memcpy(p, template, 384);
          p+= 384;
          len+= 384;
#endif
        }
        else {
#ifndef IPV6_EXT_HEADER_SUPPORT
          memcpy(p, template, 48);
          p+=48;
          len+=48;
#else
          memcpy(p, template, 384 + 8);
          p+= 384 + 8;
          len+= 384 + 8;
#endif
        }
      }
    }
       else { //Transport
        if(udp_encap) {
       if(outer_version == IPV4) {
         memset(p,0,20);
         memcpy(p+20,template,8);
         p+=28;
         len+=28;
       }
       else{
         memset(p,0,40);
         memcpy(p+40,template,8);
         p+=48;
         len+=48;
       }
     }
   }

    }
   else { //inbound
      memcpy(p,template,8); //for UDP encap
      p+=8;
      len+=8;
      if(selectors)
      {
     
        memcpy(p,SELECTOR(selectors),SELECTOR_SIZE(inner_version));
        p += (SELECTOR_SIZE(inner_version));
        len += (SELECTOR_SIZE(inner_version));
      }
   }

#ifndef IPV6_EXT_HEADER_SUPPORT
   memset(p, 0, 256-len);
#else
   memset(p, 0, 512-len);
#endif

   memset(&buffer, 0, sizeof(buffer));

   buffer.opcode = ((dir == INBOUND) ? OP_WRITE_INBOUND_IPSEC_SA : OP_WRITE_OUTBOUND_IPSEC_SA); 
   buffer.size = 0;
   buffer.param = 0;
   buffer.dlen = len;
   buffer.rlen = 0;
   buffer.reserved = 0;
   buffer.ctx_ptr = context_handle;
#endif

#ifdef IPSEC_SCATTER_GATHER
   buffer.dma_mode = CAVIUM_SCATTER_GATHER;
#else
   buffer.dma_mode = CAVIUM_DIRECT;
#endif

   buffer.incnt = 1;
   /* For DIRECT mode, we need out_buffer for completion code.
    * For SCATTER_GATHER, we do not need this, because completion
    * code goes to rptr of command
    */
   if(buffer.dma_mode == CAVIUM_DIRECT)
      buffer.outcnt=1;
   else
      buffer.outcnt=0;

   buffer.inptr[0] = CAST_TO_X_PTR(in_buffer);
#ifndef MC2
   buffer.insize[0] = buffer.dlen*8;
#else
   buffer.insize[0] = len;
#endif
   buffer.inoffset[0] = buffer.insize[0];
   buffer.inunit[0] = UNIT_8_BIT;

if(dir == OUTBOUND) {

   inter_frag_padding = htobe16(inter_frag_padding);
   buffer.inptr[1] = CAST_TO_X_PTR(&inter_frag_padding);
   buffer.insize[1] = 2;
   buffer.inoffset[1] = 2;
   buffer.inunit[1] = UNIT_8_BIT;
   buffer.dlen += buffer.insize[1];
}
else
   buffer.incnt = 1;

   buffer.res_order = res_order;
   buffer.req_queue = queue;
   buffer.callback = 0;
   buffer.cb_arg = 0;
//#ifdef NPLUS
   buffer.group = CAVIUM_IPSEC_GRP;
//#endif
    buffer.req_queue = 0;
    buffer.req_type = 0; // CAVIUM_BLOCKING
    buffer.res_order = CAVIUM_RESPONSE_ORDERED;
    buffer.dma_mode = global_dma_mode;
    buffer.status = 0;

    cond_code = 
       ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);

   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */


    return ret_val;
}
/*+****************************************************************************
 *
 * Csp1ProcessPacket
 *
 * Process outbound packet
 *
 * Input
 *    size = 0 (for MC2) or size of input data in bytes (for MC1).
 *    param = 0 (for MC2) or Offset of IP header from 8-byte alignment (for MC1) *    dlen = length of input (packet)
 *    inv = poniter to input data (packet to be processed)
 *    rlen = length of output buffer (processed packet)
 *    context_handle = 64-bit context handle pointer (context_handle%8=0)
 *    response_order = 
 *    req_queue = 
 *    
 * Output
 *   outv = pointer to output buffer
 *   request_id = Unique ID for this request.
 *
 * Return Value
 *    0  = success 
 *    >0 = failure or pending
 *    see error_codes.txt
 *
 *-***************************************************************************/
Uint32
Csp1ProcessPacket(Uint16 size, 
          Uint16 param,
          Direction dir,
          Uint16 dlen,
          n1_scatter_buffer *inv,
          n1_scatter_buffer *outv, 
          int rlen,
          Uint64 context_handle, 
          int response_order, 
          int req_queue,
          Uint32 *request_id)
{
   Csp1OperationBuffer buffer;
   Uint32 ret_val;
   Uint32 cond_code;
   int i;
//   Uint32 req_id;

   memset(&buffer, 0, sizeof(buffer));

   buffer.opcode = (dir == OUTBOUND) ? OP_IPSEC_PACKET_OUTBOUND: OP_IPSEC_PACKET_INBOUND;
   buffer.size = size;
   buffer.param = param;
   buffer.dlen = dlen;
   buffer.rlen = rlen;
   buffer.reserved = 0;
   buffer.ctx_ptr = context_handle;
   buffer.incnt = inv->bufcnt;
   buffer.outcnt = outv->bufcnt;
   
   for ( i = 0; i < inv->bufcnt; i++) {
      buffer.inptr[i] = CAST_TO_X_PTR(inv->bufptr[i]);
      buffer.insize[i] = inv->bufsize[i];
      buffer.inoffset[i] = buffer.insize[i];
      buffer.inunit[i] = UNIT_8_BIT;
   }
   
   for ( i = 0; i < outv->bufcnt; i++) 
   {
      buffer.outptr[i] = CAST_TO_X_PTR(outv->bufptr[i]);
      buffer.outsize[i] = outv->bufsize[i];
      buffer.outoffset[i] = buffer.outsize[i];
      buffer.outunit[i] = UNIT_8_BIT;
   }

#ifdef IPSEC_SCATTER_GATHER
   buffer.dma_mode = CAVIUM_SCATTER_GATHER;
#else
   buffer.dma_mode = CAVIUM_DIRECT;
#endif

//#ifdef NPLUS
   buffer.group = CAVIUM_IPSEC_GRP;
//#endif
   buffer.req_queue = req_queue;
   buffer.req_type = 0;
   buffer.res_order = response_order;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;
   cond_code = 
       ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);

   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */


   return ret_val;
}
#endif /* IPSEC_TEST */

/*+****************************************************************************
 *
 * Csp1Random
 *
 * Get random data from random pool maintained by the driver.
 *
 * Input
 *    request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *          This api will only block if driver will have to refill
 *          its random number pool. THis argument is ignored by the 
 *          driver.
 *   length = size of random data in bytes 
 *
 * Output
 *   random = pointer to length bytes of random data
 *      request_id = Unique ID for this request. This argument is ignored by the 
 *                   driver.
 *
 * Return Value
 * 0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
Uint32 
#ifdef CAVIUM_MULTICARD_API
Csp1Random(n1_request_type request_type,
      Uint16 length, 
      Uint8 *random,
      Uint32 *request_id,Uint32 dev_id)
#else
Csp1Random(n1_request_type request_type,
      Uint16 length, 
      Uint8 *random,
      Uint32 *request_id)
#endif
{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;

   memset(&buffer,0,sizeof(Csp1OperationBuffer));
   buffer.opcode = (0x1<<8) | (global_dma_mode<<7) | MAJOR_OP_RANDOM_WRITE_CONTEXT;
   buffer.size = length;
   buffer.rlen = length;
   buffer.param = 0;
   buffer.dlen = 0;

   buffer.incnt = 0;      
   buffer.outcnt = 1;      

   buffer.group = CAVIUM_GP_GRP;

   buffer.outptr[0] = CAST_TO_X_PTR(random);
   buffer.outsize[0] = length;
   buffer.outoffset[0] = length;
   buffer.outunit[0] = UNIT_8_BIT;
   buffer.ctx_ptr = 0;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;

#ifdef CAVIUM_MULTICARD_API
   cond_code = ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_GET_RANDOM_CODE, (ptrlong)&buffer);
#else
   cond_code = ioctl(CSP1_driver_handle, IOCTL_N1_GET_RANDOM_CODE, (ptrlong)&buffer);
#endif

   *request_id = buffer.request_id;
   ret_val=cond_code;

   return ret_val;
}

/*+****************************************************************************
 *
 * Csp1Hash
 *
 * Compute the HASH of a complete message. Does not use context.
 *
 * Input
 *    request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *   hash_type = MD5_TYPE or SHA1_TYPE 
 *   message_length = size of input in bytes (0<=message_length<=2^16-1)
 *   message = pointer to length bytes of input to be HMACed
 *
 * Output
 *   hash = pointer to the hash_size HASH result 
 *   request_id = Unique ID for this request.
 *
 * Return Value
 *    0  = success 
 *    >0 = failure or pending
 *    see error_codes.txt
 *
 *-***************************************************************************/
#ifdef MC2
#ifdef CAVIUM_MULTICARD_API
Uint32 
Csp1Hash(n1_request_type request_type,
    HashType hash_type, 
    Uint16 message_length, 
    Uint8 *message, 
    Uint8 *hash,
    Uint32 *request_id,Uint32 dev_id)
#else
Uint32 
Csp1Hash(n1_request_type request_type,
    HashType hash_type, 
    Uint16 message_length, 
    Uint8 *message, 
    Uint8 *hash,
    Uint32 *request_id)
#endif
{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;
   Uint32 hash_size=0;
   memset(&buffer,0,sizeof(Csp1OperationBuffer));

   buffer.opcode = (0x3<<9) | (global_dma_mode<<7) | MAJOR_OP_HASH;
   buffer.size = 0;
   if (hash_type == MD5_TYPE) {
      buffer.param = 0x01;
      hash_size = 16;
   }
   else if (hash_type == SHA1_TYPE) {
      buffer.param = 0x02;
      hash_size = 20;
   }
   else if (hash_type == SHA256_TYPE) {
      buffer.param = 0x03;
      hash_size = SHA256_HASH_LEN;	//32bytes
   }
   else if (hash_type == SHA384_TYPE) {
      buffer.param = 0x04;
      hash_size = SHA384_HASH_LEN;	//48bytes
   }
   else if (hash_type == SHA512_TYPE) {
      buffer.param = 0x05;
      hash_size = SHA512_HASH_LEN;	//64bytes
   }
   buffer.dlen = message_length;
   buffer.rlen = (Uint16) hash_size;
   if(hash_size > SHA256_HASH_LEN) 
      buffer.incnt = 2;      
   else 
      buffer.incnt = 1;      
   buffer.outcnt = 1;      

   buffer.group = CAVIUM_SSL_GRP;

   if(hash_size > SHA256_HASH_LEN) { /*for sha384 and sha512*/
   buffer.inptr[0] = CAST_TO_X_PTR(message);
   buffer.insize[0] = SHA2_HASH_IV_LEN;/*iv(64B) in case of sha384 and sha512*/
   buffer.inoffset[0] = ROUNDUP8(SHA2_HASH_IV_LEN);
   buffer.inunit[0] = UNIT_8_BIT;

   buffer.inptr[1] = CAST_TO_X_PTR(message+SHA2_HASH_IV_LEN);
   buffer.insize[1] = message_length-SHA2_HASH_IV_LEN;/*len-64B*/
   buffer.inoffset[1] = ROUNDUP8(message_length-SHA2_HASH_IV_LEN);
   buffer.inunit[1] = UNIT_8_BIT;
   } else 
   if(hash_size <= SHA256_HASH_LEN) { /*for md5, sha1 and sha256*/
   buffer.inptr[0] = CAST_TO_X_PTR(message);
   buffer.insize[0] = message_length;
   buffer.inoffset[0] = ROUNDUP8(message_length);
   buffer.inunit[0] = UNIT_8_BIT;
   }

   buffer.outptr[0] = CAST_TO_X_PTR(hash);
   buffer.outsize[0] = hash_size;
   buffer.outoffset[0] = 24;
   buffer.outunit[0] = UNIT_8_BIT;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
      ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
      ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif

   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

   return ret_val;
}
#endif


/*+****************************************************************************
 *
 * Csp1Hmac
 *
 * Compute the HMAC of a complete message. Does not use context.
 *
 * Input
 *    request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *   hash_type = MD5_TYPE or SHA1_TYPE 
 *   key_length = size of the key in bytes (key_length%8=0, 8<=key_length<=64)
 *   key = pointer to key_length-byte key
 *   message_length = size of input in bytes (0<=message_length<=2^16-1)
 *   message = pointer to length bytes of input to be HMACed
 *
 * Output
 *   hmac = pointer to the hash_size HMAC result 
 *   request_id = Unique ID for this request.
 *
 * Return Value
 *    0  = success 
 *    >0 = failure or pending
 *    see error_codes.txt
 *
 *-***************************************************************************/
Uint32 
Csp1Hmac(n1_request_type request_type,
    HashType hash_type, 
    Uint8 *iv,
    Uint16 key_length, 
    Uint8 *key, 
    Uint16 message_length, 
    Uint8 *message, 
    Uint8 *hmac,
#ifdef CAVIUM_MULTICARD_API
    Uint32 *request_id,Uint32 dev_id
#else
    Uint32 *request_id
#endif
    )
{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;
   Uint32 hash_size=0;
   memset(&buffer,0,sizeof(Csp1OperationBuffer));

if((hash_type == MD5_TYPE) || (hash_type == SHA1_TYPE)) {
   if ((key_length < 8) || (key_length > 64))/*|| ((key_length & 0x7) != 0))*/
      return ERR_ILLEGAL_KEY_LENGTH;
} else { /*for SHA256, SHA384 and SHA512*/
   if ((key_length < 8) || (key_length > 900))/*|| ((key_length & 0x7) != 0))*/
      return ERR_ILLEGAL_KEY_LENGTH;
}

#ifdef MC2
   buffer.opcode = (0x3<<9) | (global_dma_mode<<7) | MAJOR_OP_HMAC;
#else
   buffer.opcode = (0x3<<9) | (hash_type<<8) | (global_dma_mode<<7) | MAJOR_OP_HMAC;
#endif

#ifdef MC2
   buffer.size = key_length;
   if (hash_type == SHA1_TYPE) {
      buffer.param = 0x02;
      hash_size = 20;
   } else if (hash_type == MD5_TYPE) {
      buffer.param = 0x01;
      hash_size = 16;
   } else if (hash_type == SHA256_TYPE) {
      buffer.param = 0x03;
      hash_size = 32;
   } else if (hash_type == SHA384_TYPE) {
      buffer.param = 0x04;
      hash_size = 48;
   } else if (hash_type == SHA512_TYPE) {
      buffer.param = 0x05;
      hash_size = 64;
   } else
      buffer.param = 0;
   if((hash_type == SHA384_TYPE) || (hash_type == SHA512_TYPE)) 
   buffer.dlen = key_length + message_length + 64;
   else
   buffer.dlen = key_length + message_length;
   buffer.rlen = (Uint16) hash_size;
#else
   buffer.size = message_length;
   buffer.param = (key_length>>3) - 1;
   buffer.dlen = (key_length + ROUNDUP8(message_length))>>3;
   buffer.rlen = (24 + 8)>>3;
#endif

#ifdef MC2
   if((hash_type == SHA384_TYPE) || (hash_type == SHA512_TYPE)) 
   buffer.incnt = 3;      
   else
#endif
   buffer.incnt = 2;      

   buffer.outcnt = 1;      

   buffer.group = CAVIUM_SSL_GRP;

#ifdef MC2
   if((hash_type == SHA384_TYPE) || (hash_type == SHA512_TYPE)) {
   buffer.inptr[0] = CAST_TO_X_PTR(iv);
   buffer.insize[0] = 64;
   buffer.inoffset[0] = 64;
   buffer.inunit[0] = UNIT_8_BIT;
   buffer.inptr[1] = CAST_TO_X_PTR(key);
   buffer.insize[1] = key_length;
   buffer.inoffset[1] = key_length;
   buffer.inunit[1] = UNIT_8_BIT;
   buffer.inptr[2] = CAST_TO_X_PTR(message);
   buffer.insize[2] = message_length;
   buffer.inoffset[2] = ROUNDUP8(message_length);
   buffer.inunit[2] = UNIT_8_BIT;
   }
else 
#endif
   {
   buffer.inptr[0] = CAST_TO_X_PTR(key);
   buffer.insize[0] = key_length;
   buffer.inoffset[0] = key_length;
   buffer.inunit[0] = UNIT_8_BIT;
   buffer.inptr[1] = CAST_TO_X_PTR(message);
   buffer.insize[1] = message_length;
   buffer.inoffset[1] = ROUNDUP8(message_length);
   buffer.inunit[1] = UNIT_8_BIT;
   }

   buffer.outptr[0] = CAST_TO_X_PTR(hmac);
   buffer.outsize[0] = hash_size;
   buffer.outoffset[0] = 24;
   buffer.outunit[0] = UNIT_8_BIT;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif

   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

   return ret_val;
}


/*+****************************************************************************
 *
 * Csp1HmacStart
 *
 *   Compute the first stage in a multi-step HMAC.
 *   
 * Input
 *    request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *   context_handle = 64-bit pointer to context (context_handle%8=0)
 *   hash_type = MD5_TYPE or SHA1_TYPE 
 *   key_length = size of the key in bytes (key_length%8=0, 8<=key_length<=64)
 *   key = pointer to key_length-byte key
 *   message_length = size of input in bytes (0<=message_length<=2^16-1)
 *   message = pointer to length bytes of input to be HMACed
 *
 * Output
 *   request_id = Unique ID for this request.
 *
 * Return Value
 *   0  = success 
 *   >0 = failure or pending
 *   see error_codes.txt
 *
 *-***************************************************************************/
Uint32 
Csp1HmacStart(n1_request_type request_type,
           Uint64 context_handle, 
           HashType hash_type, 
           Uint16 key_length, 
           Uint8 *key, 
           Uint16 message_length, 
           Uint8 *message,
#ifdef CAVIUM_MULTICARD_API
           Uint32 *request_id,Uint32 dev_id
#else
           Uint32 *request_id
#endif 
           ) 
{
#ifdef MC2
   return    ERR_OPERATION_NOT_SUPPORTED;
#else

   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;
   Uint32 hash_size;
   memset(&buffer,0,sizeof(Csp1OperationBuffer));

#if defined(CSP1_API_DEBUG)
   if ((context_handle & UINT64_C(0x8000000000000000)) != 0) {

      if ((context_handle & 0xf) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   } else {

      if ((context_handle & 0x7) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   }

   if ((key_length < 8) || (key_length > 64) || ((key_length & 0x7) != 0))

      return ERR_ILLEGAL_KEY_LENGTH;
#endif

   buffer.opcode = (0x1<<9) | (hash_type<<8) | (global_dma_mode<<7) | MAJOR_OP_HMAC;
//   hash_size = 20 - (hash_type<<2);
   hash_size = (hash_type==MD5_TYPE)? 16:20;

   buffer.size = message_length;
   buffer.param = (key_length>>3) - 1;
   buffer.dlen = (key_length + ROUNDUP8(message_length))>>3;
   buffer.rlen = (8)>>3;
   buffer.ctx_ptr = context_handle;

   buffer.incnt = 2;      
   buffer.outcnt = 0;      

   buffer.group = CAVIUM_SSL_GRP;

   buffer.inptr[0] = CAST_TO_X_PTR(key);
   buffer.insize[0] = key_length;
   buffer.inoffset[0] = key_length;
   buffer.inunit[0] = UNIT_8_BIT;
   buffer.inptr[1] = CAST_TO_X_PTR(message);
   buffer.insize[1] = message_length;
   buffer.inoffset[1] = ROUNDUP8(message_length);
   buffer.inunit[1] = UNIT_8_BIT;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = CAVIUM_SCATTER_GATHER;
   buffer.status = 0;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif


   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */


   return ret_val;
#endif /*MC2*/
}

 
/*+****************************************************************************
 *
 * Csp1HmacUpdate
 *
 *   Compute an intermediate step in a multi-step HMAC.
 *
 * Input
 *    request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *   context_handle = 64-bit pointer to context (context_handle%8=0)
 *   hash_type = MD5_TYPE or SHA1_TYPE 
 *   message_length = size of input in bytes (0<=message_length<=2^16-1)
 *   message = pointer to length bytes of input to be HMACed
 *
 * Output
 *   request_id = Unique ID for this request.
 *
 * Return Value
 *   0  = success 
 *   >0 = failure or pending
 *    see error_codes.txt
 *
 *-***************************************************************************/
Uint32 
Csp1HmacUpdate(n1_request_type request_type,
            Uint64 context_handle, 
            HashType hash_type, 
            Uint16 message_length, 
            Uint8 *message,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )
{
#ifdef MC2
   return ERR_OPERATION_NOT_SUPPORTED;
#else
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;
   Uint32 hash_size;
   memset(&buffer,0,sizeof(Csp1OperationBuffer));

#if defined(CSP1_API_DEBUG)
   if ((context_handle & UINT64_C(0x8000000000000000)) != 0) {

      if ((context_handle & 0xf) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   } else {

      if ((context_handle & 0x7) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   }
#endif

   buffer.opcode = (0x0<<9) | (hash_type<<8) | (global_dma_mode<<7) | MAJOR_OP_HMAC;
//   hash_size = 20 - (hash_type<<2);
   hash_size = (hash_type==MD5_TYPE)? 16:20;

   buffer.size = message_length;
   buffer.param = 0;
   buffer.dlen = (ROUNDUP8(message_length))>>3;
   buffer.rlen = (8)>>3;
   buffer.ctx_ptr = context_handle;

   buffer.incnt = 1;      
   buffer.outcnt = 0;      

   buffer.group = CAVIUM_SSL_GRP;

   buffer.inptr[0] = CAST_TO_X_PTR(message);
   buffer.insize[0] = message_length;
   buffer.inoffset[0] = ROUNDUP8(message_length);
   buffer.inunit[0] = UNIT_8_BIT;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif


   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */


   return ret_val;

#endif /*MC2*/
}

          
/*+****************************************************************************
 *
 * Csp1HmacFinish
 *
 *   Compute the final step in a multi-step HMAC.
 *
 * Input
 *    request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *   context_handle = 64-bit pointer to context (context_handle%8=0)
 *   hash_type = MD5_TYPE or SHA1_TYPE 
 *   message_length = size of input in bytes (0<=message_length<=2^16-1)
 *   message = pointer to length bytes of input to be HMACed
 *
 * Output
 *   final_hmac = pointer to the hash_size-word HMAC result 
 *   request_id = Unique ID for this request.
 *
 * Return Value
 *   0  = success 
 *   >0 = failure or pending
 *    see error_codes.txt
 *
 *-***************************************************************************/
Uint32 
Csp1HmacFinish(n1_request_type request_type,
      Uint64 context_handle, 
      HashType hash_type, 
      Uint16 message_length, 
      Uint8 *message, 
      Uint8 *final_hmac,
#ifdef CAVIUM_MULTICARD_API
      Uint32 *request_id,Uint32 dev_id
#else
      Uint32 *request_id
#endif
     )

{
#ifdef MC2
   return ERR_OPERATION_NOT_SUPPORTED;
#else
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;
   Uint32 hash_size;
   memset(&buffer,0,sizeof(Csp1OperationBuffer));

#if defined(CSP1_API_DEBUG)
   if ((context_handle & UINT64_C(0x8000000000000000)) != 0) {

      if ((context_handle & 0xf) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   } else {

      if ((context_handle & 0x7) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   }
#endif

   buffer.opcode = (0x2<<9) | (hash_type<<8) | (global_dma_mode<<7) | MAJOR_OP_HMAC;
//   hash_size = 20 - (hash_type<<2);
   hash_size = (hash_type==MD5_TYPE)? 16:20;

   buffer.size = message_length;
   buffer.param = 0;
   buffer.dlen = (ROUNDUP8(message_length))>>3;
   buffer.rlen = (24 + 8)>>3;
   buffer.ctx_ptr = context_handle;

   buffer.incnt = 1;      
   buffer.outcnt = 1;      

   buffer.group = CAVIUM_SSL_GRP;

   buffer.inptr[0] = CAST_TO_X_PTR(message);
   buffer.insize[0] = message_length;
   buffer.inoffset[0] = ROUNDUP8(message_length);
   buffer.inunit[0] = UNIT_8_BIT;

   buffer.outptr[0] = CAST_TO_X_PTR(final_hmac);
   buffer.outsize[0] = hash_size;
   buffer.outoffset[0] = 24;
   buffer.outunit[0] = UNIT_8_BIT;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif


   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

   return ret_val;
#endif /*MC2*/
}


/*+****************************************************************************
 *
 * Csp1Me
 *
 * Modular exponentiation.
 *
 * p = x^e mod m
 *
 * Input
 *      request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *   #ifdef MC2
 *      modlength = size of modulus in bytes (16<=modlength<=512)
 *      explength = size of exponent in bytes 
 *      datalength = size of data in bytes
 *      modulus = pointer to modlength-byte modulus
 *      exponent = pointer to explength-byte exponent
 *      data = pointer to datalength-byte data
 *   #else
 *      result_location = CONTEXT_PTR or RESULT_PTR 
 *      context_handle = 64-bit pointer to context (context_handle%8=0)
 *      modlength = size of modulus in bytes (modlength%8=0, 24<modlength<=256)
 *      data = pointer to modlength-byte value to be exponentiated
 *      modulus = pointer to modlength-byte modulus
 *      exponent = pointer to modlength-byte exponent
 *   #endif
 *
 * Output
 *   #ifdef MC2
 *      result = pointer to modlength-byte output
 *   #else
 *      result = if (result_location == RESULT_PTR) pointer to modlength-byte 
 *             output in byte format
 *   #endif
 *      request_id = Unique ID for this request.
 *
 * Return Value
 *      0  = success 
 *      >0 = failure or pending
 *      see error_codes.txt
 *
 *-***************************************************************************/
#ifdef MC2
Uint32 
Csp1Me(n1_request_type request_type,
      Uint16 modlength,
      Uint16 explength,
      Uint16 datalength,
      Uint8 *modulus,
      Uint8 *exponent,
      Uint8 *data, 
      Uint8 *result,
#ifdef CAVIUM_MULTICARD_API
      Uint32 *request_id,Uint32 dev_id
#else
      Uint32 *request_id
#endif
      )

#else
Uint32 
Csp1Me(n1_request_type request_type,
      ResultLocation result_location,
      Uint64 context_handle, 
      Uint16 modlength, 
      Uint8 *data, 
      Uint8 *modulus, 
      Uint8 *exponent,
      Uint8 *result,
#ifdef CAVIUM_MULTICARD_API
      Uint32 *request_id,Uint32 dev_id
#else
      Uint32 *request_id
#endif
      )

#endif
{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;
#ifndef MC2
   Uint16 length = 0;
#endif
   memset(&buffer,0,sizeof(Csp1OperationBuffer));

#if defined(CSP1_API_DEBUG)
   if (result_location == CONTEXT_PTR) {

      if ((context_handle & UINT64_C(0x8000000000000000)) != 0) {

         if ((context_handle & 0xf) != 0)

            return ERR_ILLEGAL_CONTEXT_HANDLE;

      } else {

         if ((context_handle & 0x7) != 0)

            return ERR_ILLEGAL_CONTEXT_HANDLE;

      }
   }

   if ((modlength & 0x7) != 0)

      return ERR_ILLEGAL_INPUT_LENGTH;
#endif

#ifdef MC2
   if ((modlength >= 17) && (modlength <= 128)) {
#else
   if ((modlength >= 24) && (modlength <= 128)) {
#endif

#ifdef MC2
      buffer.opcode = (MAJOR_OP_ME_PKCS) | (global_dma_mode<<7) ;
   } else if ((modlength > 128) && (modlength <= 512)) {
#else
      buffer.opcode = (result_location<<9) | (0x0<<8) | (global_dma_mode<<7) 
         | MAJOR_OP_ME_PKCS;
      length = (modlength>>3) - 1;
   } else if ((modlength > 128) && (modlength <= 256)) {
#endif


#ifdef MC2
      buffer.opcode = (MAJOR_OP_ME_PKCS_LARGE) | (global_dma_mode<<7);
#else
      buffer.opcode = (result_location<<9) | (0x0<<8) | (global_dma_mode<<7) 
         | MAJOR_OP_ME_PKCS_LARGE;
      length = (modlength>>3) - 17;
#endif

#if defined(CSP1_API_DEBUG)
   } else {

      return ERR_ILLEGAL_INPUT_LENGTH;
#endif
   }

#ifdef MC2
   buffer.ctx_ptr=0;
   buffer.dlen = modlength + explength + datalength;
   buffer.param = explength;
   buffer.size = modlength;
   buffer.rlen = modlength;
#else
   buffer.size = length;
   buffer.param = 0;
   buffer.dlen = (3 * modlength)>>3;
   buffer.rlen = (8)>>3;
   buffer.ctx_ptr = context_handle;
#endif

#ifdef MC2 
   buffer.incnt = 3;
   buffer.inptr[0] = CAST_TO_X_PTR(modulus);
   buffer.insize[0] = modlength;
   buffer.inoffset[0] = modlength;
   buffer.inunit[0] = UNIT_8_BIT;
   buffer.inptr[1] = CAST_TO_X_PTR(exponent);
   buffer.insize[1] = explength;
   buffer.inoffset[1] = explength;
   buffer.inunit[1] = UNIT_8_BIT;
   buffer.inptr[2] = CAST_TO_X_PTR(data);
   buffer.insize[2] = datalength;
   buffer.inoffset[2] = datalength;
   buffer.inunit[2] = UNIT_8_BIT;

        buffer.outcnt = 1;

        buffer.outptr[0] = CAST_TO_X_PTR(result);
        buffer.outsize[0] = modlength;
        buffer.outoffset[0] = modlength;
        buffer.outunit[0] = UNIT_8_BIT;

#else 
   buffer.incnt = 3;
   buffer.inptr[0] = CAST_TO_X_PTR(data);
   buffer.insize[0] = modlength;
   buffer.inoffset[0] = modlength;
   buffer.inunit[0] = UNIT_8_BIT;
   buffer.inptr[1] = CAST_TO_X_PTR(modulus);
   buffer.insize[1] = modlength;
   buffer.inoffset[1] = modlength;
   buffer.inunit[1] = UNIT_8_BIT;
   buffer.inptr[2] = CAST_TO_X_PTR(exponent);
   buffer.insize[2] = modlength;
   buffer.inoffset[2] = modlength;
   buffer.inunit[2] = UNIT_8_BIT;
#endif

   buffer.group = CAVIUM_GP_GRP;

    buffer.req_queue = 0;
    buffer.req_type = request_type;
    buffer.res_order = CAVIUM_RESPONSE_ORDERED;
    buffer.dma_mode = global_dma_mode;

#ifndef MC2
   if (result_location == RESULT_PTR) {

      buffer.rlen += (modlength>>3);

      buffer.outcnt = 1;   
      
      buffer.outptr[0] = CAST_TO_X_PTR(result);
      buffer.outsize[0] = modlength;
      buffer.outoffset[0] = modlength;
      buffer.outunit[0] = UNIT_8_BIT;

   } else if (result_location == CONTEXT_PTR)

      buffer.outcnt = 0;
#endif
   buffer.status = 0;

       cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif


      *request_id = buffer.request_id;

   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

      return ret_val;
}


/*+****************************************************************************
 *
 * Csp1Pkcs1v15Enc
 *
 * Creates PKCS#1v1.5 container.
 *
 * Input
 *      request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *   #ifdef MC2
 *      block_type = type of PKCS#1v1.5 padding (BT1 or BT2)
 *      modlength = size of modulus in bytes 
 *      explength = size of exponent in bytes 
 *      datalength = size of data in bytes
 *      modulus = pointer to modlength-byte modulus
 *      exponent = pointer to explength-byte exponent
 *      data = pointer to datalength-byte data
 *   #else
 *      result_location = CONTEXT_PTR or RESULT_PTR 
 *      context_handle = 64-bit pointer to context (context_handle%8=0)
 *      key_material_input = KEY_HANDLE or INPUT_DATA
 *      key_handle = 64-bit handle for key memory 
 *      block_type = type of PKCS#1v1.5 padding (BT1 or BT2)
 *      modlength = size of modulus in bytes (modlength%8=0, 24<modlength<=256)
 *      modulus = (key_material_input == INPUT_DATA) ? pointer to RSA modulus : don't care
 *      exponent = (key_material_input == INPUT_DATA) ? pointer to RSA exponent : don't care
 *      length = size of the input value 
 *      data = pointer to length-byte value to be exponentiated
 *   #endif
 *
 * Output
 *   #ifdef MC2
 *      result = pointer to modlength bytes of output
 *   #else
 *      result = (result_location == RESULT_PTR) ? (pointer to modlength bytes of output: don't care)
 *   #endif
 *      request_id = Unique ID for this request.
 *
 * Return Value
 *      0  = success 
 *      >0 = failure or pending
 *      see error_codes.txt
 *
 *-***************************************************************************/
#ifdef MC2
Uint32 
Csp1Pkcs1v15Enc(n1_request_type request_type,
            RsaBlockType block_type,
            Uint16 modlength, 
            Uint16 explength,
            Uint16 datalength, 
            Uint8 *modulus, 
            Uint8 *exponent, 
            Uint8 *data,
            Uint8 *result,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

#else
Uint32 
Csp1Pkcs1v15Enc(n1_request_type request_type,
            ResultLocation result_location, 
            Uint64 context_handle,
            KeyMaterialInput key_material_input,
            Uint64 key_handle, 
            RsaBlockType block_type,
            Uint16 modlength, 
            Uint8 *modulus, 
            Uint8 *exponent, 
            Uint16 length, 
            Uint8 *data,
            Uint8 *result,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

#endif
{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;
#ifndef MC2
   Uint16 size = 0;
   Uint8 *p_modulus = NULL, *p_exponent = NULL;
   Uint8 pkey[512];
   Uint64 tmp_key;
   Uint32 dummy=0;
   memset(&buffer,0,sizeof(Csp1OperationBuffer));

   if (result_location == CONTEXT_PTR) {

      if ((context_handle & UINT64_C(0x8000000000000000)) != 0) {

         if ((context_handle & 0xf) != 0)
            return ERR_ILLEGAL_CONTEXT_HANDLE;

      } else {

         if ((context_handle & 0x7) != 0)
            return ERR_ILLEGAL_CONTEXT_HANDLE;
      }
   }

   if ((modlength & 0x7) != 0)
      return ERR_ILLEGAL_INPUT_LENGTH;

   if (key_handle & (((Uint64)0x10000) << 32))
      return ERR_ILLEGAL_MOD_EX_TYPE;
#endif

#ifdef MC2 

        memset(&buffer,0,sizeof(Csp1OperationBuffer));
        buffer.ctx_ptr=0;
        buffer.dlen = modlength + explength + datalength;
        buffer.size = modlength;
        buffer.param = (block_type) | (explength<<1);
        buffer.rlen = modlength;

#else
   if (key_material_input == KEY_HANDLE) {

         if (key_handle & (((Uint64)0x20000) << 32)) {
         
         tmp_key = key_handle & UINT64_C(0x0000ffffffffffff);
         
#ifdef CAVIUM_MULTICARD_API
         if(Csp1ReadContext(CAVIUM_BLOCKING, tmp_key, (2*modlength), pkey,&dummy,dev_id))
#else
         if(Csp1ReadContext(CAVIUM_BLOCKING, tmp_key, (2*modlength), pkey,&dummy))
#endif
         
            return ERR_ILLEGAL_KEY_HANDLE;

         p_modulus = &(pkey[0]);
         p_exponent = &(pkey[modlength]);
         buffer.param = (Uint16)0x4000;

      }

      else if (key_handle & 0x8000) {

         buffer.param = (Uint16)key_handle & 0xffff; 

      } else {

         buffer.param = ((Uint16)key_handle & 0x1ff8) >> 3;

      }
   
   } else if (key_material_input == INPUT_DATA) {

      buffer.param = (Uint16)0x4000;
      p_modulus = modulus;
      p_exponent = exponent;

   }
#endif
#ifdef MC2
   if ((modlength >= 17) && (modlength <= 128)) {
#else
   if ((modlength >= 24) && (modlength <= 128)) {
#endif

#ifdef MC2
      buffer.opcode = (global_dma_mode<<7) | (0x3<<8) | MAJOR_OP_ME_PKCS;
   } else if ((modlength > 128) && (modlength <= 512)) {
#else
      size = (length<<8) + (NORMAL_MOD_EX << 7) + ((modlength>>3) - 1);
      buffer.opcode = (result_location<<12) | (block_type<<10) | (0x3<<8) 
         | (global_dma_mode<<7) | MAJOR_OP_ME_PKCS;
   } else if ((modlength > 128) && (modlength <= 256)) {
#endif

#ifdef MC2
      buffer.opcode = (global_dma_mode<<7) | (0x3<<8) | MAJOR_OP_ME_PKCS_LARGE;
#else
      size = (length<<8) + (NORMAL_MOD_EX << 7) + ((modlength>>3) - 17);
      buffer.opcode = (result_location<<12) | (block_type<<10) | (0x3<<8) 
         | (global_dma_mode<<7) | MAJOR_OP_ME_PKCS_LARGE;
#endif

#if defined(CSP1_API_DEBUG)
   } else {

      return ERR_ILLEGAL_INPUT_LENGTH;
#endif
   }

#ifdef MC2
   buffer.incnt = 3;

   buffer.inptr[0] = CAST_TO_X_PTR(modulus);
   buffer.insize[0] = modlength;
   buffer.inoffset[0] = modlength;
   buffer.inunit[0] = UNIT_8_BIT;
   buffer.inptr[1] = CAST_TO_X_PTR(exponent);
   buffer.insize[1] = explength;
   buffer.inoffset[1] = explength;
   buffer.inunit[1] = UNIT_8_BIT;
   buffer.inptr[2] = CAST_TO_X_PTR(data);
   buffer.insize[2] = datalength;
   buffer.inoffset[2] = datalength;
   buffer.inunit[2] = UNIT_8_BIT;

   buffer.outcnt = 1;

   buffer.outptr[0] = CAST_TO_X_PTR(result);
   buffer.outsize[0] = modlength;
   buffer.outoffset[0] = modlength;
   buffer.outunit[0] = UNIT_8_BIT;

#else 
   buffer.size = size;
   buffer.dlen = (modlength>>3);
   buffer.rlen = (8)>>3;
   buffer.ctx_ptr = context_handle;

   if ((key_material_input == INPUT_DATA)
       ||
       (key_handle & (((Uint64)0x20000) << 32))) {

      buffer.dlen += ((2*modlength)>>3);

      buffer.incnt = 3;      

      buffer.inptr[0] = CAST_TO_X_PTR(data);
      buffer.insize[0] = modlength;
      buffer.inoffset[0] = modlength;
      buffer.inunit[0] = UNIT_8_BIT;
      buffer.inptr[1] = CAST_TO_X_PTR(p_modulus);
      buffer.insize[1] = modlength;
      buffer.inoffset[1] = modlength;
      buffer.inunit[1] = UNIT_8_BIT;
      buffer.inptr[2] = CAST_TO_X_PTR(p_exponent);
      buffer.insize[2] = modlength;
      buffer.inoffset[2] = modlength;
      buffer.inunit[2] = UNIT_8_BIT;
      buffer.inptr[3] = CAST_TO_X_PTR(data);
      buffer.insize[3] = modlength;
      buffer.inoffset[3] = modlength;
      buffer.inunit[3] = UNIT_8_BIT;

   } else {

      buffer.incnt = 1;      

      buffer.inptr[0] = CAST_TO_X_PTR(data);
      buffer.insize[0] = modlength;
      buffer.inoffset[0] = modlength;
      buffer.inunit[0] = UNIT_8_BIT;

   }

   if (result_location == RESULT_PTR) {

      buffer.rlen += (modlength>>3);

      buffer.outcnt = 1;      

      buffer.outptr[0] = CAST_TO_X_PTR(result);
      buffer.outsize[0] = modlength;
      buffer.outoffset[0] = modlength;
      buffer.outunit[0] = UNIT_8_BIT;

   } else if (result_location == CONTEXT_PTR) {

      buffer.outcnt = 0;      

   }
#endif

   buffer.group = CAVIUM_SSL_GRP;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif


   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

   return ret_val;
}


/*+****************************************************************************
 *
 * Csp1Pkcs1v15CrtEnc
 *
 * Creates PKCS#1v1.5 container using the Chinese Remainder Theorem.
 * The combination of block type BT2 and CRT may produce unpredictable results.
 *
 * Input
 *      request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *   #ifdef MC2
 *      block_type = type of PKCS#1v1.5 padding (BT1 only)
 *      modlength = size of modulus in bytes
 *      datalength = size of input data in bytes.
 *      Q = prime factor of RSA modulus
 *      Eq = exponent mod(Q-1)
 *      P = prime factor of RSA modulus
 *      Ep = exponent mod(P-1)
 *      iqmp = (Q^-1) mod P
 *   #else
 *      result_location = CONTEXT_PTR or RESULT_PTR 
 *      context_handle = 64-bit pointer to context (context_handle%8=0)
 *      key_material_input = KEY_HANDLE or INPUT_DATA
 *      key_handle = 64-bit handle for key memory 
 *      block_type = type of PKCS#1v1.5 padding (BT1 only)
 *      modlength = size of modulus in bytes (modlength%8=0, 24<modlength<=256)
 *      Q = (key_material_input == INPUT_DATA) ? prime factor of RSA modulus : don't care
 *      Eq = (key_material_input == INPUT_DATA) ? exponent mod(Q-1) : don't care
 *      P = (key_material_input == INPUT_DATA) ? prime factor of RSA modulus : don't care
 *      Ep = (key_material_input == INPUT_DATA) ? exponent mod(P-1) : don't care
 *      iqmp = (key_material_input == INPUT_DATA) ? (Q^-1) mod P : don't care
 *      length = size of the input value 
 *   #endif
 *      data = pointer to length-byte value to be exponentiated
 *
 * Output
 *   #ifdef MC2
 *      result = pointer to modlength bytes of output
 *   #else
 *      result = (result_location == RESULT_PTR) ? (pointer to modlength bytes of output : don't care
 *   #endif
 *      request_id = Unique ID for this request.
 * 
 *
 * Return Value
 *      0  = success 
 *      >0 = failure or pending
 *      see error_codes.txt
 *
 *-***************************************************************************/
#ifdef MC2
Uint32 
Csp1Pkcs1v15CrtEnc(n1_request_type request_type,
               RsaBlockType block_type,
               Uint16 modlength, 
               Uint16 datalength, 
               Uint8 *Q, 
               Uint8 *Eq, 
               Uint8 *P, 
               Uint8 *Ep, 
               Uint8 *iqmp, 
               Uint8 *data,
               Uint8 *result,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

#else
Uint32 
Csp1Pkcs1v15CrtEnc(n1_request_type request_type,
               ResultLocation result_location, 
               Uint64 context_handle, 
               KeyMaterialInput key_material_input,
               Uint64 key_handle, 
               RsaBlockType block_type,
               Uint16 modlength, 
               Uint8 *Q, 
               Uint8 *Eq, 
               Uint8 *P, 
               Uint8 *Ep, 
               Uint8 *iqmp, 
               Uint16 length, 
               Uint8 *data,
               Uint8 *result,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

#endif
{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;
#ifndef MC2
   Uint16 size = 0;
   Uint8 *p_Q = NULL, *p_Eq = NULL, *p_P = NULL, *p_Ep = NULL, *p_iqmp = NULL;
   Uint8 pkey[640];
   Uint64 tmp_key;
   Uint32 dummy=0;
#endif
   memset(&buffer,0,sizeof(Csp1OperationBuffer));

#if defined(CSP1_API_DEBUG)
   if (result_location == CONTEXT_PTR) {

      if ((context_handle & UINT64_C(0x8000000000000000)) != 0) {

         if ((context_handle & 0xf) != 0)

            return ERR_ILLEGAL_CONTEXT_HANDLE;

      } else {

         if ((context_handle & 0x7) != 0)

            return ERR_ILLEGAL_CONTEXT_HANDLE;

      }
   }

   
   if (block_type == BT2) 

      return ERR_ILLEGAL_BLOCK_TYPE;

   if ((modlength & 0x7) != 0)

      return ERR_ILLEGAL_INPUT_LENGTH;

   if (!(key_handle & (((Uint64)0x10000) << 32)))

      return ERR_ILLEGAL_MOD_EX_TYPE;
#endif

#ifdef MC2
   buffer.ctx_ptr=0;
   buffer.dlen = (Uint16) (2.5 * modlength + datalength);
   buffer.size = modlength;
   buffer.param = (block_type);
   buffer.rlen = modlength;
#else
   if (key_material_input == KEY_HANDLE) {

      if (key_handle & (((Uint64)0x20000) << 32)) {

         tmp_key = key_handle & UINT64_C(0x0000ffffffffffff);
         
#ifdef CAVIUM_MULTICARD_API
         if(Csp1ReadContext(CAVIUM_BLOCKING,tmp_key, (5*modlength/2), pkey, &dummy,dev_id))
#else
         if(Csp1ReadContext(CAVIUM_BLOCKING,tmp_key, (5*modlength/2), pkey, &dummy))
#endif
         
            return ERR_ILLEGAL_KEY_HANDLE;

         p_Q = &(pkey[0]);
         p_Eq = &(pkey[modlength/2]); 
         p_P = &(pkey[2*(modlength/2)]);
         p_Ep = &(pkey[3*(modlength/2)]); 
         p_iqmp = &(pkey[4*(modlength/2)]);

         buffer.param = (Uint16)0x4000;

      }

      else if (key_handle & 0x8000) {

         buffer.param = (Uint16)key_handle & 0xffff; 

      } else {

         buffer.param = ((Uint16)key_handle & 0x1ff8) >> 3;

      }
   
   } else if (key_material_input == INPUT_DATA) {

      buffer.param = (Uint16)0x4000;
      p_Q = Q;
      p_Eq = Eq; 
      p_P = P;
      p_Ep = Ep; 
      p_iqmp = iqmp; 

   }
#endif

#ifdef MC2
   if ((modlength >= 34) && (modlength <= 128) && ((modlength & 0x1) == 0)) {
#else
   if ((modlength >= 48) && (modlength <= 128) && ((modlength & 0x1) == 0)) {
#endif

#ifdef MC2
         buffer.opcode = (global_dma_mode<<7) | (0x4<<8) | MAJOR_OP_ME_PKCS;
   } else if ((modlength > 128) && (modlength <= 512) && ((modlength & 0x1) == 0)) {
#else
      size = (length<<8) + (CRT_MOD_EX << 7) + ((modlength>>3) - 1);
      buffer.opcode = (result_location<<12) | (block_type<<10) | (0x3<<8) 
         | (global_dma_mode<<7) | MAJOR_OP_ME_PKCS;
   } else if ((modlength > 128) && (modlength <= 256) && ((modlength & 0x1) == 0)) {
#endif


#ifdef MC2
      buffer.opcode = (global_dma_mode<<7) | (0x4<<8) | MAJOR_OP_ME_PKCS_LARGE;
#else
      size = (length<<8) + (CRT_MOD_EX << 7) + ((modlength>>3) - 17);
      buffer.opcode = (result_location<<12) | (block_type<<10) | (0x3<<8) 
         | (global_dma_mode<<7) | MAJOR_OP_ME_PKCS_LARGE;
#endif

#if defined(CSP1_API_DEBUG)
   } else {

      return ERR_ILLEGAL_INPUT_LENGTH;
#endif
   }

#ifdef MC2
   buffer.incnt = 6;

   buffer.inptr[0] = CAST_TO_X_PTR(Q);
   buffer.insize[0] = modlength/2;
   buffer.inoffset[0] = modlength/2;
   buffer.inunit[0] = UNIT_8_BIT;
   buffer.inptr[1] = CAST_TO_X_PTR(Eq);
   buffer.insize[1] = modlength/2;
   buffer.inoffset[1] = modlength/2;
   buffer.inunit[1] = UNIT_8_BIT;
   buffer.inptr[2] = CAST_TO_X_PTR(P);
   buffer.insize[2] = modlength/2;
   buffer.inoffset[2] = modlength/2;
   buffer.inunit[2] = UNIT_8_BIT;
   buffer.inptr[3] = CAST_TO_X_PTR(Ep);
   buffer.insize[3] = modlength/2;
   buffer.inoffset[3] = modlength/2;
   buffer.inunit[3] = UNIT_8_BIT;
   buffer.inptr[4] = CAST_TO_X_PTR(iqmp);
   buffer.insize[4] = modlength/2;
   buffer.inoffset[4] = modlength/2;
   buffer.inunit[4] = UNIT_8_BIT;
   buffer.inptr[5] = CAST_TO_X_PTR(data);
   buffer.insize[5] = datalength;
   buffer.inoffset[5] = datalength;
   buffer.inunit[5] = UNIT_8_BIT;

   buffer.outcnt = 1;

   buffer.outptr[0] = CAST_TO_X_PTR(result);
   buffer.outsize[0] = modlength;
   buffer.outoffset[0] = modlength;
   buffer.outunit[0] = UNIT_8_BIT;
#else 
   buffer.size = size;
   buffer.dlen = (ROUNDUP8(modlength))>>3;
   buffer.rlen = (8)>>3;
   buffer.ctx_ptr = context_handle;
   if ((key_material_input == INPUT_DATA)
      ||
      (key_handle & (((Uint64)0x20000) << 32))) {

      buffer.dlen += ((5*modlength/2)>>3);

      buffer.incnt = 6;      

      buffer.inptr[0] = CAST_TO_X_PTR(data);
      buffer.insize[0] = modlength;
      buffer.inoffset[0] = modlength;
      buffer.inunit[0] = UNIT_8_BIT;
      buffer.inptr[1] = CAST_TO_X_PTR(p_Q);
      buffer.insize[1] = modlength/2;
      buffer.inoffset[1] = modlength/2;
      buffer.inunit[1] = UNIT_8_BIT;
      buffer.inptr[2] = CAST_TO_X_PTR(p_Eq);
      buffer.insize[2] = modlength/2;
      buffer.inoffset[2] = modlength/2;
      buffer.inunit[2] = UNIT_8_BIT;
      buffer.inptr[3] = CAST_TO_X_PTR(p_P);
      buffer.insize[3] = modlength/2;
      buffer.inoffset[3] = modlength/2;
      buffer.inunit[3] = UNIT_8_BIT;
      buffer.inptr[4] = CAST_TO_X_PTR(p_Ep);
      buffer.insize[4] = modlength/2;
      buffer.inoffset[4] = modlength/2;
      buffer.inunit[4] = UNIT_8_BIT;
      buffer.inptr[5] = CAST_TO_X_PTR(p_iqmp);
      buffer.insize[5] = modlength/2;
      buffer.inoffset[5] = modlength/2;
      buffer.inunit[5] = UNIT_8_BIT;

   } else {

      buffer.incnt = 1;      

      buffer.inptr[0] = CAST_TO_X_PTR( data);
      buffer.insize[0] = modlength;
      buffer.inoffset[0] = modlength;
      buffer.inunit[0] = UNIT_8_BIT;

   }

   if (result_location == RESULT_PTR) {

      buffer.rlen += (modlength>>3);

      buffer.outcnt = 1;      

      buffer.outptr[0] = CAST_TO_X_PTR(result);
      buffer.outsize[0] = modlength;
      buffer.outoffset[0] = modlength;
      buffer.outunit[0] = UNIT_8_BIT;

   } else if (result_location == CONTEXT_PTR) {

      buffer.outcnt = 0;      

   }
#endif
 
   buffer.group = CAVIUM_SSL_GRP;
   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif


   *request_id = buffer.request_id;

   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

   return ret_val;
}


/*+****************************************************************************
 *
 * Csp1Pkcs1v15Dec
 *
 * Decrypts PKCS#1v1.5 container.
 *
 * Input
 *      request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *   #ifdef MC2
 *      block_type = type of PKCS#1v1.5 padding (BT1 only)
 *      modlength = size of modulus in bytes
 *      explength = size of exponent in bytes
 *      modulus = pointer to modlength-byte modulus
 *      exponent = pointer to explength-byte exponent
 *      data = pointer to modlength-11 bytes input
 *   #else
 *      result_location = CONTEXT_PTR or RESULT_PTR 
 *      context_handle = 64-bit pointer to context (context_handle%8=0)
 *      key_material_input = KEY_HANDLE or INPUT_DATA
 *      key_handle = 64-bit handle for key memory 
 *      block_type = type of PKCS#1v1.5 padding (BT1 or BT2)
 *      modlength = size of modulus in bytes (modlength%8=0, 24<modlength<=256)
 *      modulus = (key_material_input == INPUT_DATA) ? pointer to RSA modulus : don't care
 *      exponent = (key_material_input == INPUT_DATA) ? pointer to RSA exponent : don't care
 *      data = pointer to modlength-byte value to be exponentiated
 *   #endif
 *
 * Output
 *   #ifdef MC2
 *      out_length = size of decrypted data in Network Byte order.
 *      result = out_length byte size result
 *   #else
 *      result = (result_location == RESULT_PTR) ? (pointer to modlength bytes of output, 
 *            *out_length bytes used) : don't care
 *      out_length = pointer to output length in bytes
 *   #endif
 *      request_id = Unique ID for this request.
 *
 * Return Value
 *      0  = success 
 *      >0 = failure or pending
 *      see error_codes.txt
 *
 *-***************************************************************************/
#ifdef MC2
Uint32 
Csp1Pkcs1v15Dec(n1_request_type request_type,
            RsaBlockType block_type,
            Uint16 modlength, 
            Uint16 explength,
            Uint8 *modulus, 
            Uint8 *exponent, 
            Uint8 *data,
            Uint16 *out_length,
            Uint8 *result,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

#else
Uint32 
Csp1Pkcs1v15Dec(n1_request_type request_type,
            ResultLocation result_location, 
            Uint64 context_handle, 
            KeyMaterialInput key_material_input,
            Uint64 key_handle, 
            RsaBlockType block_type,
            Uint16 modlength, 
            Uint8 *modulus, 
            Uint8 *exponent, 
            Uint8 *data,
            Uint8 *result,
            Uint64 *out_length,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

#endif
{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;
#ifndef MC2
   Uint16 size = 0;
   Uint8 *p_modulus = NULL, *p_exponent = NULL;
   Uint8 pkey[512];
   Uint64 tmp_key;
   Uint32 dummy=0;
#endif          
   memset(&buffer,0,sizeof(Csp1OperationBuffer));

#if defined(CSP1_API_DEBUG)
   if (result_location == CONTEXT_PTR) {

      if ((context_handle & UINT64_C(0x8000000000000000)) != 0) {

         if ((context_handle & 0xf) != 0)

            return ERR_ILLEGAL_CONTEXT_HANDLE;

      } else {

         if ((context_handle & 0x7) != 0)

            return ERR_ILLEGAL_CONTEXT_HANDLE;

      }
   }


   if ((modlength & 0x7) != 0)

      return ERR_ILLEGAL_INPUT_LENGTH;

   if (key_handle & (((Uint64)0x10000) << 32))

      return ERR_ILLEGAL_MOD_EX_TYPE;
#endif

#ifdef MC2
   buffer.ctx_ptr=0;
   buffer.dlen = (2*modlength) + explength;
   buffer.size = modlength;
   buffer.param = (block_type) | (explength<<1);
   buffer.rlen = 2 + modlength; /* outlength + modlength bytes result */
#else 
   if (key_material_input == KEY_HANDLE) {

      if (key_handle & (((Uint64)0x20000) << 32)) {

         tmp_key = key_handle & UINT64_C(0x0000ffffffffffff);
         
#ifdef CAVIUM_MULTICARD_API
         if(Csp1ReadContext(CAVIUM_BLOCKING, tmp_key, (2*modlength), pkey, &dummy,dev_id))
#else
         if(Csp1ReadContext(CAVIUM_BLOCKING, tmp_key, (2*modlength), pkey, &dummy))
#endif
         
            return ERR_ILLEGAL_KEY_HANDLE;

         p_modulus = &(pkey[0]);
         p_exponent = &(pkey[modlength]);

         buffer.param = (Uint16)0x4000;

      }

      else if (key_handle & 0x8000) {

         buffer.param = (Uint16)key_handle & 0xffff; 

      } else {

         buffer.param = ((Uint16)key_handle & 0x1ff8) >> 3;

      }
   
   } else if (key_material_input == INPUT_DATA) {

      buffer.param = (Uint16)0x4000;
      p_modulus = modulus;
      p_exponent = exponent;

   }
#endif

#ifdef MC2
   if ((modlength >= 17) && (modlength <= 128)) {
#else
   if ((modlength >= 24) && (modlength <= 128)) {
#endif
#ifdef MC2
      buffer.opcode = (global_dma_mode<<7) | (0x1<<8) | MAJOR_OP_ME_PKCS;
   } else if ((modlength > 128) && (modlength <= 512)) {
#else
      size = (modlength>>3) - 1;
      buffer.opcode = (result_location<<12) | (block_type<<10) | (0x1<<8) 
         | (global_dma_mode<<7) | MAJOR_OP_ME_PKCS;
   } else if ((modlength > 128) && (modlength <= 256)) {
#endif

#ifdef MC2
      buffer.opcode = (global_dma_mode<<7) | (0x1<<8) | MAJOR_OP_ME_PKCS_LARGE;
#else
      size = (modlength>>3) - 17;
      buffer.opcode = (result_location<<12) | (block_type<<10) | (0x1<<8) 
         | (global_dma_mode<<7) | MAJOR_OP_ME_PKCS_LARGE;
#endif

#if defined(CSP1_API_DEBUG)
   } else {

      return ERR_ILLEGAL_INPUT_LENGTH;
#endif
   }

#ifdef MC2
   buffer.incnt = 3;

   buffer.inptr[0] = CAST_TO_X_PTR(modulus);
   buffer.insize[0] = modlength;
   buffer.inoffset[0] = modlength;
   buffer.inunit[0] = UNIT_8_BIT;
   buffer.inptr[1] = CAST_TO_X_PTR(exponent);
   buffer.insize[1] = explength;
   buffer.inoffset[1] = explength;
   buffer.inunit[1] = UNIT_8_BIT;
   buffer.inptr[2] = CAST_TO_X_PTR(data);
   buffer.insize[2] = modlength;
   buffer.inoffset[2] = modlength;
   buffer.inunit[2] = UNIT_8_BIT;

   buffer.outcnt = 2;

   buffer.outptr[0] = CAST_TO_X_PTR((Uint8 *)out_length);
   buffer.outsize[0] = 2;
   buffer.outoffset[0] = 2;
   buffer.outunit[0] = UNIT_16_BIT;
   buffer.outptr[1] = CAST_TO_X_PTR(result);
   buffer.outsize[1] = modlength;
   buffer.outoffset[1] = modlength;
   buffer.outunit[1] = UNIT_8_BIT;

#else 
   buffer.size = size;
   buffer.dlen = (modlength)>>3;
   buffer.rlen = (8 + 8)>>3;
   buffer.ctx_ptr = context_handle;

   if ((key_material_input == INPUT_DATA)
      ||
      (key_handle & (((Uint64)0x20000) << 32))) {

      buffer.dlen += ((2*modlength)>>3);

      buffer.incnt = 3;      

      buffer.inptr[0] = CAST_TO_X_PTR(data);
      buffer.insize[0] = modlength;
      buffer.inoffset[0] = modlength;
      buffer.inunit[0] = UNIT_8_BIT;
      buffer.inptr[1] = CAST_TO_X_PTR(p_modulus);
      buffer.insize[1] = modlength;
      buffer.inoffset[1] = modlength;
      buffer.inunit[1] = UNIT_8_BIT;
      buffer.inptr[2] = CAST_TO_X_PTR(p_exponent);
      buffer.insize[2] = modlength;
      buffer.inoffset[2] = modlength;
      buffer.inunit[2] = UNIT_8_BIT;

   } else {

      buffer.incnt = 1;      

      buffer.inptr[0] = CAST_TO_X_PTR(data);
      buffer.insize[0] = modlength;
      buffer.inoffset[0] = modlength;
      buffer.inunit[0] = UNIT_8_BIT;

   }

   if (result_location == RESULT_PTR) {

      buffer.rlen += (modlength>>3);

      buffer.outcnt = 2;      

      buffer.outptr[0] = CAST_TO_X_PTR(result);
      buffer.outsize[0] = modlength;
      buffer.outoffset[0] = modlength;
      buffer.outunit[0] = UNIT_8_BIT;
      buffer.outptr[1] = CAST_TO_X_PTR((Uint8 *)out_length);
      buffer.outsize[1] = 8;
      buffer.outoffset[1] = 8;
      buffer.outunit[1] = UNIT_64_BIT;

   } else if (result_location == CONTEXT_PTR) {

      buffer.outcnt = 1;      

      buffer.outptr[0] = CAST_TO_X_PTR((Uint8 *)out_length);
      buffer.outsize[0] = 8;
      buffer.outoffset[0] = 8;
      buffer.outunit[0] = UNIT_64_BIT;
   }
#endif

   buffer.group = CAVIUM_SSL_GRP;
   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;
    
   cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif


   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

   return ret_val;
}


/*+****************************************************************************
 *
 * Csp1Pkcs1v15CrtDec
 *
 * Decrypts PKCS#1v1.5 container using the Chinese Remainder Theorem.
 * The combination of block type 01 and CRT may produce unpredictable results.
 *
 * Input
 *      request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *   #ifdef MC2
 *      block_type = type of PKCS#1v1.5 padding (BT2 only)
 *      modlength = size of modulus in bytes
 *      Q = prime factor of RSA modulus
 *      Eq = exponent mod(Q-1)
 *      P = prime factor of RSA modulus
 *      Ep = exponent mod(P-1)
 *      iqmp = (Q^-1) mod P
 *      data = pointer to modlength-byte value to be exponentiated
 *   #else
 *      result_location = CONTEXT_PTR or RESULT_PTR 
 *      context_handle = 64-bit pointer to context (context_handle%8=0)
 *      key_material_input = KEY_HANDLE or INPUT_DATA
 *      key_handle = 64-bit handle for key memory 
 *      block_type = type of PKCS#1v1.5 padding (BT2 only)
 *      modlength = size of modulus in bytes (modlength%8=0, 24<modlength<=256)
 *      Q = (key_material_input == INPUT_DATA) ? prime factor of RSA modulus : don't care
 *      Eq = (key_material_input == INPUT_DATA) ? exponent mod(Q-1) : don't care
 *      P = (key_material_input == INPUT_DATA) ? prime factor of RSA modulus : don't care
 *      Ep = (key_material_input == INPUT_DATA) ? exponent mod(P-1) : don't care
 *      iqmp = (key_material_input == INPUT_DATA) ? (Q^-1) mod P : don't care
 *      data = pointer to modlength-byte value to be exponentiated
 *   #endif
 *
 * Output
 *   #ifdef MC2
 *      out_length = pointer to output length in bytes (Network Byte order)
 *      result = (pointer to modlength bytes of output,   *out_length bytes used)
 *   #else
 *      result = (result_location == RESULT_PTR) ? (pointer to modlength bytes of output, 
 *                     *out_length bytes used) : don't care
 *      out_length = pointer to output length in bytes
 *   #endif
 *      request_id = Unique ID for this request.
 *
 * Return Value
 *      0  = success 
 *      >0 = failure or pending
 *      see error_codes.txt
 *
 *-***************************************************************************/
#ifdef MC2
Uint32 
Csp1Pkcs1v15CrtDec(n1_request_type request_type,
               RsaBlockType block_type,
               Uint16 modlength, 
               Uint8 *Q, 
               Uint8 *Eq, 
               Uint8 *P, 
               Uint8 *Ep, 
               Uint8 *iqmp, 
               Uint8 *data,
               Uint16 *out_length,
               Uint8 *result,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

#else
Uint32 
Csp1Pkcs1v15CrtDec(n1_request_type request_type,
               ResultLocation result_location, 
               Uint64 context_handle, 
               KeyMaterialInput key_material_input,
               Uint64 key_handle, 
               RsaBlockType block_type,
               Uint16 modlength, 
               Uint8 *Q, 
               Uint8 *Eq, 
               Uint8 *P, 
               Uint8 *Ep, 
               Uint8 *iqmp, 
               Uint8 *data,
               Uint8 *result,
               Uint64 *out_length,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

#endif
{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;
#ifndef MC2
   Uint16 size = 0;
   Uint8 *p_Q = NULL, *p_Eq = NULL, *p_P = NULL, *p_Ep = NULL, *p_iqmp = NULL;
   Uint8 pkey[640];
   Uint64 tmp_key;
   Uint32 dummy=0;
#endif

   memset(&buffer,0,sizeof(Csp1OperationBuffer));

   buffer.group = CAVIUM_SSL_GRP;
#if defined(CSP1_API_DEBUG)
   if (result_location == CONTEXT_PTR) {

      if ((context_handle & UINT64_C(0x8000000000000000)) != 0) {

         if ((context_handle & 0xf) != 0)

            return ERR_ILLEGAL_CONTEXT_HANDLE;

      } else {

         if ((context_handle & 0x7) != 0)

            return ERR_ILLEGAL_CONTEXT_HANDLE;

      }
   }


   if (block_type == BT1) 

      return ERR_ILLEGAL_BLOCK_TYPE;

   if ((modlength & 0x7) != 0)

      return ERR_ILLEGAL_INPUT_LENGTH;

   if (!(key_handle & (((Uint64)0x10000) << 32)))

      return ERR_ILLEGAL_MOD_EX_TYPE;
#endif

#ifdef MC2
   buffer.ctx_ptr=0;
   buffer.dlen = (Uint16) ((2.5*modlength) + modlength);
   buffer.size = modlength;
   buffer.param = (block_type);
   buffer.rlen = 2 + modlength;

#else
   if (key_material_input == KEY_HANDLE) {

      if (key_handle & (((Uint64)0x20000) << 32)) {

         tmp_key = key_handle & UINT64_C(0x0000ffffffffffff);
         
#ifdef CAVIUM_MULTICARD_API
         if(Csp1ReadContext(CAVIUM_BLOCKING, tmp_key, (5*modlength/2), pkey, &dummy,dev_id))
#else
         if(Csp1ReadContext(CAVIUM_BLOCKING, tmp_key, (5*modlength/2), pkey, &dummy))
#endif
         
            return ERR_ILLEGAL_KEY_HANDLE;

         p_Q = &(pkey[0]);
         p_Eq = &(pkey[modlength/2]); 
         p_P = &(pkey[2*(modlength/2)]);
         p_Ep = &(pkey[3*(modlength/2)]); 
         p_iqmp = &(pkey[4*(modlength/2)]);

         buffer.param = (Uint16)0x4000;

      }

      else if (key_handle & 0x8000) {

         buffer.param = (Uint16)key_handle & 0xffff; 

      } else {

         buffer.param = ((Uint16)key_handle & 0x1ff8) >> 3;

      }
   
   } else if (key_material_input == INPUT_DATA) {

      buffer.param = (Uint16)0x4000;
      p_Q = Q;
      p_Eq = Eq; 
      p_P = P;
      p_Ep = Ep; 
      p_iqmp = iqmp;

   }
#endif
#ifdef MC2
   if ((modlength >= 34) && (modlength <= 128) && ((modlength & 0x1) == 0)) {
#else
   if ((modlength >= 48) && (modlength <= 128) && ((modlength & 0x1) == 0)) {
#endif
#ifdef MC2
      buffer.opcode = (0x2<<8) | (global_dma_mode<<7) | MAJOR_OP_ME_PKCS;
   } else if ((modlength > 128) && (modlength <= 512) && ((modlength & 0x1) == 0)) {
#else
      size = (CRT_MOD_EX << 7) + ((modlength>>3) - 1);
      buffer.opcode = (result_location<<12) | (block_type<<10) | (0x1<<8) 
         | (global_dma_mode<<7) | MAJOR_OP_ME_PKCS;
   } else if ((modlength > 128) && (modlength <= 256) && ((modlength & 0x1) == 0)) {
#endif

#ifdef MC2
      buffer.opcode = (0x2<<8) | (global_dma_mode<<7) | MAJOR_OP_ME_PKCS_LARGE;
#else
      size = (CRT_MOD_EX << 7) + ((modlength>>3) - 17);
      buffer.opcode = (result_location<<12) | (block_type<<10) | (0x1<<8) 
         | (global_dma_mode<<7) | MAJOR_OP_ME_PKCS_LARGE;
#endif

#if defined(CSP1_API_DEBUG)
   } else {

      return ERR_ILLEGAL_INPUT_LENGTH;
#endif
   }

#ifdef MC2

   buffer.incnt = 6;
   buffer.inptr[0] = CAST_TO_X_PTR(Q);
   buffer.insize[0] = modlength/2;
   buffer.inoffset[0] = modlength/2;
   buffer.inunit[0] = UNIT_8_BIT;
   buffer.inptr[1] = CAST_TO_X_PTR(Eq);
   buffer.insize[1] = modlength/2;
   buffer.inoffset[1] = modlength/2;
   buffer.inunit[1] = UNIT_8_BIT;
   buffer.inptr[2] = CAST_TO_X_PTR(P);
   buffer.insize[2] = modlength/2;
   buffer.inoffset[2] = modlength/2;
   buffer.inunit[2] = UNIT_8_BIT;
   buffer.inptr[3] = CAST_TO_X_PTR(Ep);
   buffer.insize[3] = modlength/2;
   buffer.inoffset[3] = modlength/2;
   buffer.inunit[3] = UNIT_8_BIT;
   buffer.inptr[4] =CAST_TO_X_PTR( iqmp);
   buffer.insize[4] = modlength/2;
   buffer.inoffset[4] = modlength/2;
   buffer.inunit[4] = UNIT_8_BIT;
   buffer.inptr[5] = CAST_TO_X_PTR(data);
   buffer.insize[5] = modlength;
   buffer.inoffset[5] = modlength;
   buffer.inunit[5] = UNIT_8_BIT;

   buffer.outcnt = 2;
   buffer.outptr[0] = CAST_TO_X_PTR((Uint8 *)out_length);
   buffer.outsize[0] = 2;
   buffer.outoffset[0] = 2;
   buffer.outunit[0] = UNIT_16_BIT;

   buffer.outptr[1] = CAST_TO_X_PTR(result);
   buffer.outsize[1] = modlength;
   buffer.outoffset[1] = modlength;
   buffer.outunit[1] = UNIT_8_BIT;

#else
   buffer.size = size;
   buffer.dlen = (modlength)>>3;
   buffer.rlen = (8 + 8)>>3;
   buffer.ctx_ptr = context_handle;

   if ((key_material_input == INPUT_DATA)
      ||
      (key_handle & (((Uint64)0x20000) << 32))) {

      buffer.dlen += ((5*modlength/2)>>3);

      buffer.incnt = 6;      

      buffer.inptr[0] = CAST_TO_X_PTR(data);
      buffer.insize[0] = modlength;
      buffer.inoffset[0] = modlength;
      buffer.inunit[0] = UNIT_8_BIT;
      buffer.inptr[1] = CAST_TO_X_PTR(p_Q);
      buffer.insize[1] = modlength/2;
      buffer.inoffset[1] = modlength/2;
      buffer.inunit[1] = UNIT_8_BIT;
      buffer.inptr[2] = CAST_TO_X_PTR(p_Eq);
      buffer.insize[2] = modlength/2;
      buffer.inoffset[2] = modlength/2;
      buffer.inunit[2] = UNIT_8_BIT;
      buffer.inptr[3] =CAST_TO_X_PTR( p_P);
      buffer.insize[3] = modlength/2;
      buffer.inoffset[3] = modlength/2;
      buffer.inunit[3] = UNIT_8_BIT;
      buffer.inptr[4] = CAST_TO_X_PTR(p_Ep);
      buffer.insize[4] = modlength/2;
      buffer.inoffset[4] = modlength/2;
      buffer.inunit[4] = UNIT_8_BIT;
      buffer.inptr[5] = CAST_TO_X_PTR(p_iqmp);
      buffer.insize[5] = modlength/2;
      buffer.inoffset[5] = modlength/2;
      buffer.inunit[5] = UNIT_8_BIT;

   } else {

      buffer.incnt = 1;      

      buffer.inptr[0] = CAST_TO_X_PTR(data);
      buffer.insize[0] = modlength;
      buffer.inoffset[0] = modlength;
      buffer.inunit[0] = UNIT_8_BIT;

   }

   if (result_location == RESULT_PTR) {

      buffer.rlen += (modlength>>3);

      buffer.outcnt = 2;      

      buffer.outptr[0] = CAST_TO_X_PTR(result);
      buffer.outsize[0] = modlength;
      buffer.outoffset[0] = modlength;
      buffer.outunit[0] = UNIT_8_BIT;
      buffer.outptr[1] = CAST_TO_X_PTR((Uint8 *)out_length);
      buffer.outsize[1] = 8;
      buffer.outoffset[1] = 8;
      buffer.outunit[1] = UNIT_64_BIT;

   } else if (result_location == CONTEXT_PTR) {

      buffer.outcnt = 1;      

      buffer.outptr[0] = CAST_TO_X_PTR((Uint8 *)out_length);
      buffer.outsize[0] = 8;
      buffer.outoffset[0] = 8;
      buffer.outunit[0] = UNIT_64_BIT;
   }
#endif


    buffer.req_queue = 0;
    buffer.req_type = request_type;
    buffer.res_order = CAVIUM_RESPONSE_ORDERED;
    buffer.dma_mode = global_dma_mode;
    buffer.status = 0;
    
    cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif


    *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

    return ret_val;
}


/*+****************************************************************************
 *
 * Csp1InitializeRc4
 *
 * Input
 *      request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *      context_handle = 64-bit pointer to context (context_handle%8=0)
 *      key_length = size of key in bytes (1<=length<=256)
 *      key = pointer to length-byte key 
 *
 * Output
 *      request_id = Unique ID for this request.
 *
 * Return Value
 *      0  = success 
 *      >0 = failure or pending
 *      see error_codes.txt
 *
 *-***************************************************************************/
Uint32 
Csp1InitializeRc4(n1_request_type request_type,
              Uint64 context_handle, 
              Uint16 key_length, 
              Uint8 *key,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;

   memset(&buffer,0,sizeof(Csp1OperationBuffer));
   if ((context_handle & UINT64_C(0x8000000000000000)) != 0) {

      if ((context_handle & 0xf) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   } else {

      if ((context_handle & 0x7) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   }

   if ((key_length < 1) || (key_length > 256))
      return ERR_ILLEGAL_KEY_LENGTH;

   buffer.group = CAVIUM_SSL_GRP;

#ifdef MC2
   buffer.opcode = (0x9<<8) | (global_dma_mode << 7) | MAJOR_OP_RANDOM_WRITE_CONTEXT;
   buffer.size = 0;
   buffer.dlen = key_length;
   buffer.rlen = 0;
#else
   buffer.opcode = (0x0<<8) | (global_dma_mode<<7) | MAJOR_OP_ENCRYPT_DECRYPT;
   buffer.size = key_length - 1;
   buffer.dlen = (ROUNDUP8(key_length))>>3;
   buffer.rlen = (8)>>3;
#endif
   buffer.param = 0;
   buffer.ctx_ptr = context_handle;

   buffer.incnt = 1;      
   buffer.outcnt = 0;      

   buffer.inptr[0] = CAST_TO_X_PTR(key);
   buffer.insize[0] = key_length;
   buffer.inoffset[0] = ROUNDUP8(key_length);
   buffer.inunit[0] = UNIT_8_BIT;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif


   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

   return ret_val;
}



/*+****************************************************************************
 *
 * Csp1EncryptRc4
 *
 * Input
 *      request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *      context_handle = 64-bit pointer to context (context_handle%8=0)
 *      context_update = UPDATE or NO_UPDATE
 *      length = size of input in bytes (0<=length<=2^16-1)
 *      input = pointer to length-byte input
 *
 * Output
 *      output = pointer to length-byte output 
 *      request_id = Unique ID for this request.
 *
 * Return Value
 *      0  = success 
 *      >0 = failure or pending
 *      see error_codes.txt
 *
 *-***************************************************************************/
Uint32 
Csp1EncryptRc4(n1_request_type request_type,
            Uint64 context_handle, 
            ContextUpdate context_update, 
            Uint16 length, 
            Uint8 *input, 
            Uint8 *output,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;

   memset(&buffer,0,sizeof(Csp1OperationBuffer));
   if ((context_handle & UINT64_C(0x8000000000000000)) != 0) {

      if ((context_handle & 0xf) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   } else {

      if ((context_handle & 0x7) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   }


#ifdef MC2
   buffer.opcode = (context_update<<13) | (global_dma_mode<<7) 
      | MAJOR_OP_ENCRYPT_DECRYPT;
   buffer.size = 0;
   buffer.param = 0;
   buffer.dlen = length;
   buffer.rlen = length;
#else
   buffer.opcode = (context_update<<13) | (0x2<<8) | (global_dma_mode<<7) 
      | MAJOR_OP_ENCRYPT_DECRYPT;
   buffer.size = length;
   buffer.param = 0;
   buffer.dlen = (ROUNDUP8(length))>>3;
   buffer.rlen = (ROUNDUP8(length) + 8)>>3;
#endif
   buffer.ctx_ptr = context_handle;
   buffer.group = CAVIUM_SSL_GRP;

   buffer.incnt = 1;      
   buffer.outcnt = 1;      

   buffer.inptr[0] = CAST_TO_X_PTR(input);
   buffer.insize[0] = length;
   buffer.inoffset[0] = ROUNDUP8(length);
   buffer.inunit[0] = UNIT_8_BIT;

   buffer.outptr[0] = CAST_TO_X_PTR(output);
   buffer.outsize[0] = length;
   buffer.outoffset[0] = (global_dma_mode == global_dma_mode) ? ROUNDUP8(length) : length;
   buffer.outunit[0] = UNIT_8_BIT;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;


   cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif


   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

   return ret_val;
}


/*+****************************************************************************
 *
 * Csp1Initialize3DES
 *
 * Input
 *      request_type = CAVIUM_BLOCKING
 *      context_handle = 64-bit pointer to context (context_handle%8=0)
 *      iv = pointer to 8-byte initialization vector
 *      key = pointer to 24-byte key 
 *
 * Return Value
 *      0  = success 
 *      >0 = failure or pending
 *      see error_codes.txt
 *
 *-***************************************************************************/
Uint32 
Csp1Initialize3DES(n1_request_type request_type,
               Uint64 context_handle, 
               Uint8 *iv, 
               Uint8 *key,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

{
#ifdef MC2
   return ERR_OPERATION_NOT_SUPPORTED;
#else
   Uint8 temp[32];
   Uint32 ret_val;
   Uint32 dummy=0;

   if(request_type == CAVIUM_NON_BLOCKING)
      return ERR_OPERATION_NOT_SUPPORTED;
   memcpy(temp, iv, 8);
   memcpy(temp + 8, key, 24);

#ifdef CAVIUM_MULTICARD_API
   ret_val = Csp1WriteContext(CAVIUM_BLOCKING, context_handle, 32, temp,&dummy,dev_id);
#else
   ret_val = Csp1WriteContext(CAVIUM_BLOCKING, context_handle, 32, temp,&dummy);
#endif

   return ret_val;
#endif /*MC2*/
}
             
             
             
/*+****************************************************************************
 *
 * Csp1Encrypt3Des
 *
 * Input
 *      request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *      context_handle = 64-bit pointer to context (context_handle%8=0)
 *      context_update = UPDATE or NO_UPDATE
 *      input = pointer to length-byte input
 *   #ifdef MC2
 *      iv = pointer to 8-byte IV
 *      key = pointer to 24-byte key
 *      length = size of input in bytes (0<=length<2^16-32, length%8=0)
 *   #else
 *      length = size of input in bytes (0<=length<=2^16-8, length%8=0)
 *   #endif
 *
 * Output
 *      output = pointer to ROUNDUP8(length)-byte output, 
 *      request_id = Unique ID for this request.
 *      
 *
 * Return Value
 *   0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
#ifdef MC2
Uint32 
Csp1Encrypt3Des(n1_request_type request_type,
            Uint64 context_handle, 
            ContextUpdate context_update, 
            Uint16 length, 
            Uint8 *input, 
            Uint8 *output,
            Uint8 *iv,
            Uint8 *key,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

#else
Uint32 
Csp1Encrypt3Des(n1_request_type request_type,
            Uint64 context_handle, 
            ContextUpdate context_update, 
            Uint16 length, 
            Uint8 *input, 
            Uint8 *output,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

#endif
{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;
#ifndef MC2
   Uint8 temp[8];
   Uint32 pad_len=0;
#endif

   memset(&buffer,0,sizeof(Csp1OperationBuffer));
   if ((context_handle & UINT64_C(0x8000000000000000)) != 0) {

      if ((context_handle & 0xf) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   } else {

      if ((context_handle & 0x7) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   }


#ifndef MC2 
   if ((length & 0x7) != 0){
      memset(temp,0x0,8);
      pad_len=8-(length & 0x7);
/*         return ERR_ILLEGAL_INPUT_LENGTH; */
   }
#else /* MC2 */
   if ((length >= 0xffe0) != 0) 
         return ERR_ILLEGAL_INPUT_LENGTH;
#endif


#ifdef MC2
   buffer.opcode = (context_update<<13) | (0x4<<8) | (global_dma_mode<<7) 
      | MAJOR_OP_ENCRYPT_DECRYPT;

   buffer.size = 0;
   buffer.param = 0;
   buffer.dlen = length + 32;
   buffer.rlen = ROUNDUP8(length);
#else
   buffer.opcode = (context_update<<13) | (0x4<<8) | (global_dma_mode<<7) 
      | MAJOR_OP_ENCRYPT_DECRYPT;

   buffer.size = (length+pad_len)>>3;
   buffer.param = 0;
   buffer.dlen = (length+pad_len)>>3;
   buffer.rlen = (length + pad_len+8)>>3;
#endif
   buffer.ctx_ptr = context_handle;
   buffer.group = CAVIUM_SSL_GRP;

#ifdef MC2
   buffer.incnt = 3;      
   buffer.outcnt = 1;      

   buffer.inptr[0] = CAST_TO_X_PTR(iv);
   buffer.insize[0] = 8;
   buffer.inoffset[0] = 8;
   buffer.inunit[0] = UNIT_8_BIT;
   buffer.inptr[1] = CAST_TO_X_PTR(key);
   buffer.insize[1] = 24;
   buffer.inoffset[1] = 24;
   buffer.inunit[1] = UNIT_8_BIT;
   buffer.inptr[2] = CAST_TO_X_PTR(input);
   buffer.insize[2] = length;
   buffer.inoffset[2] = length;
   buffer.inunit[2] = UNIT_8_BIT;
#else
   buffer.incnt = 2;      
   buffer.outcnt = 1;      

   buffer.inptr[0] = CAST_TO_X_PTR(input);
   buffer.insize[0] = length;
   buffer.inoffset[0] = length;
   buffer.inunit[0] = UNIT_8_BIT;
   buffer.inptr[1] = CAST_TO_X_PTR(temp);
   buffer.insize[1] = pad_len;
   buffer.inoffset[1] = pad_len;
   buffer.inunit[1] = UNIT_8_BIT;
#endif

   buffer.outptr[0] = CAST_TO_X_PTR(output);
#ifdef MC2
   buffer.outsize[0] = ROUNDUP8(length);
   buffer.outoffset[0] = ROUNDUP8(length);
#else
   buffer.outsize[0]   = ROUNDUP8(length);
   buffer.outoffset[0] = ROUNDUP8(length);
#endif
   buffer.outunit[0] = UNIT_8_BIT;
   
   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif


   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */


   return ret_val;
}



/*+****************************************************************************
 *
 * Csp1Decrypt3Des
 *
 * Input
 *      request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *      context_handle = 64-bit pointer to context (context_handle%8=0)
 *      context_update = UPDATE or NO_UPDATE
 *      length = size of input in bytes (length%8=0, 0<=length<=2^16-1)
 *      input = pointer to length-byte input
 *   #ifdef MC2
 *      iv = pointer to 8-byte IV
 *      key = pointer to 24-byte key
 *   #endif
 *
 * Output
 *      output = pointer to length-byte output, 
 *      request_id = Unique ID for this request.
 *
 * Return Value
 *   0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/
#ifdef MC2
Uint32 
Csp1Decrypt3Des(n1_request_type request_type,
            Uint64 context_handle, 
            ContextUpdate context_update, 
            Uint16 length, 
            Uint8 *input, 
            Uint8 *output,
            Uint8 *iv,
            Uint8 *key,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

#else
Uint32 
Csp1Decrypt3Des(n1_request_type request_type,
            Uint64 context_handle, 
            ContextUpdate context_update, 
            Uint16 length, 
            Uint8 *input, 
            Uint8 *output,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

#endif
{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;

   memset(&buffer,0,sizeof(Csp1OperationBuffer));
   if ((context_handle & UINT64_C(0x8000000000000000)) != 0) {

      if ((context_handle & 0xf) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   } else {

      if ((context_handle & 0x7) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   }

   buffer.group = CAVIUM_SSL_GRP;

   if ((length & 0x7) != 0)

      return ERR_ILLEGAL_INPUT_LENGTH;


#ifdef MC2
   buffer.opcode =  (0x5<<8) | (global_dma_mode<<7) | MAJOR_OP_ENCRYPT_DECRYPT;
   buffer.size = 0;
   buffer.param = 0;
   buffer.dlen = length + 32;
   buffer.rlen = length;
#else
   buffer.opcode = (context_update<<13) | (0x5<<8) | (global_dma_mode<<7) 
      | MAJOR_OP_ENCRYPT_DECRYPT;

   buffer.size = length>>3;
   buffer.param = 0;
   buffer.dlen = length>>3;
   buffer.rlen = (length + 8)>>3;
#endif
   buffer.ctx_ptr = context_handle;

#ifdef MC2
   buffer.incnt = 3;      
   buffer.outcnt = 1;      

   buffer.inptr[0] = CAST_TO_X_PTR(iv);
   buffer.insize[0] = 8;
   buffer.inoffset[0] = 8;
   buffer.inunit[0] = UNIT_8_BIT;
   buffer.inptr[1] = CAST_TO_X_PTR(key);
   buffer.insize[1] = 24;
   buffer.inoffset[1] = 24;
   buffer.inunit[1] = UNIT_8_BIT;
   buffer.inptr[2] = CAST_TO_X_PTR(input);
   buffer.insize[2] = length;
   buffer.inoffset[2] = length;
   buffer.inunit[2] = UNIT_8_BIT;
#else
   buffer.incnt = 1;      
   buffer.outcnt = 1;      

   buffer.inptr[0] = CAST_TO_X_PTR(input);
   buffer.insize[0] = length;
   buffer.inoffset[0] = length;
   buffer.inunit[0] = UNIT_8_BIT;
#endif

   buffer.outptr[0] = CAST_TO_X_PTR(output);
   buffer.outsize[0] = length;
   buffer.outoffset[0] = length;
   buffer.outunit[0] = UNIT_8_BIT;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif


   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */


    return ret_val;
}


/*+****************************************************************************
 *
 * Csp1InitializeAES
 *
 * Input
 *      request_type = CAVIUM_BLOCKING
 *      context_handle = 64-bit pointer to context (context_handle%8=0)
 *      aes_type = AES_128, AES_192, or AES_256
 *      iv = pointer to 16-byte initialization vector
 *      key = pointer to key, whose length depends on aes_type 
 *
 * Output
 *      request_id = Unique ID for this request. (ignored)
 * Return Value
 *      0  = success 
 *      >0 = failure or pending
 *      see error_codes.txt
 *
 *-***************************************************************************/
Uint32 
Csp1InitializeAES(n1_request_type request_type,
              Uint64 context_handle, 
              AesType aes_type, 
              Uint8 *iv, 
              Uint8 *key,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

{
#ifdef MC2
   return ERR_OPERATION_NOT_SUPPORTED;
#else
   Uint8 temp[48];
   Uint32 ret_val;
   Uint32 dummy=0;

   if(request_type == CAVIUM_NON_BLOCKING)
      return ERR_OPERATION_NOT_SUPPORTED;

   memcpy(temp, iv, 16);

   memcpy(temp + 16, key, 16 + 8 * aes_type);

#ifdef CAVIUM_MULTICARD_API
   ret_val = Csp1WriteContext(CAVIUM_BLOCKING,context_handle, (Uint16)(32 + 8 * aes_type), temp,&dummy,dev_id);
#else
   ret_val = Csp1WriteContext(CAVIUM_BLOCKING,context_handle, (Uint16)(32 + 8 * aes_type), temp,&dummy);
#endif

   return ret_val;
#endif /*MC2*/
}
             
             
/*+****************************************************************************
 *
 * Csp1EncryptAes
 *
 * Input
 *      request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *      context_handle = 64-bit pointer to context (context_handle%8=0)
 *      context_update = UPDATE or NO_UPDATE
 *      aes_type = AES_128, AES_192, or AES_256
 *      length = size of input in bytes (0<=length<=2^16-1)
 *      input = pointer to length-byte input
 *   #ifdef MC2
 *      iv = pointer to 16- byte IV
 *      key = pointer to key depending upon aes type
 *   #endif
 *
 * Output
 *      output = pointer to ROUNDUP16(length)-byte output
 *      request_id = Unique ID for this request.
 *
 * Return Value
 *      0  = success 
 *      >0 = failure or pending
 *      see error_codes.txt
 *
 *-***************************************************************************/
#ifdef MC2
Uint32 
Csp1EncryptAes(n1_request_type request_type,
            Uint64 context_handle, 
            ContextUpdate context_update, 
            AesType aes_type, 
            Uint16 length, 
            Uint8 *input, 
            Uint8 *output,
            Uint8 *iv,
            Uint8 *key,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

#else
Uint32 
Csp1EncryptAes(n1_request_type request_type,
            Uint64 context_handle, 
            ContextUpdate context_update, 
            AesType aes_type, 
            Uint16 length, 
            Uint8 *input, 
            Uint8 *output,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

#endif
{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;
#ifdef MC2
   Uint32 key_length;
#endif

   memset(&buffer,0,sizeof(Csp1OperationBuffer));
   if ((context_handle & UINT64_C(0x8000000000000000)) != 0) {

      if ((context_handle & 0xf) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   } else {

      if ((context_handle & 0x7) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   }


#ifndef MC2
   if ((length & 0xf) != 0) 
      return ERR_ILLEGAL_INPUT_LENGTH;
#endif

#ifdef MC2
   buffer.opcode = (0x6<<8) | (global_dma_mode<<7) | MAJOR_OP_ENCRYPT_DECRYPT;
   if (aes_type == AES_128) {
      buffer.size = 0x0005;
      key_length = 16;
   } else if (aes_type == AES_192) {
      buffer.size = 0x0006;
      key_length = 24;
   } else if (aes_type == AES_256) {
      buffer.size = 0x0007;
      key_length = 32;
   } else {
      buffer.size = 0x0000;
      key_length = 0;
   }
   buffer.param = 0;
   buffer.dlen = length + 16 + key_length;
   buffer.rlen = ROUNDUP16(length);
#else
   buffer.opcode = (context_update<<13) | ((aes_type + 1 )<<11) | (0x6<<8) 
      | (global_dma_mode<<7) | MAJOR_OP_ENCRYPT_DECRYPT;

   buffer.size = length>>4;
   buffer.param = 0;
   buffer.dlen = length>>3;
   buffer.rlen = (length + 8)>>3;
#endif
   buffer.ctx_ptr = context_handle;
   buffer.group = CAVIUM_SSL_GRP;

#ifdef MC2
   buffer.incnt = 3;      
   buffer.outcnt = 1;      

   buffer.inptr[0] = CAST_TO_X_PTR(iv);
   buffer.insize[0] = 16;
   buffer.inoffset[0] = 16;
   buffer.inunit[0] = UNIT_8_BIT;
   buffer.inptr[1] = CAST_TO_X_PTR(key);
   buffer.insize[1] = key_length;
   buffer.inoffset[1] = key_length;
   buffer.inunit[1] = UNIT_8_BIT;
   buffer.inptr[2] = CAST_TO_X_PTR(input);
   buffer.insize[2] = length;
   buffer.inoffset[2] = length;
   buffer.inunit[2] = UNIT_8_BIT;
#else
   buffer.incnt = 1;      
   buffer.outcnt = 1;      

   buffer.inptr[0] = CAST_TO_X_PTR(input);
   buffer.insize[0] = length;
   buffer.inoffset[0] = length;
   buffer.inunit[0] = UNIT_8_BIT;
#endif

   buffer.outptr[0] = CAST_TO_X_PTR(output);
   buffer.outsize[0] = length;
   buffer.outoffset[0] = length;
   buffer.outunit[0] = UNIT_8_BIT;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif


   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

   return ret_val;
}

#ifdef MC2
/*+****************************************************************************
 *
 * Csp1EncryptAesGcmGmac
 *
 * Input
 *      request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *      context_handle = 64-bit pointer to context (context_handle%8=0)
 *      context_update = UPDATE or NO_UPDATE
 *      aes_type     = AES_128, AES_192, or AES_256
 *      length       = size of input in bytes (0<=length<=2^16-1)
 *      input        = pointer to length-byte input
 *      aad          = pointer to key depending upon the AAD Length
 *   #ifdef MC2
 *      iv           = pointer to 16- byte IV
 *      key          = pointer to key depending upon aes type
 *   #endif
 *
 * Output
 *      output       = pointer to length+tag_length(16B) output
 *      request_id   = Unique ID for this request.
 *
 * Return Value
 *      0            = success 
 *      >0           = failure or pending
 *      see error_codes.txt
 *
 *-***************************************************************************/
Uint32 
Csp1EncryptAesGcmGmac(n1_request_type request_type,
            Uint64 context_handle, 
            ContextUpdate context_update, 
            AesType aes_type, 
            Uint16 length, 
            Uint8 *input, 
            Uint8 *aad,
            Uint8 eseqnumber,
            Uint8 *output,
            Uint8 gcm_gmac_bit,
            Uint8 *iv,
            Uint8 *key,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

{
   Csp1OperationBuffer buffer;
   Uint32 cond_code=0;
   Uint32 ret_val=0;
   Uint16 param2 = 0;
   Uint16 aad_len=0; 
   Uint32 key_length=0;
   Uint32 iv_length=0;

   memset(&buffer,0,sizeof(Csp1OperationBuffer));
   if ((context_handle & UINT64_C(0x8000000000000000)) != 0) {

      if ((context_handle & 0xf) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   } else {

      if ((context_handle & 0x7) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   }

   buffer.group = CAVIUM_SSL_GRP;

   buffer.opcode = (0x8<<8) | (global_dma_mode<<7) | MAJOR_OP_ENCRYPT_DECRYPT;
   if (gcm_gmac_bit) 
      param2 |= 1; //gmac bit
   else 
      param2 |= 0;
   iv_length = 12;
   buffer.param |= (param2<<15);    //GCM/GMAC bit
   param2 = 0;
   if (aes_type == AES_128) {
      param2 = (1<<1);
      key_length = 16;
   } else if (aes_type == AES_192) {
      param2 = (2<<1);
      key_length = 24;
   } else if (aes_type == AES_256) {
      param2 = (3<<1);
      key_length = 32;
   } else {
      buffer.size = 0x0000;
      key_length = 0;
   }
   buffer.param |= param2;
   param2 = 0;
   if(eseqnumber) {
     param2 = 1;
     aad_len = 12;
   }
   else { 
     param2 = 0;
     aad_len = 8; 
   }
   buffer.param |= param2;
   buffer.size = length;
   if(!gcm_gmac_bit) {
   buffer.dlen = buffer.size + key_length + 16/*nonce*/ + ROUNDUP8(aad_len);
   buffer.rlen = length + 16;	/*length+tag_length(always tag length is 16B)*/
   }
   else {
   buffer.dlen = buffer.size + key_length +16 /*nonce*/;
   buffer.rlen = 16; /*tag_length*/
   }
   buffer.ctx_ptr = context_handle;

   buffer.incnt = 4;       
   buffer.outcnt = 1;      

   buffer.inptr[0] = CAST_TO_X_PTR(iv);
   buffer.insize[0] = 16;
   buffer.inoffset[0] = 16;
   buffer.inunit[0] = UNIT_8_BIT;
   buffer.inptr[1] = CAST_TO_X_PTR(key);
   buffer.insize[1] = key_length;
   buffer.inoffset[1] = key_length;
   buffer.inunit[1] = UNIT_8_BIT;
   buffer.inptr[2] = CAST_TO_X_PTR(aad);
   if(!gcm_gmac_bit) {
   buffer.insize[2] = ROUNDUP8(aad_len);
   buffer.inoffset[2] = ROUNDUP8(aad_len);
   } else {
   buffer.insize[2] = length;
   buffer.inoffset[2] = length;
   }   
   buffer.inunit[2] = UNIT_8_BIT;
   buffer.inptr[3] = CAST_TO_X_PTR(input);
   if(!gcm_gmac_bit) {
   buffer.insize[3] = length;
   buffer.inoffset[3] = length;
   } else {
   buffer.insize[3] = 0;
   buffer.inoffset[3] = 0;
   }
   buffer.inunit[3] = UNIT_8_BIT;

   buffer.outptr[0] = CAST_TO_X_PTR(output);
   if(!gcm_gmac_bit) {
   buffer.outsize[0] = length + 16;
   buffer.outoffset[0] = length + 16;
   } else {
   buffer.outsize[0] = 16;
   buffer.outoffset[0] = 16;
   }
   buffer.outunit[0] = UNIT_8_BIT;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif

   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

   return ret_val;
}
#endif


             
#ifdef MC2
             
             
/*+****************************************************************************
 *
 * Csp1SrtpAesCtr
 *
 * Input
 *      request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *      context_handle = 64-bit pointer to context (context_handle%8=0)
 *      context_update = UPDATE or NO_UPDATE
 *      aes_type = AES_128  (is it only for AES_128) 
 *      length = size of input in bytes (0<=length<=2^16-1)
 *      input = pointer to length-byte input
 *   #ifdef MC2
 *      iv = pointer to 16- byte IV
 *      key = pointer to key depending upon aes type
 *   #endif
 *
 * Output
 *      output = pointer to ROUNDUP16(length)-byte output
 *      request_id = Unique ID for this request.
 *
 * Return Value
 *      0  = success 
 *      >0 = failure or pending
 *      see error_codes.txt
 *
 *-***************************************************************************/
Uint32 
Csp1SrtpAesCtr(n1_request_type request_type,
            Uint64 context_handle, 
            ContextUpdate context_update, 
            AesType aes_type, 
            Uint16 length, 
            Uint8 *input, 
            Uint8 *output,
            Uint8 *iv,
            Uint8 *key,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )
{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;
   Uint32 key_length;
   memset(&buffer,0,sizeof(Csp1OperationBuffer));
   if ((context_handle & UINT64_C(0x8000000000000000)) != 0) {

      if ((context_handle & 0xf) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   } else {

      if ((context_handle & 0x7) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   }

   buffer.group = CAVIUM_SSL_GRP;

   if (aes_type == AES_128) {
      key_length = 16;
   } 
   else if (aes_type == AES_192) {
      key_length = 24;
   } 
   else if (aes_type == AES_256) {
      key_length = 32;
   } 
   else {
      key_length = 0;
   }
     buffer.size = length;
        buffer.opcode = 0x0018 | (global_dma_mode<<7);
    	buffer.param = ((key_length - 16)/8);
   	buffer.dlen = length +  key_length  + 16; //length + key_length + iv_length;
   	buffer.rlen = length; 
   buffer.ctx_ptr = context_handle;

#ifdef MC2
   	buffer.incnt = 3;      
   	buffer.outcnt = 1;      

   	buffer.inptr[0] = CAST_TO_X_PTR(iv);
   	buffer.insize[0] = 16;
   	buffer.inoffset[0] = 16;
   	buffer.inunit[0] = UNIT_8_BIT;

   	buffer.inptr[1] = CAST_TO_X_PTR(key);
   	buffer.insize[1] = key_length;
   	buffer.inoffset[1] = key_length;
   	buffer.inunit[1] = UNIT_8_BIT;

   	buffer.inptr[2] = CAST_TO_X_PTR(input);
   	buffer.insize[2] = length;
   	buffer.inoffset[2] = length;
   	buffer.inunit[2] = UNIT_8_BIT;

#endif

   buffer.outptr[0] = CAST_TO_X_PTR(output);
   buffer.outsize[0] = length;
   buffer.outoffset[0] = length;
   buffer.outunit[0] = UNIT_8_BIT;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;
   cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif

   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

   return ret_val;
}

#endif

#ifdef MC2
/*+****************************************************************************
 * Csp1ProcessSrtp
 * input
 *      request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *      encrypt      = 0 - encrypt, 1 -decrypt
 *      keytype      = AES_128, AES_192, or AES_256
 *      authtype     = NULL or SHA1 
 *      proto        = 0 - SRTP, 1 - SRTCP
 *      length       = size of input in bytes (0<=length<=2^16-1)
 *      hdr_ln       = size of the hdr in bytes (0 <= hdr_ln <= 72)
 *      index_ln     = size of the Tag len[7:4] and Index len [3:0] in bytes (0 <= index_ln <= 4)
 *      iv           = pointer to 16- byte IV
 *      key          = pointer to key depending upon aes type
 *      auth_key     = pointer to auth_key depending upon auth type
 *      index        = pointer to index depending upon index_ln
 *      auth_tag     = pointer to auth_tag depending upon auth type & encrypt
 *      input        = pointer to ROUNDUP8(length) + ROUNDUP8(hdr_ln) bytes input
 *
 * Output
 *      output       = pointer to length + ((proto) ? Index_ln : 0) + auth_tag[(auth_type&!encrypt)? Tag len : 0] output
 *      request_id   = Unique ID for this request.
 *
 * Return Value
 *   0  = success 
 *   >0 = failure or pending
 *
 *-***************************************************************************/
Uint32
Csp1ProcessSrtp(n1_request_type request_type,
                Uint8 encrypt,
                Uint8 keytype,
                Uint8 authtype,
                Uint8 proto, 
                Uint16 length,
                Uint8 hdr_ln,
                Uint8 index_ln,
                Uint8 *iv,
                Uint8 *key,
                Uint8 *auth_key,
                Uint8 *index,
                Uint8 *auth_tag,
                Uint8 *input,
                Uint8 *output,
#ifdef CAVIUM_MULTICARD_API
                Uint32 *request_id,Uint32 dev_id
#else
                Uint32 *request_id
#endif
                )
{

   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;
   Uint8 minor_op;
   Uint8 key_length;

   memset(&buffer,0,sizeof(Csp1OperationBuffer));

   buffer.group = CAVIUM_SSL_GRP;

   minor_op = encrypt;
   minor_op |= ((keytype&0x3) << 1);
   minor_op |= ((authtype&0x7) << 3);
   minor_op |= ((proto&0x1) << 6);
   key_length = ((keytype + 2) << 3);

   buffer.opcode = 0x0018 | (global_dma_mode<<7);
   buffer.opcode |= ((minor_op&0xff) << 8);
   buffer.size = length;
   buffer.param =  hdr_ln;
   buffer.param |=  (index_ln << 8);
   buffer.dlen = 16/*iv*/ + key_length + ((authtype) ? 24 : 0)/*authkey*/ + ROUNDUP8(hdr_ln) + ROUNDUP8(length) 
                 + ROUNDUP8(index_ln & 0xF);

   if ((encrypt) && (authtype == 1))
      buffer.dlen += ((index_ln >> 4) & 0xF); /* auth tag length */

#if 0
   buffer.rlen = ROUNDUP8(hdr_ln) + length + ((proto) ? (index_ln & 0xF): 0);
#else
   buffer.rlen =  length + ((proto) ? (index_ln & 0xF): 0);
#endif

   if ((!encrypt) && (authtype == 1))
      buffer.rlen += ((index_ln >> 4) & 0xF); /* auth tag length */

   buffer.incnt = 6;      
   buffer.outcnt = 1;      

   buffer.inptr[0] = CAST_TO_X_PTR(iv);
   buffer.insize[0] = 16;
   buffer.inoffset[0] = 16;
   buffer.inunit[0] = UNIT_8_BIT;

   buffer.inptr[1] = CAST_TO_X_PTR(key);
   buffer.insize[1] = key_length;
   buffer.inoffset[1] = key_length;
   buffer.inunit[1] = UNIT_8_BIT;

   buffer.inptr[2] = CAST_TO_X_PTR(auth_key);
   buffer.insize[2] = (authtype) ? 24 :0;
   buffer.inoffset[2] = (authtype) ? 24 :0;
   buffer.inunit[2] = UNIT_8_BIT;

   buffer.inptr[3] = CAST_TO_X_PTR(index);
   buffer.insize[3] = ROUNDUP8(index_ln & 0xF);
   buffer.inoffset[3] = ROUNDUP8(index_ln & 0xF);
   buffer.inunit[3] = UNIT_8_BIT;

   buffer.inptr[4] = CAST_TO_X_PTR(input);
   buffer.insize[4] = ROUNDUP8(length) + ROUNDUP8(hdr_ln);
   buffer.inoffset[4] = ROUNDUP8(length) + ROUNDUP8(hdr_ln);
   buffer.inunit[4] = UNIT_8_BIT;

   buffer.inptr[5] = CAST_TO_X_PTR(auth_tag);
   buffer.insize[5] = (authtype & encrypt) ? ((index_ln >> 4) & 0xF) :0;
   buffer.inoffset[5] = (authtype & encrypt) ? ((index_ln >> 4) & 0xF) :0;
   buffer.inunit[5] = UNIT_8_BIT;

   buffer.outptr[0] = CAST_TO_X_PTR(output);
   buffer.outsize[0] = buffer.rlen;
   buffer.outoffset[0] = buffer.rlen;
   buffer.outunit[0] = UNIT_8_BIT;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;
   cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif

   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

   return ret_val;
}
#endif

#ifdef MC2
/*+****************************************************************************
 *
 * Csp1AesXcbcPrf128 
 *
 * Input
 *      request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	key = pointer to key
 * 	key_length = size of the key ( 1 <= key_length <= 912)
 *	data = pointer to input data
 * 	data_length = size of input data
 *
 * Output
 *      output = pointer to (AESXCBC_BLOCK_SIZE)-byte output
 *      request_id = Unique ID for this request.
 *
 *
 * Return Value
 *      0  = success 
 *      >0 = failure or pending
 *      see error_codes.txt
 *
 *-***************************************************************************/
Uint32 
Csp1AesXcbcPrf128(n1_request_type request_type,
	Uint8 *key,
	Uint16 key_length, 
	Uint8 *data, 
	Uint16 data_length,
	Uint8 *output,
#ifdef CAVIUM_MULTICARD_API
	Uint32 *request_id,Uint32 dev_id
#else
	Uint32 *request_id
#endif
)

{
	Csp1OperationBuffer buffer;
	Uint32 cond_code;
	Uint32 ret_val;
	memset(&buffer,0,sizeof(Csp1OperationBuffer));

	buffer.opcode = 0x0807 | (global_dma_mode<<7);
	buffer.param = 0;
	buffer.size = key_length;
	buffer.dlen = ROUNDUP16(key_length) + data_length;
	buffer.rlen = AESXCBC_BLOCK_SIZE;

   	buffer.incnt = 2;      
   	buffer.outcnt = 1;      

    buffer.group = CAVIUM_SSL_GRP;

   	buffer.inptr[0] = CAST_TO_X_PTR(key);
   	buffer.insize[0] = ROUNDUP16(key_length);
   	buffer.inoffset[0] = ROUNDUP16(key_length);
   	buffer.inunit[0] = UNIT_8_BIT;

   	buffer.inptr[1] = CAST_TO_X_PTR(data);
   	buffer.insize[1] = data_length;
   	buffer.inoffset[1] = data_length;
   	buffer.inunit[1] = UNIT_8_BIT;


	buffer.outptr[0] = CAST_TO_X_PTR(output);
	buffer.outsize[0] = AESXCBC_BLOCK_SIZE;
	buffer.outoffset[0] = AESXCBC_BLOCK_SIZE;
	buffer.outunit[0] = UNIT_8_BIT;

	buffer.req_queue = 0;
	buffer.req_type = request_type;
	buffer.res_order = CAVIUM_RESPONSE_ORDERED;
	buffer.dma_mode = global_dma_mode;
	buffer.status = 0;
	cond_code = 
#ifdef CAVIUM_MULTICARD_API
	 ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
	 ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif

	*request_id = buffer.request_id;
	if(cond_code)
	 ret_val = cond_code; /*return error val*/
	else
	 ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

	return ret_val;
}
#endif

#ifdef MC2
/*+****************************************************************************
 *
 * Csp1AesCfbRfc3826
 *
 * Input
 *      request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *	key = pointer to key
 *      aes_type = AES_128, AES_192, AES_256
 * 	iv = pointer to iv
 *	data = pointer to input data
 * 	data_length = size of input data
 * 	encrypt =  0:1 (decrypt:encrypt) 
 *
 * Output
 *      output = pointer to (AESXCBC_BLOCK_SIZE)-byte output
 *      request_id = Unique ID for this request.
 *
 *
 * Return Value
 *      0  = success 
 *      >0 = failure or pending
 *      see error_codes.txt
 *
 *-***************************************************************************/
Uint32 
Csp1AesCfbRfc3826(n1_request_type request_type,
	Uint8 *key,
        AesType aes_type, 
	Uint8 *iv,
	Uint8 *data, 
	Uint16 data_length,
	Uint8 *output,
	Uint8 encrypt, /* 0:1 (decrypt:encrypt) */
#ifdef CAVIUM_MULTICARD_API
	Uint32 *request_id,Uint32 dev_id
#else
	Uint32 *request_id
#endif
)

{
	Csp1OperationBuffer buffer;
	Uint32 cond_code;
	Uint32 ret_val;
   	Uint32 key_length;
	memset(&buffer,0,sizeof(Csp1OperationBuffer));

	if(encrypt)
         buffer.opcode = (0x6<<8) | (global_dma_mode<<7) | MAJOR_OP_ENCRYPT_DECRYPT;
	else
         buffer.opcode = (0x7<<8) | (global_dma_mode<<7) | MAJOR_OP_ENCRYPT_DECRYPT;

   	if (aes_type == AES_128) {
         buffer.size = 0x0005;
         key_length = 16;
   	} else if (aes_type == AES_192) {
         buffer.size = 0x0006;
         key_length = 24;
   	} else if (aes_type == AES_256) {
         buffer.size = 0x0007;
         key_length = 32;
   	} else {
         buffer.size = 0x0000;
         key_length = 0;
   	}
	buffer.param = (1 << 15); /*15th bit for AES_CFB*/ 
	buffer.dlen = key_length + 16 /* iv */ + data_length;
	buffer.rlen = data_length;

   	buffer.incnt = 3;      
   	buffer.outcnt = 1;      

   buffer.group = CAVIUM_SSL_GRP;

   	buffer.inptr[0] = CAST_TO_X_PTR(iv);
   	buffer.insize[0] = 16;
   	buffer.inoffset[0] = 16;
   	buffer.inunit[0] = UNIT_8_BIT;

   	buffer.inptr[1] = CAST_TO_X_PTR(key);
   	buffer.insize[1] = key_length;
   	buffer.inoffset[1] = key_length;
   	buffer.inunit[1] = UNIT_8_BIT;

   	buffer.inptr[2] = CAST_TO_X_PTR(data);
   	buffer.insize[2] = data_length;
   	buffer.inoffset[2] = data_length;
   	buffer.inunit[2] = UNIT_8_BIT;


	buffer.outptr[0] = CAST_TO_X_PTR(output);
	buffer.outsize[0] = data_length;
	buffer.outoffset[0] = data_length;
	buffer.outunit[0] = UNIT_8_BIT;

	buffer.req_queue = 0;
	buffer.req_type = request_type;
	buffer.res_order = CAVIUM_RESPONSE_ORDERED;
	buffer.dma_mode = global_dma_mode;
	buffer.status = 0;
	cond_code = 
#ifdef CAVIUM_MULTICARD_API
	 ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
	 ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif

	*request_id = buffer.request_id;
	if(cond_code)
	 ret_val = cond_code; /*return error val*/
	else
	 ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

	return ret_val;
}
#endif
/*+****************************************************************************
 *
 * Csp1DecryptAes
 *
 * Input
 *      request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *      context_handle = 64-bit pointer to context (context_handle%8=0)
 *      context_update = UPDATE or NO_UPDATE
 *      aes_type = AES_128, AES_192, or AES_256
 *      length = size of input in bytes (length%16=0, 0<=length<=2^16-1)
 *      input = pointer to length-byte input
 *   #ifdef MC2
 *      iv = pointer to 16- byte IV
 *      key = pointer to key depending upon aes type
 *   #endif
 *
 * Output
 *      output = pointer to length-byte output
 *      request_id = Unique ID for this request.
 *
 * Return Value
 *   0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/

#ifdef MC2
Uint32 
Csp1DecryptAes(n1_request_type request_type,
            Uint64 context_handle, 
            ContextUpdate context_update, 
            AesType aes_type, 
            Uint16 length, 
            Uint8 *input, 
            Uint8 *output,
            Uint8 *iv,
            Uint8 *key,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

#else
Uint32 
Csp1DecryptAes(n1_request_type request_type,
            Uint64 context_handle, 
            ContextUpdate context_update, 
            AesType aes_type, 
            Uint16 length, 
            Uint8 *input, 
            Uint8 *output,
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

#endif
{
   Csp1OperationBuffer buffer;
   Uint32 cond_code;
   Uint32 ret_val;
#ifdef MC2
   Uint32 key_length;
#endif

   memset(&buffer,0,sizeof(Csp1OperationBuffer));
   if ((context_handle & UINT64_C(0x8000000000000000)) != 0) {

      if ((context_handle & 0xf) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   } else {

      if ((context_handle & 0x7) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   }

   if ((length & 0xf) != 0)

      return ERR_ILLEGAL_INPUT_LENGTH;

   buffer.group = CAVIUM_SSL_GRP;

#ifdef MC2
   buffer.opcode = (0x7<<8) | (global_dma_mode<<7) | MAJOR_OP_ENCRYPT_DECRYPT;
   if (aes_type == AES_128) {
      buffer.size = 0x0005;
      key_length = 16;
   } else if (aes_type == AES_192) {
      buffer.size = 0x0006;
      key_length = 24;
   } else if (aes_type == AES_256) {
      buffer.size = 0x0007;
      key_length = 32;
   } else {
      buffer.size = 0x0000;
      key_length = 0;
   }
   buffer.param = 0;
   buffer.dlen = length + 16 + key_length;
   buffer.rlen = length;
#else
   buffer.opcode = (context_update<<13) | ((aes_type + 1 )<<11) | (0x7<<8) 
      | (global_dma_mode<<7) | MAJOR_OP_ENCRYPT_DECRYPT;

   buffer.size = length>>4;
   buffer.param = 0;
   buffer.dlen = length>>3;
   buffer.rlen = (length + 8)>>3;
#endif
   buffer.ctx_ptr = context_handle;

#ifdef MC2
   buffer.incnt = 3;      
   buffer.outcnt = 1;      

   buffer.inptr[0] = CAST_TO_X_PTR(iv);
   buffer.insize[0] = 16;
   buffer.inoffset[0] = 16;
   buffer.inunit[0] = UNIT_8_BIT;
   buffer.inptr[1] = CAST_TO_X_PTR(key);
   buffer.insize[1] = key_length;
   buffer.inoffset[1] = key_length;
   buffer.inunit[1] = UNIT_8_BIT;
   buffer.inptr[2] = CAST_TO_X_PTR(input);
   buffer.insize[2] = length;
   buffer.inoffset[2] = length;
   buffer.inunit[2] = UNIT_8_BIT;
#else
   buffer.incnt = 1;      
   buffer.outcnt = 1;      

   buffer.inptr[0] = CAST_TO_X_PTR(input);
   buffer.insize[0] = length;
   buffer.inoffset[0] = length;
   buffer.inunit[0] = UNIT_8_BIT;
#endif

   buffer.outptr[0] = CAST_TO_X_PTR(output);
   buffer.outsize[0] = length;
   buffer.outoffset[0] = length;
   buffer.outunit[0] = UNIT_8_BIT;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif


   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

   return ret_val;
}

#ifdef MC2
/*+****************************************************************************
 *
 * Csp1DecryptAesGcm
 *
 * Input
 *      request_type = CAVIUM_BLOCKING or CAVIUM_NON_BLOCKING
 *      context_handle = 64-bit pointer to context (context_handle%8=0)
 *      context_update = UPDATE or NO_UPDATE
 *      aes_type     = AES_128, AES_192, or AES_256
 *      length       = size of input in bytes (length%16=0, 0<=length<=2^16-1)
 *      input        = pointer to length-byte input in case of GCM
 *      eseqnum      = extented sequence number bit
 *      tag_length   = can be 4, 8. 12 and 16B
 *      aad          = pointer to AAD data incase of GCM, 
 *                     pointer to length-byte AAD in GMAC
 *      output       = pointer to length-byte output in GCM, 
 *                     pointer to 0B output in case of GMAC. 
 *      gcm_gmac_bit = set if GMAC, otherwise GCM
 *      iv = pointer to 16- byte IV
 *      key = pointer to key depending upon aes type
 *
 * Output
 *      output = pointer to length-byte output
 *      request_id = Unique ID for this request.
 *
 * Return Value
 *   0  = success 
 * >0 = failure or pending
 * see error_codes.txt
 *
 *-***************************************************************************/

Uint32 
Csp1DecryptAesGcm(n1_request_type request_type,
            Uint64 context_handle, 
            ContextUpdate context_update, 
            AesType aes_type, 
            Uint16 length, 
            Uint8 *input, 
            Uint8 eseqnumber,           
            Uint16 tag_length,
            Uint8 *aad,
            Uint8 *output,
            Uint8 gcm_gmac_bit,
            Uint8 *iv,
            Uint8 *key,
                 
#ifdef CAVIUM_MULTICARD_API
            Uint32 *request_id,Uint32 dev_id
#else
            Uint32 *request_id
#endif
           )

{
   Csp1OperationBuffer buffer;
   Uint32 cond_code=0;
   Uint32 ret_val=0;
   Uint16 param2=0;
   Uint16 aad_len=0; 
   Uint32 key_length=0;
   Uint32 iv_length=0;

   memset(&buffer,0,sizeof(Csp1OperationBuffer));
   if ((context_handle & UINT64_C(0x8000000000000000)) != 0) {

      if ((context_handle & 0xf) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   } else {

      if ((context_handle & 0x7) != 0)

         return ERR_ILLEGAL_CONTEXT_HANDLE;

   }

   buffer.group = CAVIUM_SSL_GRP;

   buffer.opcode = (0x9<<8) | (global_dma_mode<<7) | MAJOR_OP_ENCRYPT_DECRYPT;
   iv_length = 12;	
   if (gcm_gmac_bit) 
      param2 |= 1; //gmac bit
   else 
      param2 |= 0;
   buffer.param |= (param2<<15);    //GCM/GMAC bit
   param2 = 0;
   if(tag_length == 16)  
      param2 =  (0x3<<3);
   else if(tag_length == 12) 
      param2 =  (0x2<<3);
   else if(tag_length == 8) 
      param2 =  (0x1<<3);
   else /*tag_length == 4*/
      param2 = (0x0<<3);
   
   buffer.param = buffer.param | param2;
   param2 = 0;
   if (aes_type == AES_128) {
      param2 = (1<<1);
      key_length = 16;
   } else if (aes_type == AES_192) {
      param2 = (2<<1);
      key_length = 24;
   } else if (aes_type == AES_256) {
      param2 = (3<<1);
      key_length = 32;
   } else {
      param2 = 0;
      key_length = 0;
   }
   buffer.param |= param2;
   param2 = 0;
   if(eseqnumber) {
     param2 = 1;
     aad_len = 12;
   }
   else { 
     param2 = 0;
     aad_len = 8; 
   }
   buffer.param |= param2;
   buffer.size = length;
   if(!gcm_gmac_bit) {
   buffer.dlen = buffer.size + key_length + 16/*nonce*/ + 
                 ROUNDUP8(aad_len) + tag_length;
   buffer.rlen = length;	
   } else {
   buffer.dlen = buffer.size + key_length + 16/*nonce*/ + tag_length;
   buffer.rlen = 0;	
   }
   
   buffer.ctx_ptr = context_handle;

   buffer.incnt = 4;      
   buffer.outcnt = 1;      

   buffer.inptr[0] = CAST_TO_X_PTR(iv);
   buffer.insize[0] = 16;
   buffer.inoffset[0] = 16;
   buffer.inunit[0] = UNIT_8_BIT;
   buffer.inptr[1] = CAST_TO_X_PTR(key);
   buffer.insize[1] = key_length;
   buffer.inoffset[1] = key_length;
   buffer.inunit[1] = UNIT_8_BIT;
   buffer.inptr[2] = CAST_TO_X_PTR(aad);
   if(!gcm_gmac_bit) {
   buffer.insize[2] = ROUNDUP8(aad_len);
   buffer.inoffset[2] = ROUNDUP8(aad_len);
   } else {
   buffer.insize[2] = length + 16;
   buffer.inoffset[2] = length + 16;
   }
   buffer.inunit[2] = UNIT_8_BIT;
   buffer.inptr[3] = CAST_TO_X_PTR(input);
   if(!gcm_gmac_bit) {
   buffer.insize[3] = length+16;
   buffer.inoffset[3] = length+16;
   } else {
   buffer.insize[3] = 0;
   buffer.inoffset[3] = 0;
   }
   buffer.inunit[3] = UNIT_8_BIT;

   buffer.outptr[0] = CAST_TO_X_PTR(output);
   if(!gcm_gmac_bit) {
   buffer.outsize[0] = length;
   buffer.outoffset[0] = length;
   } else {
   buffer.outsize[0] = 0;
   buffer.outoffset[0] = 0;
   }
   buffer.outunit[0] = UNIT_8_BIT;

   buffer.req_queue = 0;
   buffer.req_type = request_type;
   buffer.res_order = CAVIUM_RESPONSE_ORDERED;
   buffer.dma_mode = global_dma_mode;
   buffer.status = 0;

   cond_code = 
#ifdef CAVIUM_MULTICARD_API
     ioctl(gpkpdev_hdlr[dev_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#else
     ioctl(CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&buffer);
#endif


   *request_id = buffer.request_id;
   if(cond_code)
     ret_val = cond_code; /*return error val*/
   else
     ret_val = buffer.status;/*return OPERATION STATUS: SUCCESS('0')/EAGAIN */

   return ret_val;
}
#endif

/*****************************************************************************
 *
 * Csp1GetAllResults
 *
 * Returns the status of all requests sent by the current process
 *
 * Input
 *  req_stat_buf = array of Csp1RequestStatusBuffer structures
 *  buf_size = size of req_stat_buf in multiple of Csp1RequestStatusBuffer size.
 *                           (buf_size % sizeof(Csp1RequestStatusBuffer) = 0)
 *
 * Output
 *      res_count = number of elements returned in req_stat_buf.
 *
 * Return Value
 *      completion code = 0 (for success), ERR_BAD_IOCTL
 *
 ****************************************************************************/
Uint32
Csp1GetAllResults(Csp1RequestStatusBuffer *req_stat_buf,
                                  Uint32 buf_size,
                                  Uint32 *res_count
#ifdef CAVIUM_MULTICARD_API
                                  ,Uint32 device_id
#endif
                                  )
{
     Uint32 ret_code = 0;
     Csp1StatusOperationBuffer buffer;

   memset(&buffer,0,sizeof(Csp1StatusOperationBuffer));
     if ((buf_size == 0) ||
                (buf_size%sizeof(Csp1RequestStatusBuffer)))
                return ERR_ILLEGAL_INPUT_LENGTH;

     /*get the number of requests*/
     memset (&buffer, 0, sizeof buffer);
     buffer.cnt = buf_size/sizeof(Csp1RequestStatusBuffer);
     buffer.req_stat_buf = (Uint64)(ptrlong)req_stat_buf;

#if defined(linux) || defined(_WIN32)
#ifdef CAVIUM_MULTICARD_API
   ret_code = ioctl((gpkpdev_hdlr[device_id]), IOCTL_N1_GET_ALL_REQUEST_STATUS, (ptrlong)&buffer);
#else
     ret_code = ioctl(CSP1_driver_handle, IOCTL_N1_GET_ALL_REQUEST_STATUS, (ptrlong)&buffer);
#endif
#else
     ret_code = ERR_OPERATION_NOT_SUPPORTED;
#endif

     if(ret_code == 0)
        *res_count = buffer.res_count;
     return ret_code;
}

/*****************************************************************************
 *
 *Csp1GetDevCnt
 *
 * Returns the number of Nitrox devices detected.
 *
 * Output
 *      pdev_count = number of devices returned in pdev_count.
 *
 * Return Value
 *      completion code = 0 (for success), ERR_BAD_IOCTL
 *
 ****************************************************************************/
Uint32
Csp1GetDevCnt(Uint32 *pdev_count,Uint8 *dev_mask)
{
     Uint32 ret_code = 0;
     Csp1DevMask  buf;
     memset(&buf,0,sizeof buf);
#ifdef CAVIUM_MULTICARD_API
     ret_code = ioctl(gpkpdev_hdlr[CAVIUM_DEV_ID],IOCTL_N1_GET_DEV_CNT,(ptrlong)&buf);
#else
     ret_code = ioctl(CSP1_driver_handle,IOCTL_N1_GET_DEV_CNT,(ptrlong)&buf);
#endif
     if(ret_code!= 0)
     {
        printf("CSP1: No devices detected \n");
     }
     *pdev_count=buf.dev_cnt;
     *dev_mask=buf.dev_mask;
	  
#ifdef CAVIUM_MULTICARD_API	  
     int i;
	  for(i=0;i<buf.dev_cnt;i++)
	     if(1<<i&buf.dev_mask){
		     default_device=i;
			  break;		        
	     }       
#endif	  
		
	
     return ret_code;

}
/*****************************************************************************
 *
 *Csp1GetDevType
 *
 * Returns the device type: 
 * Output
 *      device = NLITE/N1/PX.
 *
 * Return Value
 *      completion code = 0 (for success), ERR_BAD_IOCTL
 *
 ****************************************************************************/

Uint32
Csp1GetDevType(Uint32 *device)
{
     Uint32 ret_code = 0;
#ifdef CAVIUM_MULTICARD_API
     ret_code = ioctl(gpkpdev_hdlr[CAVIUM_DEV_ID],IOCTL_N1_GET_DEV_TYPE,device);
#else
     ret_code = ioctl(CSP1_driver_handle,IOCTL_N1_GET_DEV_TYPE,device);
#endif
     if(ret_code!= 0)
     {
        printf("CSP1: No devices detected \n");
     }
     return ret_code;
}


/*****************************************************************************
 *
 * CSP1_multi_open_device_file
 *
 * Opens a device with minor number =  dev_id
 *
 * Input
 *  dev_id = minor number of the device to be openend.
 *
 * Output
 *
 * Return Value
 *      completion code = 0 (for success), errno
 *
 ****************************************************************************/
int
CSP1_multi_open_device_file(int dev_id)
{
	char   name[32];
        int cond_code = 0;

	strcpy(name, "/dev/pkp_");
	
	strcat(name, "dev");

        if(dev_id)
           sprintf(name,"%s%d",name,dev_id);

	printf("CSP1_multi_open_device_file: %s\n", name);

        if(CSP1_driver_handle < 0)
	   CSP1_driver_handle= open(name, O_RDWR);

        if (CSP1_driver_handle < 0) 
          cond_code = errno;
        else 
        {
           cond_code = 0;
        }
        return cond_code;
}


/*****************************************************************************
 *
 * SpeedTestResult
 *
 * Calculate the result of speedtest
 *       
 * Input  
 *  info = information of speedtest.
 *      
 * Output
 *           
 * Return Value
 *      ret = speed values in Mbps 
              0 (if time_taken = 0 microsecond )
 *  
 ****************************************************************************/


Uint64 SpeedTestResult(Speed_Test_Info *info)
{   
        Uint64 ret = 0;
        if(info->time_taken != 0)
                ret = ((info->req_completed * info->dlen * 8) /(info->time_taken ));
        return (ret);
}


#ifdef _WIN32
DWORD	sleepInMs = 1;
static	HANDLE pkpHandle = INVALID_HANDLE_VALUE;

int
open (const char *path, int flags)
{
	if (pkpHandle != INVALID_HANDLE_VALUE) {
		errno = ERROR_ALREADY_INITIALIZED;
		return -1;
	}
	pkpHandle = CreateFile ("\\\\.\\PKP0", GENERIC_READ | GENERIC_WRITE,
	    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
	    FILE_ATTRIBUTE_NORMAL, NULL);
	if (pkpHandle == INVALID_HANDLE_VALUE) {
		errno = GetLastError ();
		return -1;
	}
	else
		return (int) pkpHandle;
}

int
close (int fd)
{
	if (pkpHandle != INVALID_HANDLE_VALUE) {
		CloseHandle (pkpHandle);
		pkpHandle = INVALID_HANDLE_VALUE;
		return 0;
	}
	errno = ERROR_FILE_NOT_FOUND;
	return -1;
}

int
ioctl (int fd, int request, ...)
{
	int	cst;
	va_list	vl;
	DWORD	retb;

	if (pkpHandle == INVALID_HANDLE_VALUE) {
		errno = ERROR_INVALID_PARAMETER;
		return -1;
	}
	va_start (vl, request);
	switch (request) {
	case IOCTL_N1_OPERATION_CODE:
	case IOCTL_N1_DO_OPERATION:
	case IOCTL_N1_DO_SG_OPERATION:
	case IOCTL_N1_GET_RANDOM_CODE:
		{
			Csp1OperationBuffer	*ob;

			ob = va_arg (vl, Csp1OperationBuffer *);
			if (DeviceIoControl (pkpHandle, (DWORD) request,
			    (LPVOID) ob, (DWORD) sizeof (Csp1OperationBuffer),
			    (LPVOID) ob, (DWORD) sizeof (Csp1OperationBuffer),
			    &retb, NULL)) {
				cst = ob->status;
				if (ob->status == ERR_REQ_PENDING) {
					ob->status = EAGAIN;
					cst = 0;
				}
			}
			else {
				cst = -1;
				errno = GetLastError ();
			}
		}
		break;
	case IOCTL_N1_ALLOC_CONTEXT:
	case IOCTL_N1_FREE_CONTEXT:
		{
			n1_context_buf	*cbuf;

			cbuf = va_arg (vl, n1_context_buf *);
			if (DeviceIoControl (pkpHandle, (DWORD) request,
			    (LPVOID) cbuf, (DWORD) sizeof (n1_context_buf),
			    (LPVOID) cbuf, (DWORD) sizeof (n1_context_buf),
			    &retb, NULL)) {
				cst = 0;
			}
			else {
				errno = GetLastError ();
				cst = -1;
			}
		}
		break;
	case IOCTL_N1_POLL_CODE:
	case IOCTL_N1_GET_REQUEST_STATUS:
		{
			Csp1RequestStatusBuffer	*rsb;

			rsb = va_arg (vl, Csp1RequestStatusBuffer *);
			if (DeviceIoControl (pkpHandle, (DWORD) request,
			    (LPVOID) rsb, (DWORD)
			    sizeof (Csp1RequestStatusBuffer), (LPVOID) rsb,
			    (DWORD) sizeof (Csp1RequestStatusBuffer), &retb,
			    NULL)) {
				cst = rsb->status;
				if (rsb->status == ERR_REQ_PENDING) {
					rsb->status = EAGAIN;
					cst = 0;
				}
			}
			else {
				errno = GetLastError ();
				cst = -1;
			}
		}
		break;
	case IOCTL_N1_GET_ALL_REQUEST_STATUS:
		{
			Csp1StatusOperationBuffer	*sob;

			sob = va_arg (vl, Csp1StatusOperationBuffer *);
			if (DeviceIoControl (pkpHandle, (DWORD) request,
			    (LPVOID) sob, (DWORD)
			    sizeof (Csp1StatusOperationBuffer), (LPVOID) sob,
			    (DWORD) sizeof (Csp1StatusOperationBuffer), &retb,
			    NULL)) {
				errno = GetLastError ();
				cst = -1;
			}
		}
		break;
	case IOCTL_N1_ALLOC_KEYMEM:
	case IOCTL_N1_FREE_KEYMEM:
	case IOCTL_N1_WRITE_KEYMEM:
		{
			n1_write_key_buf	*keybuf;

			keybuf = va_arg (vl, n1_write_key_buf *);
			if (DeviceIoControl (pkpHandle, (DWORD) request,
			    (LPVOID) keybuf, (DWORD) sizeof (n1_write_key_buf),
			    (LPVOID) keybuf, (DWORD) sizeof (n1_write_key_buf),
			    &retb, NULL))
				cst = 0;
			else {
				errno = GetLastError ();
				cst = -1;
			}
		}
		break;
	case IOCTL_N1_FLUSH_ALL_CODE:
		if (DeviceIoControl (pkpHandle, (DWORD) request, NULL,
		    0, NULL, 0, &retb, NULL))
			cst = 0;
		else {
			errno = GetLastError ();
			cst = -1;
		}
		break;
	case IOCTL_N1_FLUSH_CODE:
		{
			Uint32	id;

			id = va_arg (vl, Uint32);
			if (DeviceIoControl (pkpHandle, (DWORD) request,
			    (LPVOID) &id, (DWORD) sizeof (Uint32), NULL, 0,
			    &retb, NULL))
				cst = 0;
			else {
				errno = GetLastError ();
				cst = -1;
			}
		}
		break;
	case IOCTL_N1_DEBUG_WRITE_CODE:
	case IOCTL_N1_DEBUG_READ_CODE:
	case IOCTL_PCI_DEBUG_WRITE_CODE:
	case IOCTL_PCI_DEBUG_READ_CODE:
	case IOCTL_N1_INIT_CODE:
	case IOCTL_N1_SOFT_RESET_CODE:
	case IOCTL_N1_API_TEST_CODE:
	default:
		errno = ERROR_INVALID_PARAMETER;
		cst = -1;
		break;
	}
	return cst;
}
#endif

/*
 * $Id: cavium_common.c,v 1.44 2009/09/18 06:29:42 aravikumar Exp $
 * $Log: cavium_common.c,v $
 * Revision 1.44  2009/09/18 06:29:42  aravikumar
 * Csp1Random group changed to GP_GRP
 *
 * Revision 1.43  2009/09/16 11:42:51  aravikumar
 * SSL group added for missing APIs
 *
 * Revision 1.42  2009/09/14 09:39:33  aravikumar
 * group changed to GP_GRP for Csp1Me
 *
 * Revision 1.41  2009/09/09 14:29:17  aravikumar
 * NPLUS macro dependency removed and made it dynamic
 *
 * Revision 1.40  2009/08/07 07:09:04  rdhana
 * Removed returning of SRTP header at output.
 *
 * Revision 1.39  2009/07/03 07:08:30  rdhana
 * Updated SRTP_AES_CTR to support variable Tag len and non-returning of ROC incase of SRTP.
 * API changes:
 * minor OPcode[6] = 0 - SRTP and 1 - SRTCP
 * Param2[15:12] =  Tag length in bytes.
 * Param2[11:8]  =  Index length in bytes
 *
 * Revision 1.38  2009/06/23 10:41:42  kramaraju
 * Added multicard suport for Csp1GetAllResults api
 *
 * Revision 1.37  2009/06/23 08:37:05  kmonendra
 * Changes in SpeedTestResult.
 *
 * Revision 1.36  2009/06/22 06:49:49  rsruthi
 * -- Added AES_CFB Support.
 *
 * Revision 1.35  2009/06/18 09:55:39  rdhana
 * Added IPv6 Extension header and Selector Check support.
 *
 * Revision 1.34  2009/06/02 14:47:12  kmonendra
 * Done type casting in SpeedTestResult function.
 *
 * Revision 1.33  2009/05/15 10:31:14  kmonendra
 * Changes in SpeedTestResult, return speed in Mbps.
 *
 * Revision 1.32  2009/05/11 09:56:41  jrana
 * Defined ioctl switch IOCTL_N1_GET_ALL_REQUEST_STATUS for Csp1GetAllResults routine to work with windows.
 *
 * Revision 1.31  2009/05/06 09:40:50  kmonendra
 * Fixed comments for SpeedTestResult().
 *
 * Revision 1.30  2009/04/07 05:34:03  kmonendra
 * Added SpeedTestResult() for speedtest.
 *
 * Revision 1.29  2009/03/10 11:49:07  rdhana
 * Added Single PASS [AES_xxx + SHA1] SRTP support in SSL and IPSEC.
 *
 * Revision 1.28  2009/01/28 09:26:26  kmaheshwar
 * Removed MC1 define related code in Csp1SrtpAesCtr and Csp1AesXcbcPrf128
 *
 * Revision 1.27  2009/01/09 05:53:52  kmaheshwar
 * Added AesXcbcPrf128 (RFC 3566,3664, and 4434) support and it is disabled in Makefile
 *
 * Revision 1.26  2009/01/06 06:46:11  rdhana
 * Added AES_192, AES_256 Support in Csp1SrtpAesCtr.
 *
 * Revision 1.25  2008/10/24 09:35:21  ysandeep
 * changed "admin" to "nle_admin"
 *
 * Revision 1.24  2008/10/18 05:53:58  aramesh
 * default_device set properly.
 *
 * Revision 1.23  2008/10/16 09:30:36  aramesh
 * default_device  variable is added.
 *
 * Revision 1.22  2008/10/15 08:03:38  ysandeep
 * Multicard support for NPLUS added.
 *
 * Revision 1.21  2008/08/08 09:37:17  aramesh
 * initialized hash_size to 0.
 *
 * Revision 1.20  2008/07/10 12:17:29  rsruthi
 * --Fixed compilation error related to HMAC_SHA384/SHA512 support in MC2.
 *
 * Revision 1.19  2008/07/07 12:34:39  aramesh
 * Csp1GetDev parameters are changed.
 *
 * Revision 1.18  2008/07/03 09:59:37  aramesh
 * Declared Csp1GetDevType API.
 *
 * Revision 1.16  2008/06/05 07:01:55  sshekkari
 * Modified Csp1Me, PkcsEnc, PkcsCrtEnc, PkcsDec and PkcsCrtDec MC2 api's to support modlength upto 4096-bits.
 *
 * Revision 1.15  2008/06/03 06:19:40  rsruthi
 * - Added AesGCM/GMAC Encrypt/Decrypt API Support.
 * - Added SHA256, SHA384, SHA512 support in Csp1Hash and Csp1Hmac APIs.
 *
 * Revision 1.14  2008/05/22 05:48:17  aramesh
 * Csp1drivehandle is used only for non-multicard support.
 *
 * Revision 1.13  2008/04/25 06:06:45  rdhana
 * Added the FRAG_SUPPORT code in normal flow and  Removed the FRAG_SUPPORT ifdef and else part of the code.
 *
 * Revision 1.12  2008/02/12 13:27:08  aramesh
 * CSP1_driver_handle initilaized for multicard api also.
 *
 * Revision 1.11  2008/02/04 07:44:12  kmaheshwar
 * added Csp1SrtpAesCtr
 *
 * Revision 1.10  2007/10/26 13:48:37  kchunduri
 * --memset 'Csp1OperationBuffer' to zero to overcome issues observed with gcc-4.1.
 *
 * Revision 1.9  2007/10/18 09:35:09  lpathy
 * Added windows support.
 *
 * Revision 1.8  2007/09/10 10:15:22  kchunduri
 * --API changed to accept 'dev_id' as input parameter.
 *
 * Revision 1.7  2007/08/14 08:27:01  kchunduri
 * --define new API to retrieve number of Nitrox Devices detected and
 *   API to open a device with dev_id as input parameter.
 *
 * Revision 1.6  2007/07/04 09:25:49  kchunduri
 * --multi-card support.
 *
 * Revision 1.5  2007/05/04 10:30:38  kchunduri
 * fix compiler warnings.
 *
 * Revision 1.4  2007/05/01 05:45:37  kchunduri
 * * modified UIT64_C macro.
 *
 * Revision 1.3  2007/03/06 01:53:39  panicker
 * * CSP1_open_device_file - new routine automatically creates device file name
 *   and opens it for NitroxPX & N1 for NPLUS and normal mode.
 *
 * Revision 1.2  2007/02/20 23:30:52  panicker
 * * N1 and NLE device files are different
 *
 * Revision 1.1  2007/01/15 23:17:42  panicker
 * *** empty log message ***
 *
 * Revision 1.37  2006/08/23 05:41:18  pnalla
 * Added Fragmentation and UDP Encapsulation support
 *
 * Revision 1.36  2006/08/21 10:01:12  kchunduri
 * the status of IOCTL_N1_OPERATION is available in 'status' field. Earlier status is a return parameter. Need to change since earlier implementation was a problemon FreeBSD-4.11 for NB_CRYPTO mode of operation.
 *
 * Revision 1.35  2006/08/16 14:21:20  kchunduri
 * --IOCTL_N1_POLL_CODE takes Csp1RequestStatusBuffer as argument instead of RequestID value
 *
 * Revision 1.34  2006/05/16 13:44:52  kchunduri
 * --fix compilation warning
 *
 * Revision 1.33  2006/05/16 10:18:15  kchunduri
 * --conditional definition of UINT64_C
 *
 * Revision 1.32  2006/05/16 09:51:35  kchunduri
 * --changes to support re-aligned API structures.
 *
 * Revision 1.31  2006/05/05 11:02:12  dgandhewar
 * added UINT64_C(x) define
 *
 * Revision 1.30  2006/04/17 03:52:08  kchunduri
 * --single IOCTL support for Csp1GetAllResults --kiran
 *
 * Revision 1.29  2006/03/27 04:55:23  kchunduri
 * --kchunduri new API Csp1GetAllResults()
 *
 * Revision 1.28  2005/12/14 09:34:09  kkiran
 * - Replaced SSL flag with IPSEC_TEST flag to fix compilation error in TurboSSL
 *
 * Revision 1.27  2005/11/24 05:37:23  kanantha
 * Removed the compilation warning
 *
 * Revision 1.26  2005/11/17 13:31:09  kanantha
 * Updating with the 64 bit modifications, with proper matching of data types
 *
 * Revision 1.25  2005/10/20 10:00:35  phegde
 * - Added two APIs named Csp1WriteIpsecSa() and Csp1ProcessPacket() to support IPSec functionality.
 *
 * Revision 1.24  2005/09/29 12:29:52  sgadam
 * Moved back FreeBSD AMD64 changes to CVS head
 *
 * Revision 1.21  2005/09/29 10:06:37  sgadam
 * - input length for 3Des Enc is aligned multiple of 8 bytes.
 *
 * Revision 1.20  2005/09/28 15:39:30  ksadasivuni
 * - Merging FreeBSD 6.0 ADM64 release with CVS Head
 * - In ipsec_mc2.c the change is due to passing of physical context pointer
 * directly to userspace application. So no need for vtophys
 *
 * Revision 1.19  2005/09/08 14:27:35  sgadam
 * - Warning Removed
 *
 * Revision 1.18  2005/09/06 10:10:39  ksadasivuni
 * - Added "ULL" suffix to long constants
 *
 * Revision 1.17  2005/08/31 18:12:22  bimran
 * Fixed several compile warnings.
 *
 * Revision 1.16  2005/08/13 06:48:03  sgadam
 * SSL-FIPS merged code
 *
 * Revision 1.15  2005/05/21 05:04:16  rkumar
 * Merge with India CVS head
 *
 * Revision 1.14  2005/02/01 04:04:56  bimran
 * copyright fix
 *
 * Revision 1.13  2004/10/12 00:12:26  danny
 * bug fix
 * nehanet #366
 *
 * Revision 1.12  2004/08/25 22:31:34  tsingh
 * new file from India (Ram) fixes hash define
 *
 * Revision 1.2  2004/08/20 15:43:14  rkumar
 * Csp1HMac bug fixed for MC2
 *
 * Revision 1.1.1.1  2004/07/28 06:43:14  rkumar
 * Initial Checkin
 *
 * Revision 1.11  2004/06/03 21:10:08  bimran
 * added context type in deallocationg context.
 *
 * Revision 1.10  2004/05/02 19:35:13  bimran
 * Added Copyright notice.
 *
 * Revision 1.9  2004/05/01 05:57:44  bimran
 * Fixed a function descriptions on each function to match with the latest microcode and driver.
 *
 * Revision 1.8  2004/04/30 21:19:25  bimran
 * Fixed comments and enabled random number to be get from driver.
 *
 * Revision 1.7  2004/04/28 03:16:02  bimran
 * Fixed comments.
 *
 * Revision 1.6  2004/04/26 18:57:31  bimran
 * Fixed comment header of Csp1Initialize() to reflect NPLUS changes.
 *
 * Revision 1.5  2004/04/23 21:46:32  bimran
 * Lot of cleanup.
 * Removed all OS dependencies.
 * It should all be just ioctl.
 *
 * Revision 1.4  2004/04/21 22:23:49  bimran
 * Fixed key memory allocation deallocation.
 *
 * Revision 1.3  2004/04/16 23:55:23  bimran
 * Removed un-necessary defines. THey should go to cavium_common.h.
 *
 * Revision 1.2  2004/04/16 00:04:48  bimran
 * Fixed compilation issues.
 * returned ERR_OPERATION_NOT_SUPPORTED instead of '0' when a microcode does not support a particular macro.
 *
 * Revision 1.1  2004/04/15 22:38:38  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

