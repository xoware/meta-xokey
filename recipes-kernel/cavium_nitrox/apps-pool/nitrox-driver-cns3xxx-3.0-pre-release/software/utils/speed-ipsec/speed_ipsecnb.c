/*
 * copyright (c) 2003-2005 cavium networks (support@cavium.com). all rights 
 * reserved.
 * 
 * redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 * 
 * 2. redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 * 
 * 3. all advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement:
 * 
 *   this product includes software developed by cavium networks
 * 
 * 4. cavium networks' name may not be used to endorse or promote products 
 *    derived from this software without specific prior written permission.
 * 
 * 5. user agrees to enable and utilize only the features and performance 
 *    purchased on the target hardware.
 * 
 * this software,including technical data,may be subject to u.s. export control 
 * laws, including the u.s. export administration act and its associated 
 * regulations, and may be subject to export or import regulations in other 
 * countries.you warrant that you will comply strictly in all respects with all 
 * such regulations and acknowledge that you have the responsibility to obtain 
 * licenses to export, re-export or import the software.

 * to the maximum extent permitted by law, the software is provided "as is" and 
 * with all faults and cavium makes no promises, representations or warranties, 
 * either express,implied,statutory, or otherwise, with respect to the software,
 * including its condition,its conformity to any representation or description, 
 * or the existence of any latent or patent defects, and cavium specifically 
 * disclaims all implied (if any) warranties of title, merchantability, 
 * noninfringement,fitness for a particular purpose,lack of viruses, accuracy or
 * completeness, quiet enjoyment, quiet possession or correspondence to 
 * description. the entire risk arising out of use or performance of the 
 * software lies with you.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <sys/time.h>

#include "cavium_common.h"
#include "cavium_le.h"
#include "linux_ioctl.h"
#include "speed_ipsecnb.h"

#define	err(_x, ...)		fprintf (stderr, _x, ## __VA_ARGS__)

#define Exit printf ("Exiting (Line: %d)\n", __LINE__); exit (0);

const char *options = "hsi:i:m:l:p:t:e:a:";

#ifdef CAVIUM_MULTICARD_API
Uint64 ctxHandle[4];
int dev_mask = 0;
#endif
int device_count = 0;
Uint32 device_id;

Uint8 e_key[] = {
	0x11,0x11,0xaa,0xaa,0x22,0x22,0xbb,0xbb,
	0x33,0x33,0xcc,0xcc,0x44,0x44,0xdd,0xdd,
	0x55,0x55,0xee,0xee,0x66,0x66,0xff,0xff};

Uint8 a_key[] ={
	0x11,0x11,0xaa,0xaa,0x22,0x22,0xbb,0xbb,
	0x33,0x33,0xcc,0xcc,0x44,0x44,0xdd,0xdd}; 

Uint8 temp_data [2000] = { 
	0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,
	0x45,0x00,0x00,0x57,0x00,0x00,0x40,0x00, 
	0x40,0x01,0xb6,0x8f,0xc0,0xa8,0x01,0x64,
	0xc0,0xa8,0x01,0x65,0x08,0x00,0x67,0x41,
	0x1e,0x09,0x00,0x01,0x9a,0xe6,0xc7,0x41,
	0x1f,0x89,0x06,0x00,0x08,0x09,0x0a,0x0b, 
	0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,
	0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,
	0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,
	0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,
	0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,
	0x34,0x35,0x36,0x37,0x38,0x39,0x40,0x06,
	0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,
	0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,
	0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,
	0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,
	0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,
	0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,
	0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,
	0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33
};

Uint32 output_data[5000];
PendingBuffer           *pendingList = NULL;
Csp1RequestStatusBuffer *pollBuffer = NULL;

void help ()
{
	err ("./speedtest     [-i <inbound|outbound>]\n");
	err ("                [-t <Test duration in seconds>\n");
	err ("                [-l <Packet length in bytes>]\n");
	err ("                [-p <IPSec Proto (ESP or AH)>]\n");
	err ("                [-m <IPSec mode (tunnel or transport)>]\n");
	err ("                [-e <Encryption Type>] \n");
	err ("                        [-Possible combinations]\n");
	err ("                              [-AES128 (or 192 or 256)]\n");
	err ("                              [-DESCBC]\n");
	err ("                              [-DES3CBC]\n");
	err ("                        [This option is not required for AH mode]\n");
	err ("                [-a <Authentication Type>\n");
	err ("                        [-Possible combinations]\n");
	err ("                              [-MD5 or SHA1]\n");
}

Uint64 apiTimeMs ()
{
    struct timeval m_real1;
    unsigned long temp;

    gettimeofday(&m_real1, 0);
    temp = (m_real1.tv_sec * 1000) + ((m_real1.tv_usec+999) / 1000);

    return temp;
}


int SpeedProcessOutbound (
		Uint16 size, 
		Uint16 param, 
		Uint16 dlen,
		n1_scatter_buffer *inv,
		n1_scatter_buffer *outv, 
		int rlen,
		Uint64 ctx,
		int response_order, 
		int req_queue,
		int dir, 
		Uint32 *req_id
#ifdef CAVIUM_MULTICARD_API
		, Uint32 device_id
#endif
		)
{
	n1_request_buffer n1_buf;
	int cond_code;
	int i;
	
	memset(&n1_buf, 0, sizeof(n1_buf));
	
	if (dir == OUTBOUND)  
		n1_buf.opcode = OP_IPSEC_PACKET_OUTBOUND; 
	else if (dir == INBOUND) {
		n1_buf.opcode = OP_IPSEC_PACKET_INBOUND; 
	}

	n1_buf.size = size;
	n1_buf.param = param;
	n1_buf.dlen = dlen;
	n1_buf.rlen = rlen;
	n1_buf.reserved = 0;
	n1_buf.ctx_ptr = ctx;
	n1_buf.group = CAVIUM_IPSEC_GRP;

	n1_buf.incnt = inv->bufcnt;
	n1_buf.outcnt = outv->bufcnt;
	
	for ( i = 0; i < inv->bufcnt; i++) {
		n1_buf.inptr[i] = CAST_TO_X_PTR((Uint8 *)inv->bufptr[i]);
		n1_buf.insize[i] = inv->bufsize[i];
		n1_buf.inoffset[i] = n1_buf.insize[i];
		n1_buf.inunit[i] = UNIT_8_BIT;
	}
	
	for ( i = 0; i < outv->bufcnt; i++) {
		n1_buf.outptr[i] = CAST_TO_X_PTR((Uint8 *)outv->bufptr[i]);
		n1_buf.outsize[i] = outv->bufsize[i];
		n1_buf.outoffset[i] = n1_buf.outsize[i];
		n1_buf.outunit[i] = UNIT_8_BIT;
	}
	
	n1_buf.dma_mode  = CAVIUM_DIRECT;
	n1_buf.res_order = response_order;
	n1_buf.req_queue = req_queue;
	n1_buf.status    = 0;

	if (dir == OUTBOUND)  {
		n1_buf.req_type = CAVIUM_NON_BLOCKING;
	}

#ifdef CAVIUM_MULTICARD_API
	cond_code = ioctl (gpkpdev_hdlr[device_id], IOCTL_N1_OPERATION_CODE, &n1_buf);
#else
	cond_code = ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, &n1_buf);
#endif
	*req_id=n1_buf.request_id;

    printf("cond_code is %d\n", cond_code);
	if (cond_code)
		return cond_code; /* return error value */
	else
		return n1_buf.status;
}


Uint32
SpeedWriteIpsecSa(
	IpsecProto proto, 
	Version inner_version, 
	Version outer_version, 
	IpsecMode mode,
	Direction dir, 
	EncType cypher, 
	Uint8 *e_key, 
	AuthType auth,
	Uint8 *a_key, 
	Uint8 template[40], 
	Uint32 spi, 
	Uint8 copy_df,
	Uint8 udp_encap, 
	Uint64 ctx, 
	Uint64 next_ctx, 
	Uint32 *in_buffer, 
	Uint32 *out_buffer, 
	int res_order,
	int req_queue
#ifdef CAVIUM_MULTICARD_API
	, Uint32 device_id
#endif
	)          
{
	Uint8 *p;
	Uint16 *control;
	n1_request_buffer n1_buf;
	Uint32 len;
	int queue = 0;
	Uint32 ret_val;
	Uint32 cond_code;

	p = (Uint8*)in_buffer;

	control = (Uint16*)p;
	*control = 0;

    /* Populate the control structure as the MC2 microcode requires */

	*control = (((dir& 0x1) << IPSEC_DIRECTION_SHIFT) |
				((VALID_SA & 0x1) << IPSEC_VALID_SHIFT) | 
				((outer_version & 0x1) << IPSEC_VERSION_SHIFT) |
				((inner_version & 0x1) << (IPSEC_VERSION_SHIFT+1)) |
				((mode & 0x1) << IPSEC_MODE_SHIFT) |
				((proto & 0x1) << IPSEC_PROT_SHIFT) |
				((udp_encap & 0x3) << IPSEC_ENCAP_SHIFT) |  
				((cypher & 0x7) << IPSEC_CIPHER_SHIFT) |
				((auth & 0x3) << IPSEC_AUTH_SHIFT) |
				((dir==INBOUND) ? (0x0 << IPSEC_SELECTOR_SHIFT) : ((copy_df & 0x1) << IPSEC_DF_SHIFT)) |
				((0x0) << IPSEC_FT_SHIFT) |                         
				((next_ctx ? 1 : 0) << IPSEC_NEXT_SA_SHIFT));

	*control = htobe16(*control);
	p += 2; 
	*(Uint16*)p = 0;
	p += 2; 

	memcpy(p,&spi,4);
	p += 4;

	if(cypher != NO_CYPHER)   memcpy(p, e_key, 32);
	else                      memset(p, 0, 32);

	p += 32;

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

	len = (Uint8*)p - (Uint8*)in_buffer;

   /* Next SA */
   /* We are now passing the physical addr directly as context */
   /* so no need for cavium_vtophys */
	*(Uint64*)p = htobe64(next_ctx);

	p   += 8;
	len += 8;

	if (dir == OUTBOUND) {
		if (mode==TUNNEL) {
			if (outer_version == IPV4) {
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
				memcpy(p, template, 40);
				p+=40;
				len+=40;
			}
		}
	}

	memset (p, 0, IPSEC_CONTEXT_SIZE-len);
	memset (&n1_buf, 0, sizeof(n1_buf));

	n1_buf.opcode = ((dir == INBOUND) ? OP_WRITE_INBOUND_IPSEC_SA : OP_WRITE_OUTBOUND_IPSEC_SA); 
	n1_buf.size = 0;
	n1_buf.param = 0;
	n1_buf.dlen = len;
	n1_buf.rlen = 0;
	n1_buf.reserved = 0;
	n1_buf.ctx_ptr = ctx;
	n1_buf.group = CAVIUM_IPSEC_GRP;

	n1_buf.dma_mode = CAVIUM_DIRECT;

	n1_buf.incnt = 1;
   /* For DIRECT mode, we need out_buffer for completion code.
    * For SCATTER_GATHER, we do not need this, because completion
    * code goes to rptr of command
    */
	if(n1_buf.dma_mode == CAVIUM_DIRECT)  n1_buf.outcnt=1;
	else                                  n1_buf.outcnt=0; 

	n1_buf.inptr[0]    = CAST_TO_X_PTR((Uint8 *)in_buffer);
	n1_buf.insize[0]   = len;
	n1_buf.inoffset[0] = n1_buf.insize[0];
	n1_buf.inunit[0]   = UNIT_8_BIT;

	if(n1_buf.outcnt)  {
		n1_buf.outptr[0]    = CAST_TO_X_PTR((Uint8 *)out_buffer);
		n1_buf.outsize[0]   = 0; 
		n1_buf.outoffset[0] = n1_buf.outsize[0];
		n1_buf.outunit[0]   = UNIT_8_BIT;
	}

	n1_buf.res_order = res_order;
	n1_buf.req_queue = queue;
	
#ifdef CAVIUM_MULTICARD_API
	cond_code = ioctl (gpkpdev_hdlr[device_id], IOCTL_N1_OPERATION_CODE, (ptrlong)&n1_buf);
#else
	cond_code = ioctl (CSP1_driver_handle, IOCTL_N1_OPERATION_CODE, (ptrlong)&n1_buf);
#endif
	if (cond_code)
		ret_val = cond_code;
	else
		ret_val = n1_buf.status;

	return ret_val;
}

int StartNonBlockTest (
	Uint32 buflen,
	n1_scatter_buffer inv,
	n1_scatter_buffer outv, 
	Uint64 rlen,
	Uint64 ctx,
	int dir, 
	int time)
{
	Uint64 t1, t2;
	Uint32 i,j, hit, hit_count, miss_count, pending_count, resCount;
    Uint32 count=0;
	Uint32 time_elapsed = 0;
	Uint8 moretogo = 1;
	int ret;
	Uint32 throughput;

	pollBuffer = (Csp1RequestStatusBuffer *) malloc (MAX_TO_POLL * sizeof (Csp1RequestStatusBuffer));
#ifndef CAVIUM_MULTICARD_API
	pendingList = (PendingBuffer *) malloc (MAX_PENDING*sizeof(PendingBuffer));
	if (!pendingList || !pollBuffer)  {
		if (pendingList)  free (pendingList);
		if (pollBuffer)   free (pollBuffer);
		err ("Not enough memory to allocate Pending/Poll buffer\n");
		return -1;
	}

	t1 = apiTimeMs ();

	//for (i = 0; i < MAX_PENDING; i++)  {
	for (i = 0; i < 1; i++)  {
		pendingList[i].outlen = 0;
		pendingList[i].status = 0xff;

		ret = SpeedProcessOutbound (0, 0, buflen, &inv, &outv, rlen, 
								(Uint64)ctx, 0, 0, dir, &pendingList[i].reqId);
		if (ret != EAGAIN)  {
			err ("SpeedProcessOutbound failed ret : %d\n", ret);

		/* Cleanup all pending requests */
			count = 0;
			while (moretogo)  {
				sleep (1);
				moretogo = 0;
				for (j = 0; j < i; j++)  {
					pendingList[j].status = Csp1CheckForCompletion (pendingList[j].reqId);
					if (pendingList[j].status != 0x00)  moretogo = 1;
					count++;
				}
				if (count > 20) break;
			}
			return -1;
		}
		printf("yes over\n");
		exit(1);
		pendingList[i].status = 1;
	}

	pending_count = MAX_PENDING;
	hit_count = miss_count = 0; 
	int rep = 0;
	//while (1)  {
	if ( rep == 2) {
	//if (!(count % 100)) {
			t2 = apiTimeMs();
			//if ((t2 - t1) >= time * 1000) {
				goto cleanup;
			//}
        //}
		for(i = 0; i < MAX_PENDING; i = i + MAX_TO_POLL) {
			hit = 1;
			for(j = 0; j < MAX_TO_POLL; j++) {
				if (pendingList[j+i].status == 0) {
					hit = 0;
					break;
				}
			}
			if (hit) {
				hit_count++;
				for(j = 0; j < MAX_TO_POLL; j++) {
					pollBuffer[j].request_id = pendingList[j+i].reqId;
					pollBuffer[j].status = 1;
				}

				ret = Csp1GetAllResults (pollBuffer,
                            MAX_TO_POLL*sizeof(Csp1RequestStatusBuffer),
                            &resCount);
				for (j = 0; j < MAX_TO_POLL; j++)  {
					if (pollBuffer[j].status == 0)  {
						printf("Yes incr. count\n");
						count++;
						/* Sending the request again */

						ret = SpeedProcessOutbound (0, 0, buflen, &inv, 
                                                    &outv, rlen, (Uint64)ctx, 
													0, 0, dir, 
													&pendingList[j+i].reqId);

						if (ret != EAGAIN)  {
							err ("Error sending request\n");
							pendingList[j+i].status = 0;
							pending_count--;
							goto cleanup;
						}
						pendingList[j+i].status = 1;
					}
#if 0
                                            else if (pollBuffer[j].status == ERR_REQ_PENDING)  {
						pendingList[j+i].status = 0;
						pending_count--;
						err ("Request %d failed (error code:0x%X)\n", 
								pendingList[j+i].reqId, pollBuffer[j].status);
						err ("Success Count: %d\n", count);
						err ("Pending Count: %d\n", pending_count);
						goto cleanup;
					}
#endif
				}
			} else {

				miss_count++;
				for(j=0;j<MAX_TO_POLL;j++) {
					if(pendingList[j+i].status) {
						pollBuffer[0].request_id = pendingList[j+i].reqId;
						pollBuffer[0].status = 1;
						ret = Csp1GetAllResults(pollBuffer,
									sizeof(Csp1RequestStatusBuffer),
									&resCount);
						if(pollBuffer[0].status == 0) {
							count ++;

							ret = SpeedProcessOutbound (0, 0, buflen, &inv, 
                                                    &outv, rlen, (Uint64)ctx, 
													0, 0, dir, 
													&pendingList[j+i].reqId);
							if (ret != EAGAIN) {
									printf("Error Sending request.\n");
									pendingList[j+i].status=0;
									pending_count--;
									goto cleanup;
							}
						} else if (pollBuffer[0].status != ERR_REQ_PENDING) {
							pendingList[j+i].status=0;
							pending_count--;
							printf("Request %d failed (error code 0x%X)\n", 
								pendingList[j+i].reqId, pollBuffer[0].status);
							printf("Success Count = %d\n", count);
							printf("Pending Count = %d\n", pending_count);
							goto cleanup;
						}
					}
		    	}
			}
		}
	}
#else
	pendingList = (PendingBuffer *) malloc (
		((MAX_PENDING + MAX_TO_POLL) * device_count) *sizeof(PendingBuffer));
	if (!pendingList || !pollBuffer)  {
		if (pendingList)  free (pendingList);
		if (pollBuffer)   free (pollBuffer);
		err ("Not enough memory to allocate Pending/Poll buffer\n");
		return -1;
	}

	t1 = apiTimeMs ();

	for (device_id = 0; device_id < device_count; device_id++)  {
		for (i = 0; i < MAX_PENDING; i++)  {
			pending_count = device_id * MAX_PENDING;
			pendingList[pending_count + i].outlen = 0;
			pendingList[pending_count + i].status = 0xff;

			ret = SpeedProcessOutbound (0, 0, buflen, &inv, &outv, rlen, 
							(Uint64)ctxHandle[device_id], 0, 0, dir,
							&pendingList[pending_count + i].reqId, 
							device_id);
			if (ret != EAGAIN)  {
				err ("SpeedProcessOutbound failed ret : %d\n", ret);

			/* Cleanup all pending requests */
				count = 0;
				while (moretogo)  {
					sleep (1);
					moretogo = 0;
					for (j = 0; j < i; j++)  {
						pendingList[pending_count + j].status = 
						Csp1CheckForCompletion (pendingList[pending_count + j].reqId, device_id);
						if (pendingList[pending_count+j].status!=0x00)
							moretogo = 1;
						count++;
					}
					if (count > 20) break;
				}
				return -1;
			}
			pendingList[pending_count + i].status = 1;
		}
	}

	pending_count = MAX_PENDING * device_count;
	hit_count = miss_count = 0; 
	while (1)  {
		if (!(count % 100)) {
			t2 = apiTimeMs();
			if ((t2 - t1) >= time * 1000) {
				goto cleanup;
			}
        }
		for (device_id = 0; device_id < device_count; device_id++)  {
			for(i = 0; i < MAX_PENDING; i = i + MAX_TO_POLL) {
				hit = 1;
				for(j = 0; j < MAX_TO_POLL; j++) {
					if (pendingList[(device_id*MAX_PENDING)+j+i].status == 0) {
						hit = 0;
						break;
					}
				}
				if (hit) {
					hit_count++;
					for(j = 0; j < MAX_TO_POLL; j++) {
						pollBuffer[j].request_id = pendingList[(device_id*MAX_PENDING)+j+i].reqId;
						pollBuffer[j].status = 1;
					}
	
					ret = Csp1GetAllResults (pollBuffer,
	                            MAX_TO_POLL*sizeof(Csp1RequestStatusBuffer),
	                            &resCount, device_id);
					if (ret)  {
						printf ("Error return from %s : %d\n", __FUNCTION__, ret);
					}
					for (j = 0; j < MAX_TO_POLL; j++)  {
						if (pollBuffer[j].status == 0)  {
							count++;
							/* Sending the request again */
	
							ret = SpeedProcessOutbound (
										0, 0, buflen, &inv, 
	                                    &outv, rlen, 
										(Uint64)ctxHandle[device_id], 
										0, 0, dir, 
										&pendingList[(device_id*MAX_PENDING)+j+i].reqId,
										device_id);
	
							if (ret != EAGAIN)  {
								err ("Error sending request\n");
								pendingList[(device_id * MAX_PENDING) + j+i].status = 0;
								pending_count--;
								goto cleanup;
							}
							pendingList[(device_id*MAX_PENDING)+j+i].status = 1;
						}
					}
				} else {
					miss_count++;
					for(j=0;j<MAX_TO_POLL;j++) {
						if(pendingList[(device_id*MAX_TO_POLL)+j+i].status) {
							pollBuffer[0].request_id = pendingList[(device_id+MAX_TO_POLL)+j+i].reqId;
							pollBuffer[0].status = 1;
							ret = Csp1GetAllResults(pollBuffer,
										sizeof(Csp1RequestStatusBuffer),
										&resCount, device_id);
							if(pollBuffer[0].status == 0) {
								count ++;
	
								ret = SpeedProcessOutbound (0, 0, buflen, &inv, 
	                                    &outv, rlen, (Uint64)ctxHandle[device_id], 
										0, 0, dir, 
										&pendingList[(device_id*MAX_PENDING)+j+i].reqId,
										device_id);
								if (ret != EAGAIN) {
										printf("Error Sending request.\n");
										pendingList[(device_id*MAX_TO_POLL)+j+i].status=0;
										pending_count--;
										goto cleanup;
								}
							} else if (pollBuffer[0].status != ERR_REQ_PENDING) {
								pendingList[(device_id*MAX_TO_POLL)+j+i].status=0;
								pending_count--;
								printf("Request %d failed (error code 0x%X)\n", pendingList[(device_id*MAX_TO_POLL)+j+i].reqId, pollBuffer[0].status);
								printf("Success Count = %d\n", count);
								printf("Pending Count = %d\n", pending_count);
								goto cleanup;
							}
						}
			    	}
				}
			}
		}
	}

#endif
cleanup: 
	t2 = apiTimeMs();
	while (pending_count) {
#ifndef CAVIUM_MULTICARD_API
		for(i=0;i<MAX_PENDING;i++) {
			if(pendingList[i].status) {
				pollBuffer[0].request_id = pendingList[i].reqId;
				pollBuffer[0].status = 1;
                                ret = Csp1CheckForCompletion(pendingList[i].reqId);
				if(ret == 0) {
					pending_count--;
					pendingList[i].status=0;
				}else if(ret!= 11){
					printf("Cleanup: Request %d failed (error code 0x%X)\n", 
							pendingList[i].reqId, pollBuffer[0].status);
					printf("Success Count = %d\n", count);
					printf("Pending Count = %d\n", pending_count);
					break;
				}
			}
		}
#else
		for (device_id = 0; device_id < device_count; device_id++)  {
			for(i=0;i<MAX_PENDING;i++) {
				if(pendingList[(device_id * MAX_PENDING) + i].status) {
					pollBuffer[0].request_id = pendingList[(device_id * MAX_PENDING)+i].reqId;
					pollBuffer[0].status = 1;
		            ret = Csp1CheckForCompletion(pendingList[(device_id * MAX_PENDING)+i].reqId, device_id);
					if(ret == 0) {
						pending_count--;
						pendingList[(device_id * MAX_PENDING)+i].status=0;
					}else if(ret!= 11){
						printf("Cleanup: Request %d failed (error code 0x%X)\n", pendingList[(device_id * MAX_PENDING)+i].reqId, pollBuffer[0].status);
						printf("Success Count = %d\n", count);
						printf("Pending Count = %d\n", pending_count);
						break;
					}
				}
			}
		}
#endif
	}

if(pendingList) free(pendingList);
if(pollBuffer) free(pollBuffer);
	time_elapsed = t2 - t1;


	/* Check if the test has run for atleast 1 sec */
	if (time_elapsed >= 1000)
		throughput = ((((count)/(int)((time_elapsed)/1000))*buflen*8)/1000000);
	else
		throughput = 0;	

	printf ("  %-8d          %-8u\n", buflen, throughput);
	return throughput;
}


int SpeedDoOutbound (
		int8_t proto, 
		Uint32 datalen, 
		int8_t mode, 
		int8_t enc, 
		int8_t auth,
		int dir, 
		int time)
{
	n1_scatter_buffer inv, outv;
	Uint32 *out_buffer_ip, *in_buffer_ip;
	Uint64 ctx;
	int ret;
	Uint64 rlen;
	int aes = 0, auth1 = 0;
	Uint32 iphdr_len = 20, template_len = 20;

	Uint16 buflen = datalen + 20;
	Uint8 *pt = (Uint8 *) &buflen;

	in_buffer_ip = (Uint32 *) malloc (512 * sizeof (Uint8));
	out_buffer_ip = (Uint32 *) malloc (8 * sizeof(Uint8));

	if (!in_buffer_ip || !out_buffer_ip)  {
		printf ("Error!! Malloc failure\n");
	}

#ifdef CAVIUM_MULTICARD_API
	ret = Csp1Initialize (CAVIUM_DIRECT, CAVIUM_DEV_ID);
#else
	ret = Csp1Initialize (CAVIUM_DIRECT);
#endif
	if (ret != 0)  {
		err ("Csp1Initialize failed (Line: %d  Function: %s)\n", __LINE__, __FUNCTION__);
		return -1;
	}

#ifdef CAVIUM_MULTICARD_API
	Csp1GetDevCnt ((Uint32 *) & device_count, (Uint8 *) & dev_mask);
	for (device_id = 0; device_id < device_count; device_id++) {
		if (Csp1Initialize (CAVIUM_DIRECT, device_id)) {
			printf ("pkp_init(): Cps1Initialize() failed for dev%d.\n",
			device_id);
			exit (-1);
		}
	}
#else
	device_count = 1;
#endif


#ifdef CAVIUM_MULTICARD_API
	for (device_id = 0; device_id < device_count; device_id++) {
		if (Csp1AllocContext (CONTEXT_SSL, &ctxHandle[device_id], device_id)) {
			printf ("Error allocating context.\n");
			goto End;
		}
	}
#else
	ret = Csp1AllocContext (CONTEXT_IPSEC, &ctx);
#endif
	if (ret != 0)  {
		err ("Csp1AllocContext failed (Line: %d  Function: %s\n", __LINE__, __FUNCTION__);
		goto End;
	}

	for (device_id = 0; device_id < device_count; device_id++)  {
	ret = SpeedWriteIpsecSa (proto, IPV4, IPV4, mode, OUTBOUND, enc, e_key,
			  				 auth, a_key, (mode == TUNNEL)? temp_data: NULL,
							 0x200, 0, 0, 
#ifdef CAVIUM_MULTICARD_API
							ctxHandle[device_id],
#else
							 ctx, 
#endif
							 0, in_buffer_ip, out_buffer_ip, 
							 0, 0
#ifdef CAVIUM_MULTICARD_API
							, device_id
#endif
							 ); 
	}

	auth1        = auth             ? 1  : 0;
	aes          = (enc > 2)        ? 1  : 0; 
	iphdr_len    = (mode==TUNNEL)   ? 0  : 20;
	template_len = (mode == TUNNEL) ? 20 : 0;

	if (proto == ESP)  {
		rlen = RLEN_OUTBOUND_ESP_PACKET(
						buflen, 
						iphdr_len,
						template_len,
						aes,
						auth1);
	} 
	else if (proto == AH)  {
		buflen = (mode == TUNNEL) ? (buflen) : (buflen - 20);
		rlen = RLEN_OUTBOUND_AH_PACKET(
						buflen, 
						template_len,
						iphdr_len);
	}

	temp_data[10] = pt[1];
	temp_data[11] = pt[0];

	inv.bufsize[0]  = buflen + 8;
	outv.bufsize[0] = rlen;
	
	inv.bufcnt      = 1;
	outv.bufcnt     = 1;
	inv.bufptr[0]   = (Uint32 *)temp_data;
	outv.bufptr[0]  = output_data;

	ret = StartNonBlockTest (buflen+8, inv, outv, rlen, ctx, dir, time);
	
	if (ret == -1)  {
		err ("StartNonBlockTest failed\n");
		return -1;
	}

#ifdef CAVIUM_MULTICARD_API
	for (device_id = 0; device_id < device_count; device_id++)  {
		Csp1FreeContext (CONTEXT_IPSEC, (Uint64)ctxHandle[device_id], device_id);	
		Csp1Shutdown (device_id);
	}
#else
	Csp1FreeContext (CONTEXT_IPSEC, (Uint64)ctx);
	Csp1Shutdown ();
#endif

End: 
	if (in_buffer_ip)   free (in_buffer_ip); 
	if (out_buffer_ip)  free (out_buffer_ip);

	return 0;
}


int main (int argc, char **argv)
{
	int8_t option;
	Uint32 buflen, payload;
	char *proc;
	int dir = -1;
	int8_t mode = -1, enc = -1, auth = -1, proto = -1;
	int time = -1;
	int ret;

	while ((option = getopt (argc, argv, options)) != -1)  {
		switch (option)  {
			case 'h':
				help ();
				return -1;

			case 't': 
				time = atoi (optarg);
				break;

			case 'i':
				proc = strdup (optarg);
				break;

			case 'l':
				buflen = atoi (optarg);
				break;

			case 'p':
				if (!strcasecmp ("ESP", strdup(optarg))) {
					proto = ESP;
				} else if (!strcasecmp ("AH", strdup (optarg))) {
					proto = AH;
				} else {
					err ("Invalid IPSec Protocol entered (-p option)\n");
					help ();
					return -1;
				}
				break;

			case 'm':
				if (!strcasecmp ("tunnel", strdup(optarg))) {
					mode = TUNNEL;
				} else if (!strcasecmp ("transport", strdup(optarg))) {
					mode = TRANSPORT;
				} else {
					err ("Invalid IPSec mode entered (-m option)\n");
					help ();
					return -1;
				}
				break;

			case 'e':
				if (!strcasecmp ("AES128", strdup(optarg))) {
					enc = AES128CBC;
				} else if (!strcasecmp ("AES192", strdup(optarg))) {
					enc = AES192CBC;
				} else if (!strcasecmp ("AES256", strdup(optarg))) {
					enc = AES256CBC;
				} else if (!strcasecmp ("DESCBC", strdup(optarg))) {
					enc = DESCBC;
				} else if (!strcasecmp ("DES3CBC", strdup(optarg))) {
					enc = DES3CBC;
				} else {
					err ("Invalid Encryption Type entered(-e option");
					help ();
					return -1;
				}
				break;

			case 'a':
				if (!strcasecmp ("MD5", strdup(optarg))) {
					auth = MD5HMAC96;
				} else if (!strcasecmp("SHA1", strdup(optarg))) {
					auth = SHA1HMAC96;
				} else {
					err ("Invalid Authentication Type (-a option)\n");
					help ();
					return -1;
				}
				break;

			case '?':
			default:
				if (strchr (options, option) != NULL)
					err ("option %c needs an argument\n", option);
				return -1;
		}
	}

	if ((auth == -1) ||  (mode == -1) || (proto == -1))  {
		help ();
		return -1;
	}
	if (proto == AH)  {
		if (enc != -1)  {
			err ("IPSec AH Protocol doesn't require -e option\n");
			help ();
			return -1;
		}
	}


	if (!strcasecmp (proc, "outbound")) {
		dir = OUTBOUND;
		payload = buflen - 28;
		ret = SpeedDoOutbound (proto, payload, mode, enc, auth, dir, time);
	} else if (!strcasecmp (proc, "inbound"))  {
		err ("Error !!! Presently inbound is not supported\n");
		return -1;
	} else {
		err ("Invalid IPSec processing entered (-i option)\n");
		help ();
		return -1;
	}

	return 0;
}
