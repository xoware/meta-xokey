
/* Copyright (c) 2003-2005 Cavium Networks (support@cavium.com) All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:

 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation and/or
 * other materials provided with the distribution.
 *
 * 3. Cavium Networks name may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * This Software, including technical data, may be subject to U.S. export control laws,
 * including the U.S. Export Administration Act and its associated regulations,
and may be
 * subject to export or import regulations in other countries. You warrant that
You will comply
 * strictly in all respects with all such regulations and acknowledge that you have the responsibility
 * to obtain licenses to export, re-export or import the Software.
 *
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" AND
WITH ALL FAULTS
 * AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR WARRANTIES, EITHER EXPRESS,
IMPLIED, STATUTORY,
 * OR OTHERWISE, WITH RESPECT TO THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY
 * REPRESENTATION OR DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM
 * SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY, NONINFRINGEMENT,
 * FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES, ACCURACY OR COMPLETENESS,
QUIET ENJOYMENT,
 * QUIET POSSESSION OR CORRESPONDENCE TO DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE
 * OF THE SOFTWARE LIES WITH YOU.
*/

#ifndef CAV_ECC_MUL_H
#define CAV_ECC_MUL_H
#include<openssl/ec.h>
#include<openssl/cavium_common.h>
#include<openssl/objects.h>
#include<openssl/bn.h>

Uint64 Get_Curve_Id(const EC_GROUP *group);
void* Allocate_Memory(int num);
int Ecc_Alloc_Context(EC_GROUP *group,Uint64 cid);
int Cav_Ecc_Mul(const EC_GROUP *group,Uint64 cid,EC_POINT *r,const BIGNUM *k,const EC_POINT *point,const BIGNUM *scalar,BN_CTX *ctx);
int Fixed_Point_Mul(const EC_GROUP *group,EC_POINT *r,const BIGNUM *scalar,BN_CTX *ctx);
int Unknown_Point_Mul(const EC_GROUP *group,EC_POINT *r,const EC_POINT *point,const BIGNUM *p_scalar,BN_CTX *ctx);

/*  r=k*p(fixed)+point*scalar(unknown)  */

int Simul_Point_Mul(const EC_GROUP *group,EC_POINT *r,const BIGNUM *k,const EC_POINT *point,const BIGNUM *scalar,BN_CTX *ctx);

#endif
