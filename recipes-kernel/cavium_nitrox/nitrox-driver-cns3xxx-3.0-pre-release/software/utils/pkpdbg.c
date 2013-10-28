/* pkpdbg.c*/
/*
 * Copyright (c) 2003-2005 Cavium Networks (support@cavium.com). All rights 
 * reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 * 
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement:
 * 
 *   This product includes software developed by Cavium Networks
 * 
 * 4. Cavium Networks' name may not be used to endorse or promote products 
 *    derived from this software without specific prior written permission.
 * 
 * 5. User agrees to enable and utilize only the features and performance 
 *    purchased on the target hardware.
 * 
 * This Software,including technical data,may be subject to U.S. export control 
 * laws, including the U.S. Export Administration Act and its associated 
 * regulations, and may be subject to export or import regulations in other 
 * countries.You warrant that You will comply strictly in all respects with all 
 * such regulations and acknowledge that you have the responsibility to obtain 
 * licenses to export, re-export or import the Software.

 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS" AND 
 * WITH ALL FAULTS AND CAVIUM MAKES NO PROMISES, REPRESENTATIONS OR WARRANTIES, 
 * EITHER EXPRESS,IMPLIED,STATUTORY, OR OTHERWISE, WITH RESPECT TO THE SOFTWARE,
 * INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR DESCRIPTION, 
 * OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM SPECIFICALLY 
 * DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE, MERCHANTABILITY, 
 * NONINFRINGEMENT,FITNESS FOR A PARTICULAR PURPOSE,LACK OF VIRUSES, ACCURACY OR
 * COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO 
 * DESCRIPTION. THE ENTIRE RISK ARISING OUT OF USE OR PERFORMANCE OF THE 
 * SOFTWARE LIES WITH YOU.
 *
 */


#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include "cavium_sysdep.h"
#include "cavium_common.h"
#include "cavium_ioctl.h"


/* Note: Currently for NITROXPX, IOCTL to read,
 * 		BAR0 mappings returns BAR4 memory-mapped address,
 * 		BAR1 mappings retutns BAR4 mem-mapped address + 0x100.
 */


unsigned long bar0, bar1;


/* Gets the BAR address mapping for Nitrox.
 */
int
pkpdbg_get_bars(int fd)
{
	DebugRWReg bar;

	bar.addr = 0x10;
    if (ioctl(fd, IOCTL_PCI_DEBUG_READ_CODE, &bar)) {
		printf("pkpdbg_get_bars(): ioctl() failed %s <%d>\n",
		       strerror(errno), errno);
		return 1;
	}
	bar0 = bar.data;
	printf("pkpdbg:  BAR0 @ %lx\n", bar0);


	bar.addr = 0x18;
    if (ioctl(fd, IOCTL_PCI_DEBUG_READ_CODE, &bar)) {
		printf("pkpdbg_get_bars(): ioctl() failed %s <%d>\n",
		       strerror(errno), errno);
		return 1;
	}
	bar1 = bar.data;
	printf("pkpdbg:  BAR1 @ %lx\n", bar1);
	return 0;
}




/* Reads a string from user in the format <bar_num:offset> and returns
 * the actual address to read the required register.
 */
unsigned long
pkpdbg_get_address()
{
	int             bar, i=0;
	unsigned long   address;
	char             s[80], s_bar[10];

	printf("Enter Address as BAR:Offset (e.g. 0:0x20 for BAR0:0x20)\n");
	scanf("%s", s);
	while(s[i] != ':') {
		s_bar[i] = s[i];
		i++;
	}
	s_bar[i] = '\0';		
	i++;
	
	bar = strtoul(s_bar, NULL, 16);
	if(bar != 0 && bar != 1) {
		printf("pkpdbg: Error! Invalid Bar: %d\n", bar);
		return ((unsigned long) -1);
	}

	address = strtoul((s + i), NULL, 16);

	/* If BAR0 is selected, return the BAR0-mapped offset */
	if(bar == 0)
		return (address + bar0);

	/* Else return the BAR1-mapped offset. */
	return (address + bar1);
}







int main(void)
{
	char s[80];
	int file_desc = -1;
	unsigned char c;
	unsigned long address, dwval;
	DebugRWReg dw;


	printf("\nPKP DEBUG PROGRAM.\n Cavium Networks.\n\n");

	/* open device driver */
	file_desc = open("/dev/pkp_dev", 0);
	if (file_desc < 0) {
		printf("Couldn't open device pkp_driver\n");
		return 1;
	}

	if(pkpdbg_get_bars(file_desc))
		return 1;


	while(1) {
		dw.addr = 0;
		dw.data=0;
		printf("\nEnter 'r' to read pkp register\n");
		printf("Enter 'w' to write pkp register\n");
		printf("Enter 'R' to read PCI config register.\n");
		printf("Enter 'W' to write PCI config register\n"); 
		printf("Enter 's' to do CSP soft reset.\n");       
		printf("Enter 'x' to exit.\n");

		printf("\nEnter the required operation: ");
		scanf("%c", &c);
		switch(c) {
			case 'r':
				dwval = 0;
				dw.addr = pkpdbg_get_address();	
				if(dw.addr == (unsigned long)-1) 
					continue;
				printf("\nRead register at address 0x%lx\n", dw.addr); 
				ioctl(file_desc,IOCTL_N1_DEBUG_READ_CODE,&dw);
				printf("\nValue is 0x%08x\n", dw.data);
				break;
	
			case 'w':
				dwval = 0;
				dw.addr = pkpdbg_get_address();
				if(dw.addr == (unsigned long)-1) 
					continue;
				printf("\n Please enter data (hex): ");
				scanf("%s", s);
				dw.data = strtoul((char *)s,NULL,16);
				printf("\nWrite register at address 0x%lx with 0x%lx\n",
				       dw.addr,dw.data);
				ioctl(file_desc,IOCTL_N1_DEBUG_WRITE_CODE,&dw);  
				break;

			case 'R':
				dwval = 0;
				printf("\n Please enter address (hex): ");
				scanf("%s", s);
				dw.addr = strtoul((char *)s,NULL,16);
				printf("\nRead register at address %x\n", dw.addr); 
				ioctl(file_desc,IOCTL_PCI_DEBUG_READ_CODE,&dw);
				printf("\nValue is %x\n", dw.data);
				break;

			case 'W':
				dwval = 0;
				printf("\n Please enter address (hex): ");
				scanf("%s", s);
				dw.addr = strtoul((char *)s,NULL,16);
				printf("\n Please enter data (hex): ");
				scanf("%s", s);
				dw.data = strtoul((char *)s,NULL,16);
				printf("\nWrite PCI config register at address %x with %x\n",
				       dw.addr,dw.data);
				ioctl(file_desc,IOCTL_PCI_DEBUG_WRITE_CODE ,&dw);  
				break;
		
			case 'x':
			case 'X':
				printf("\n Exiting ...\n");
				close(file_desc);
				return 0;

			default:
				break;
		} 
	}
}


/*
 * $Id: pkpdbg.c,v 1.2 2008/12/18 15:16:54 jsrikanth Exp $
 * $Log: pkpdbg.c,v $
 * Revision 1.2  2008/12/18 15:16:54  jsrikanth
 * pci BAR addr related changes and device count ioctl changes
 *
 * Revision 1.1  2007/02/20 23:43:29  panicker
 * * Utilities checked in
 *
 * Revision 1.5  2005/09/27 05:20:24  sgadam
 * Warning fixed
 *
 * Revision 1.4  2005/08/31 17:22:13  bimran
 * Fixed warnings.
 *
 * Revision 1.3  2005/02/01 04:12:33  bimran
 * copyright fix
 *
 * Revision 1.2  2004/05/02 19:46:19  bimran
 * Added Copyright notice.
 *
 * Revision 1.1  2004/04/15 22:40:51  bimran
 * Checkin of the code from India with some cleanups.
 *
 */

