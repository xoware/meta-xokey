#if !defined (__CAVIUM_IOCTL_H__)
#define __CAVIUM_IOCTL_H__

#if defined (_WIN32)
#include "windows_ioctl.h"
#elif defined (linux)
#include "linux_ioctl.h"
#elif defined (__FreeBSD__)
#include "freebsd_ioctl.h"
#elif defined (__NetBSD__)
#include "netbsd_ioctl.h"
#else
#include "custom_ioctl.h"
#endif

#endif
