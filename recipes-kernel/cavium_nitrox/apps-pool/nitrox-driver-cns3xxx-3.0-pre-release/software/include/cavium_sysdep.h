#if !defined (__CAVIUM_SYSDEP_H__)
#define __CAVIUM_SYSDEP_H__

#if defined (_WIN32)
#include "windows_sysdep.h"
#elif defined (linux)
#include "linux_sysdep.h"
#elif defined (__FreeBSD__)
#include "freebsd_sysdep.h"
#elif defined (__NetBSD__)
#include "netbsd_sysdep.h"
#else
#include "custom_sysdep.h"
#endif

#endif
