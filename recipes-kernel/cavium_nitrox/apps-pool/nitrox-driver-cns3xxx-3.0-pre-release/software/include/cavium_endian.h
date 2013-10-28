#if !defined (__CAVIUM_ENDIAN_H__)
#define __CAVIUM_ENDIAN_H__

#if defined (_X86_) || defined (i386) || defined (i686)
#include "cavium_le.h"
#elif defined (mips) || defined (ppc)
#include "cavium_be.h"
#elif defined(__amd64__) || defined (_AMD64_) || defined (AMD64)
#include "cavium_le.h"
#elif defined(__i386__) || defined (_IA64_) || defined (IA64)
#include "cavium_le.h"
#elif defined(PPC) || defined (__PPC__) || defined(powerpc)
#include "cavium_be.h"
#else
#include "cavium_le.h"
#endif

#endif
