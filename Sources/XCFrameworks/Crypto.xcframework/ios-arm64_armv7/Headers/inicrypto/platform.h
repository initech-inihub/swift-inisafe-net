/*!
* \file platform.h
* \brief platform Á¤ÀÇ
* \remarks
* \author sungwook.jang@initech.com
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_PLATFROM_H
#define HEADER_PLATFROM_H


/* Platform Identification */
#define ISC_OS_FREE_BSD      0x0001
#define ISC_OS_AIX           0x0002
#define ISC_OS_HPUX          0x0003
#define ISC_OS_TRU64         0x0004
#define ISC_OS_LINUX         0x0005
#define ISC_OS_MAC_OS_X      0x0006
#define ISC_OS_BSD			 0x0007
#define ISC_OS_OPEN_BSD      0x0008
#define ISC_OS_IRIX          0x0009
#define ISC_OS_SOLARIS       0x000a
#define ISC_OS_QNX           0x000b
#define ISC_OS_VXWORKS       0x000c
#define ISC_OS_CYGWIN        0x000d
#define ISC_OS_IOS           0x000e
#define ISC_OS_UNKNOWN_UNIX  0x00ff
#define ISC_OS_WINDOWS_NT    0x1001
#define ISC_OS_WINDOWS_CE    0x1011
#define ISC_OS_WSAPP         0x1012
#define ISC_OS_ANDROID       0x1013
#define ISC_OS_VMS           0x2001


#if defined(__FreeBSD__)
	#define ISC_OS_FAMILY_UNIX 1
	#define ISC_OS_FAMILY_BSD 1
	#define ISC_OS_MEMBER_FREEBSD 1
	#define ISC_OS ISC_OS_FREE_BSD
#elif defined(_AIX) || defined(__TOS_AIX__) || defined(AIX)
	#define ISC_OS_FAMILY_UNIX 1
	#define ISC_OS_MEMBER_AIX 1
	#define ISC_OS ISC_OS_AIX
#elif defined(HPUX) || defined(hpux) || defined(_hpux)
	#define ISC_OS_FAMILY_UNIX 1
	#define ISC_OS_MEMBER_HPUX 1
	#define ISC_OS ISC_OS_HPUX
#elif defined(__digital__) || defined(__osf__)
	#define ISC_OS_FAMILY_UNIX 1
	#define ISC_OS_MEMBER_TRU64 1
	#define ISC_OS ISC_OS_TRU64
#elif defined(ANDROID)
    #define ISC_OS_FAMILY_UNIX 1
    #define ISC_OS_MEMBER_ANDROID 1
    #define ISC_OS_MEMBER_LINUX 1
    #define ISC_OS ISC_OS_ANDROID
#elif defined(linux) || defined(__linux) || defined(__linux__) || defined(__TOS_LINUX__) || defined(LINUX)
	#define ISC_OS_FAMILY_UNIX 1
	#define ISC_OS_MEMBER_LINUX 1
	#define ISC_OS ISC_OS_LINUX
	#if defined(_OTHERS)
	#define ISC_OS_FAMILY_OTHERS 1
	#endif
#elif  defined(MACOS) /*|| defined(__APPLE__)*/ || defined(__TOS_MACOS__)
	#define ISC_OS_FAMILY_UNIX 1
	#define ISC_OS_MEMBER_MAC 1
	#define ISC_OS ISC_OS_MAC_OS_X
#elif defined(IOS)
    #define ISC_OS_FAMILY_UNIX 1
    #define ISC_OS_MEMBER_IOS 1
    #define ISC_OS ISC_OS_IOS
#elif defined(__NetBSD__)
	#define ISC_OS_FAMILY_UNIX 1
	#define ISC_OS_FAMILY_BSD 1
	#define ISC_OS_MEMBER_NETBSD 1
	#define ISC_OS ISC_OS_BSD
#elif defined(__OpenBSD__)
	#define ISC_OS_FAMILY_UNIX 1
	#define ISC_OS_FAMILY_BSD 1
	#define ISC_OS_MEMBER_OPENBSD 1
	#define ISC_OS ISC_OS_OPEN_BSD
#elif defined(sgi) || defined(__sgi)
	#define ISC_OS_FAMILY_UNIX 1
	#define ISC_OS_MEMBER_SGI 1
	#define ISC_OS ISC_OS_IRIX
#elif defined(sun) || defined(__sun) || defined(SunOS)
	#define ISC_OS_FAMILY_UNIX 1
	#define ISC_OS_MEMBER_SOLARIS 1
	#define ISC_OS ISC_OS_SOLARIS
#elif defined(__QNX__)
	#define ISC_OS_FAMILY_UNIX 1
	#define ISC_OS_MEMBER_QNX 1
	#define ISC_OS ISC_OS_QNX
#elif defined(unix) || defined(__unix) || defined(__unix__)
	#define ISC_OS_FAMILY_UNIX 1
	#define ISC_OS_MEMBER_UNKNOWN_UNIX 1
	#define ISC_OS ISC_OS_UNKNOWN_UNIX
#elif defined(ISC_WSAPP)
	#define ISC_OS_FAMILY_WINDOWS 1
	#define ISC_OS ISC_OS_WSAPP
#elif defined(_WIN32_WCE)
	#define ISC_OS_FAMILY_WINDOWS 1
	#define ISC_OS ISC_OS_WINDOWS_CE
#elif (defined(_WIN32) || defined(_WIN64)) && !defined(ISC_BADA)
	#define ISC_OS_FAMILY_WINDOWS 1
	#define ISC_OS ISC_OS_WINDOWS_NT
#elif defined(__CYGWIN__)
	#define ISC_OS_FAMILY_UNIX 1
	#define ISC_OS_MEMBER_CYGWIN 1
	#define ISC_OS ISC_OS_CYGWIN
#elif defined(__VMS)
	#define ISC_OS_FAMILY_VMS 1
	#define ISC_OS_MEMBER_VMS 1
	#define ISC_OS ISC_OS_VMS
#elif defined(ISC_BADA)
	#define ISC_OS_BADA 1
#endif



/* Hardware Architecture and Byte Order*/
#define ISC_ARCH_ALPHA   0x01
#define ISC_ARCH_IA32    0x02
#define ISC_ARCH_IA64    0x03
#define ISC_ARCH_MIPS    0x04
#define ISC_ARCH_HPPA    0x05
#define ISC_ARCH_PPC     0x06
#define ISC_ARCH_POWER   0x07
#define ISC_ARCH_SPARC   0x08
#define ISC_ARCH_AMD64   0x09
#define ISC_ARCH_ARM     0x0a

#if defined WIN32 || defined (WINCE)
#define ISC_ARCH_LITTLE_ENDIAN 1
#else
#ifdef B_ENDIAN
	#define ISC_ARCH_BIG_ENDIAN 1
#else
	#ifndef L_ENDIAN
	#error In order to compile this, you have to   \
		define either L_ENDIAN or B_ENDIAN.   \
	If unsure, try define either of one and run   \
	checkEndian() function to see if your guess   \
	is correct.
	#endif
	
	#define ISC_ARCH_LITTLE_ENDIAN 1
#endif
#endif


/********************
#if defined(__ALPHA) || defined(__alpha) || defined(__alpha__) || defined(_M_ALPHA)
	#define INI_ARCH ISC_ARCH_ALPHA
	#define ISC_ARCH_LITTLE_ENDIAN 1
#elif ((defined(i386) || defined(__i386) || defined(__i386__) || defined(_M_IX86))) && !defined(ISC_BADA)
	#define INI_ARCH ISC_ARCH_IA32
	#define ISC_ARCH_LITTLE_ENDIAN 1
#elif defined(_IA64) || defined(__IA64__) || defined(__ia64__) || defined(__ia64) || defined(_M_IA64)
	#define INI_ARCH ISC_ARCH_IA64
	#if defined(hpux) || defined(_hpux)
		#define ISC_ARCH_BIG_ENDIAN 1
	#else
		#define ISC_ARCH_LITTLE_ENDIAN 1
	#endif
#elif defined(__x86_64__)
	#define INI_ARCH ISC_ARCH_AMD64
	#define ISC_ARCH_LITTLE_ENDIAN 1
#elif defined(__mips__) || defined(__mips) || defined(__MIPS__) || defined(_M_MRX000)
	#define INI_ARCH ISC_ARCH_MIPS
	#define ISC_ARCH_BIG_ENDIAN 1
#elif defined(__hppa) || defined(__hppa__)
	#define INI_ARCH ISC_ARCH_HPPA
	#define ISC_ARCH_BIG_ENDIAN 1
#elif defined(__PPC) || defined(__POWERPC__) || defined(__powerpc) || defined(__PPC__) || \
      defined(__powerpc__) || defined(__ppc__) || defined(_ARCH_PPC) || defined(_M_PPC)
	#define INI_ARCH ISC_ARCH_PPC
	#define ISC_ARCH_BIG_ENDIAN 1
#elif defined(_POWER) || defined(_ARCH_PWR) || defined(_ARCH_PWR2) || defined(_ARCH_PWR3) || \
      defined(_ARCH_PWR4) || defined(__THW_RS6000)
	#define INI_ARCH ISC_ARCH_POWER
	#define ISC_ARCH_BIG_ENDIAN 1
#elif defined(__sparc__) || defined(__sparc) || defined(sparc)
	#define INI_ARCH ISC_ARCH_SPARC
	#define ISC_ARCH_BIG_ENDIAN 1
#elif defined(__arm__) || defined(__arm) || defined(ARM) || defined(_ARM_) || defined(__ARM__) || defined(_M_ARM)
	#define INI_ARCH ISC_ARCH_ARM
	#if defined(__ARMEB__)
		#define ISC_ARCH_BIG_ENDIAN 1
	#else
		#define ISC_ARCH_LITTLE_ENDIAN 1
	#endif
#endif
********************/

#endif /* HEADER_PLATFROM_H */

