/*!
* \file types.h
* \brief 기본 변수 타입을 시스템에 따라 정의
* \remarks
* \author sungwook.jang@initech.com
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_TYPE_H
#define HEADER_TYPE_H

#ifdef ISC_BADA
typedef unsigned int 		DWORD;
#ifndef __GNUC__
#define stderr 0
#endif
#endif

#if defined(WIN32) || defined(_WIN32) || defined(_WIN32_WCE) || defined(ISC_BADA)

#define SIZEOF_CHAR 1
#define SIZEOF_INT 4
#define SIZEOF_LONG 4
#define SIZEOF_LONG_LONG 8
#define SIZEOF_VOIDP  4
#define SIZEOF_SHORT 2
#define SIZEOF_SIZE_T 4
#define SIZEOF_UNSIGNED_INT 4
#define SIZEOF_UNSIGNED_LONG 4
#define SIZEOF_UNSIGNED_LONG_LONG 8

#elif defined(WIN64) || defined(_WIN64)

#define SIZEOF_CHAR 1
#define SIZEOF_INT 4
#define SIZEOF_LONG 4
#define SIZEOF_LONG_LONG 8
#define SIZEOF_VOIDP  8
#define SIZEOF_SHORT 2
#define SIZEOF_SIZE_T 8
#define SIZEOF_UNSIGNED_INT 4
#define SIZEOF_UNSIGNED_LONG 4
#define SIZEOF_UNSIGNED_LONG_LONG 8

#else  /* Unix (not WINDOWS OR not BADA) */
/* 
 * If you change these definitions, also check in configure.in, config.in.h
 */
#ifndef IOS
#include "config.h"
#else
#include "config_ios.h"
#endif

#if defined(HAVE_STDINT_H)
#include <stdint.h>
#endif
#if defined(HAVE_UNISTD_H)
#if !defined(MACOS)
#include <unistd.h>
#endif
#endif
#if defined(HAVE_STRING_H)
#if !defined(MACOS)
#include <string.h>
#endif
#endif
#if defined(HAVE_SYS_TIME_H)
#include <sys/time.h>
#endif
#if defined(HAVE_SYS_TYPES_H)
#if !defined(MACOS)
#include <sys/types.h>
#endif
#endif
#if defined(HAVE_SYS_RESOURCE_H)
#include <sys/resource.h>
#endif
#if defined(HAVE_BSD_LIBC_H)
#include <bsd/libc.h>
#endif
#if defined(HAVE_KERNEL_OS_H)
#include <kernel/OS.h>
#endif

#undef	__NORETURN__
#if defined(__GNUC__)
#define	__NORETURN__ __attribute__((__noreturn__))
#else
#define	__NORETURN__
#endif

#undef	__UNUSED__
#if defined(__GNUC__)
#define	__UNUSED__ __attribute__((__unused__))
#else
#define	__UNUSED__
#endif

#endif /* end of !defined(WIN32) && !defined(_WIN32) && !def ........ */

#if !defined(MACOS)
	#include <stdio.h>
	#include <stdlib.h>
	#include <assert.h>
#endif

#if !defined(HAVE_INT8_T)
	#if defined(ISC_WSAPP)
		typedef	signed char					int8_t;
	#else
		#if defined(WIN32)
			#if (_MSC_VER < 1300)
				typedef	char				int8_t;
			#else
				typedef signed __int8		int8_t;
			#endif
		#else
				typedef	char				int8_t;
		#endif
	#endif
#endif


#if !defined(HAVE_UINT8_T)
	#if defined(WIN32)
		#if (_MSC_VER < 1300)
			typedef	unsigned char			uint8_t;
		#else
			typedef unsigned __int8			uint8_t;
		#endif
	#else
			typedef	unsigned char			uint8_t;
	#endif
#endif

#if SIZEOF_SHORT == 2
	#if !defined(HAVE_INT16_T)
		#if defined(WIN32)
			#if (_MSC_VER < 1300)
				typedef	short				int16_t;
			#else
				typedef signed __int16		int16_t;
			#endif
		#else
			typedef	short					int16_t;
		#endif
	#endif
	#if !defined(HAVE_UINT16_T)
		#if defined(WIN32)
			#if (_MSC_VER < 1300)
				typedef	unsigned short		uint16_t;
			#else
				typedef unsigned __int16	uint16_t;
			#endif
		#else
			typedef	unsigned short			uint16_t;
		#endif
	#endif
#else
	#error "sizeof(short) must be 2"
#endif

#if SIZEOF_INT == 4
	#if !defined(HAVE_INT32_T)
		#if defined(WIN32)
			#if (_MSC_VER < 1300)
				typedef	int					int32_t;
			#else
				typedef signed __int32		int32_t;
			#endif
		#else
			typedef	int						int32_t;
		#endif
	#endif
	#if !defined(HAVE_UINT32_T)
		#if defined(WIN32)
			#if (_MSC_VER < 1300)
				typedef	unsigned int		uint32_t;
			#else
				typedef unsigned __int32	uint32_t;
			#endif
		#else
			typedef	unsigned int			uint32_t;
		#endif
	#endif
#elif SIZEOF_LONG == 4
	#if !defined(HAVE_INT32_T)
		typedef	long						int32_t;
	#endif
	#if !defined(HAVE_UINT32_T)
		typedef	unsigned long				uint32_t;
	#endif
#else
	#error "sizeof(int) or sizeof(long) must be 4"
#endif

#if SIZEOF_LONG == 8
	#if !defined(HAVE_INT64_T)
		typedef	long						int64_t;
	#endif
	#if !defined(HAVE_UINT64_T)
		typedef	unsigned long				uint64_t;
	#endif
#elif SIZEOF_LONG_LONG == 8
	#if !defined(HAVE_INT64_T)
		#if defined(WIN32) || defined(_WIN32) || defined(_WIN32_WCE) || defined(ISC_BADA)
			typedef __int64					int64_t;
		#else
			typedef	long long				int64_t;
		#endif
	#endif
	#if !defined(HAVE_UINT64_T)
		#if defined(WIN32) || defined(_WIN32) || defined(_WIN32_WCE) || defined(ISC_BADA)
			typedef unsigned __int64		uint64_t;
		#else
			typedef	unsigned long long		uint64_t;
		#endif
	#endif
#elif SIZEOF___INT64 == 8
	#if !defined(HAVE_INT64_T)
		typedef	__int64						int64_t;
	#endif
	#if !defined(HAVE_UINT64_T)
		typedef	unsigned __int64			uint64_t;
	#endif
#else
	#error "sizeof(long) or sizeof(long long) or sizeof(__int64) must be 8"
#endif

typedef int8_t								int8;
typedef int16_t								int16;
typedef int32_t								int32;
typedef int64_t								int64;
typedef uint8_t								uint8;
typedef uint16_t							uint16;
typedef uint32_t							uint32;
typedef uint64_t							uint64;

#if SIZEOF_VOIDP == 4 || defined(LINUX) || defined(MACOS) || defined(IOS) || defined(ANDROID)
	typedef signed int						intptr;
	typedef unsigned int					uintptr;
#elif SIZEOF_VOIDP == 8
	typedef signed long						intptr;
	typedef unsigned long					uintptr;
#else
	#error "sizeof(void*) must be 4 or 8"
#endif

#if SIZEOF_CHAR == 1
	typedef char							byte8;
#else
	#error "sizeof(char) must be 1"
#endif

/* 
 * status code of INISAFE Package
 */
typedef uint32 ISC_STATUS; 		/*!< 성공,에러코드 타입 */

#endif /* HEADER_TYPE_H */
