#ifndef HEADER_ISC_ENDIAN_H__
#define HEADER_ISC_ENDIAN_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#ifndef __has_declspec_attribute
#define __has_declspec_attribute(x) 0
#endif

/* Inlining Macro */
#ifdef INLINE
	/* do nothing */
#elif defined(_MSC_VER)
#define INLINE __forceinline
#elif __has_attribute(always_inline)
#define INLINE inline __attribute__((always_inline)) 
#elif defined(__GNUC__)
#define INLINE inline __attribute__((always_inline)) 
#elif defined(__cplusplus)
#define INLINE inline
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define INLINE inline
#else
#define INLINE 
#endif

/* Check Endian */
#if defined(ISC_IS_LITTLE_ENDIAN)
	/* do Nothing */
#elif defined(__i386) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_X64)
#	define ISC_IS_LITTLE_ENDIAN 1
	/* Intel Architecture */
#elif defined(_MSC_VER)
#	define ISC_IS_LITTLE_ENDIAN 1
	/* All available "Windows" are Little-Endian except XBOX360. */
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && defined(__ORDER_LITTLE_ENDIAN__)
	/* GCC style */
	/* use __BYTE_ORDER__ */
#	if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#		define ISC_IS_LITTLE_ENDIAN 1
#	else
#		define ISC_IS_LITTLE_ENDIAN 0
#	endif
#elif defined(__BIG_ENDIAN__) || defined(__LITTLE_ENDIAN__)
	/* use __BIG_ENDIAN__ and __LITTLE_ENDIAN__ */
#	if defined(__LITTLE_ENDIAN__)
#		if __LITTLE_ENDIAN__
#			define ISC_IS_LITTLE_ENDIAN 1
#		else
#			define ISC_IS_LITTLE_ENDIAN 0
#		endif
#	elif defined(__BIG_ENDIAN__)
#		if __BIG_ENDIAN__
#			define ISC_IS_LITTLE_ENDIAN 0
#		else
#			define ISC_IS_LITTLE_ENDIAN 1
#		endif
#	endif
#else

/* use <endian.h> */
#	ifdef BSD
#		include <sys/endian.h>
#	else
#		ifndef ISC_OS_MEMBER_HPUX
#			ifndef ISC_OS_MEMBER_SOLARIS
#				include <endian.h>
#			endif
#		endif
#	endif

#	if __BYTE_ORDER__ == __LITTLE_ENDIAN
#		if defined(ISC_OS_MEMBER_HPUX) || defined(ISC_OS_MEMBER_SOLARIS)
#			define ISC_IS_LITTLE_ENDIAN 0
#		else
#			define ISC_IS_LITTLE_ENDIAN 1
#		endif
#	else
#		define ISC_IS_LITTLE_ENDIAN 0
#	endif

#endif

#if defined(ISC_LOAD_LE32) && defined(ISC_LOAD_LE64)
	/* do Nothing */
#elif ISC_IS_LITTLE_ENDIAN
	/*	little endian */
	#define ISC_LOAD_LE32(v)	(v)
	#define ISC_LOAD_LE64(v)	(v)
#else
/*	big endian */
#if defined(__GNUC__) && ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3))
#define ISC_LOAD_LE32(v)	__builtin_bswap32(v)
#define ISC_LOAD_LE64(v)	__builtin_bswap64(v)

#elif __has_builtin(__builtin_bswap32)

#define ISC_LOAD_LE32(v)	__builtin_bswap32(v)
#define ISC_LOAD_LE64(v)	__builtin_bswap64(v)
#else

#define ISC_LOAD_LE32(val) \
	( (((val) >> 24) & 0x000000FF) | (((val) >>  8) & 0x0000FF00) | \
	  (((val) <<  8) & 0x00FF0000) | (((val) << 24) & 0xFF000000) )

#define ISC_LOAD_LE64(val) \
	( (((val) >> 56) & 0x00000000000000FF) | (((val) >> 40) & 0x000000000000FF00) | \
	  (((val) >> 24) & 0x0000000000FF0000) | (((val) >>  8) & 0x00000000FF000000) | \
	  (((val) <<  8) & 0x000000FF00000000) | (((val) << 24) & 0x0000FF0000000000) | \
	  (((val) << 40) & 0x00FF000000000000) | (((val) << 56) & 0xFF00000000000000) )

#endif
#endif


#ifdef __cplusplus
}
#endif

#endif