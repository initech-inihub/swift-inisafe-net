/* include/inicrypto/config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.in by autoheader.  */

/******************************************************/
/* Define OS */
/******************************************************/
/* Define if AIX */
/* #undef AIX */

/* Define if BSDi */
/* #undef BSDI */

/* Define if FreeBSD */
/* #undef FREEBSD */

/* Define if HP-UX 10 or 11 */
/* #undef HPUX */

/* For INADDR_NONE definition */
/* #undef INADDR_NONE */

/* Define if Irix 6 */
/* #undef IRIX */

/* For libpcap versions that accumulate stats */
/* #undef LIBPCAP_ACCUMULATES */

/* Define if Linux */
/* #undef LINUX */

/* For Linux kernel 2.4.x */
/* #undef LINUX_24 */

/* For Linux libpcap versions 0.9.0 to 0.9.4 */
/* #undef LINUX_LIBPCAP_DOUBLES_STATS */

/* Define if MacOS */
//#define MACOS 1

/* Define if IOS */
/* #undef IOS */
#define IOS 1

/* Define if OpenBSD < 2.3 */
/* #undef OPENBSD */

/* Define if Tru64 */
/* #undef OSF1 */

/* Define if Solaris */
/* #undef SOLARIS */

/* For sparc v9 with %time register */
/* #undef SPARCV9 */

/* Define if SunOS */
/* #undef SunOS */


/******************************************************/
/* Define Endian */
/******************************************************/
/* Define if words are big endian */
/* #undef B_ENDIAN */

/* Define if words are little endian */
#define L_ENDIAN 1



/******************************************************/
/* Define Shared Library */
/******************************************************/
/* Define if build target is shared library */
/* config_ios.h에서 설정하지 않고 xCode 프로젝트 설정에서 동적, 정적을 설정한다. */
/* #define _SHARED_LIBRARY 1 */

/******************************************************/
/* Define DRBG */
/******************************************************/
/* No use DRBG */
/* #undef NO_DRBG */

/******************************************************/
/* Define Header file */
/******************************************************/
/* Define to 1 if you have the `snprintf' function. */
/* #undef HAVE_SNPRINTF */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcat' function. */
/* #undef HAVE_STRLCAT */

/* Define to 1 if you have the `strlcpy' function. */
/* #undef HAVE_STRLCPY */

/* Define to 1 if you have the `strtoul' function. */
/* #undef HAVE_STRTOUL */

/* Define to 1 if you have the <sys/sockio.h> header file. */
/* #undef HAVE_SYS_SOCKIO_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1


/******************************************************/
/* Define Size */
/******************************************************/
/* The number of bytes in a __int64.  */
/* #undef SIZEOF___INT64 */

/* The number of bytes in a char.  */
#define SIZEOF_CHAR 1

/* The number of bytes in a int.  */
#define SIZEOF_INT 4

/* The number of bytes in a short.  */
#define SIZEOF_SHORT 2

/* The number of bytes in a long.  */
#define SIZEOF_LONG 8

/* The number of bytes in a long long.  */
#define SIZEOF_LONG_LONG 8

/* The number of bytes in a void*.  */
#define SIZEOF_VOIDP 8


/******************************************************/
/* Define Type */
/******************************************************/
/* Define to 1 if the system has the type `u_char'. */
/* #undef HAVE_U_CHAR_T */

/* Define to 1 if the system has the type `int8_t'. */
#define HAVE_INT8_T 1

/* Define to 1 if the system has the type `uint8_t'. */
#define HAVE_UINT8_T 1

/* Define to 1 if the system has the type `int16_t'. */
#define HAVE_INT16_T 1

/* Define to 1 if the system has the type `uint16_t'. */
#define HAVE_UINT16_T 1

/* Define to 1 if the system has the type `int32_t'. */
#define HAVE_INT32_T 1

/* Define to 1 if the system has the type `uint32_t'. */
#define HAVE_UINT32_T 1

/* Define to 1 if the system has the type `int64_t'. */
#define HAVE_INT64_T 1

/* Define to 1 if the system has the type `uint64_t'. */
#define HAVE_UINT64_T 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1


/******************************************************/
/* Define Package INFO */
/******************************************************/
/* Define to the full name of this package. */
#define CRYPTO_NAME "INISAFE_Crypto_for_C"

/* Define to the version of this package. */
#define CRYPTO_VERSION "5.4.2"

/* Define to the full name and version of this package. */
//#define CRYPTO_STRING "libINISAFE_Crypto_for_C_v5.4.2_iOS.dylib"

/*XCFramework로 컴파일 할 경우 아래 경로에서 로드하게됨.*/
#define CRYPTO_STRING "libINISAFE_Crypto_for_C_v5.4.2_iOS.a"
 
/* Define to the one symbol short name of this package. */
#define CRYPTO_TARNAME "libINISAFE_Crypto_for_C_v5.4.2_Darwin_17.3_64.dylib.tar"

/* Define __FUNCTION__ as required. */
/* #undef __FUNCTION__ */

