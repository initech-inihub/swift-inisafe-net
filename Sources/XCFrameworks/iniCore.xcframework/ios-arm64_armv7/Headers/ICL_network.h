#ifndef INITECH_COMMON_BYTE_H
#define INITECH_COMMON_BYTE_H

#ifdef _INI_BADA
#include "ICL_bada.h"
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef INISAFECORE_API
#if defined(WIN32) || defined(_WIN32_WCE)
	#ifdef INISAFECORE_EXPORTS
	#define INISAFECORE_API __declspec(dllexport)
	#else
	#define INISAFECORE_API __declspec(dllimport)
	#endif
#else
	#define INISAFECORE_API
#endif
#endif

#include <string.h>

#ifndef _WINDOWS
#include <pthread.h>
#endif


#if !defined(AIX) && !defined(WIN32)
typedef char           int_8;
typedef short          int_16;
#endif

#if !defined(AIX)
typedef int            int32;
typedef unsigned char  uchar;
#endif

typedef unsigned char  u_int8;
typedef unsigned short u_int16;
typedef unsigned int   u_int32;
/*******************************************************
 *                                                     *
 * definitions for MACRO functions                     *
 *                                                     *
 *******************************************************/
#define M_MIN(a,b)  (((a) < (b)) ? (a) : (b))
#define M_MAX(a,b)  (((a) > (b)) ? (a) : (b))
#define M_MUL_GT(a,b) ((a) + (b) - ((a) % (b)))
#define M_MUL_LT(a,b) ((a) - ((a) % (b)))
#define M_DIV_ROUNDDOWN(n,s) ((n) / (s))
#define M_DIV_ROUNDUP(n,s)   (((n) / (s)) + ((((n) % (s)) > 0) ? 1 : 0))

/*******************************************************
 *                                                     *
 * definitions for MACRO BIT functions                 *
 *                                                     *
 *******************************************************/
#define M_BIT_AND(a, b)     ((a) & (b))
#define M_BIT_OR(a, b)      ((a) | (b))
#define M_BIT_XOR(a, b)     ((a) ^ (b))
#define M_BIT_NOT(a)        (~(a))
#define M_BIT_SET(a, b)     ((a) |= (b))
#define M_BIT_UNSET(a, b)   ((a) &= M_BIT_NOT(b))
#define M_BIT_IS_ANY_SET(a, b)   (M_BIT_AND(a, b))
#define M_BIT_IS_ALL_SET(a, b)   ((M_BIT_AND(a, b)) == (b))
#define M_BIT_IS_ANY_UNSET(a, b) ((M_BIT_AND(a, b)) != (b))
#define M_BIT_IS_ALL_UNSET(a, b) (!M_BIT_IS_ANY_SET(a,b))

#define M_BITS_PER_BYTE (8)
#define M_BIT2BYTE(bit)  (M_DIV_ROUNDUP((bit), M_BITS_PER_BYTE))
#define M_BYTE2BIT(byte) ((byte) * M_BITS_PER_BYTE)

/*******************************************************
 *                                                     *
 * definitions for HEX functions                       *
 *                                                     *
 *******************************************************/
/*
void uchar2hex(uchar c, char h[2]);
uchar hex2uchar(char h[2]);
*/
INISAFECORE_API void ICL_Uchar2Hex(uchar c, char v[2]);
INISAFECORE_API uchar ICL_Hex2Uchar(char v[2]);


/*******************************************************
 *                                                     *
 * definitions for BYTE ORDER functions                *
 *   ERROR: -1                                         *
 *   SUCC : sizeof(type)                               *
 *******************************************************/
/*
int32 hton_short(unsigned short host, uchar *buf, int bufsize);
int32 ntoh_short(uchar *buf, int bufl, unsigned short *host);
int32 hton_int(unsigned int host, uchar *buf, int bufsize);
int32 ntoh_int(uchar *buf, int bufl, unsigned int *host);
int32 hton_double(double host, uchar *buf, int bufsize);
int32 ntoh_double(uchar *buf, int bufl, double *host);
int32 hton_float(float host, uchar *buf, int bufsize);
int32 ntoh_float(uchar *buf, int bufl, float *host);
int32 hton_int16(uint16 host, uchar *buf, int bufsize);
int32 ntoh_int16(uchar *buf, int bufl, uint16 *host);
int32 hton_int32(uint32 host, uchar *buf, int bufsize);
int32 ntoh_int32(uchar *buf, int bufl, uint32 *host);
*/
#ifndef _WIN32_LOADLOBRARY_CORE_
INISAFECORE_API int32 ICL_HtonShort(unsigned short host, uchar *buf, int bufsize);
INISAFECORE_API int32 ICL_NtohShort(uchar *buf, int bufl, unsigned short *host);
INISAFECORE_API int32 ICL_HtonInt(unsigned int host, uchar *buf, int bufsize);
INISAFECORE_API int32 ICL_NtohInt(uchar *buf, int bufl, unsigned int *host);
INISAFECORE_API int32 ICL_HtonDouble(double host, uchar *buf, int bufsize);
INISAFECORE_API int32 ICL_NtohDouble(uchar *buf, int bufl, double *host);
INISAFECORE_API int32 ICL_HtonFloat(float host, uchar *buf, int bufsize);
INISAFECORE_API int32 ICL_NtohFloat(uchar *buf, int bufl, float *host);
INISAFECORE_API int32 hton_int16(u_int16 host, uchar *buf, int bufsize);
INISAFECORE_API int32 hton_int16(u_int16 host, uchar *buf, int bufsize);
INISAFECORE_API int32 ICL_NtohInt16(uchar *buf, int bufl, u_int16 *host);
INISAFECORE_API int32 ICL_HtonInt32(u_int32 host, uchar *buf, int bufsize);
INISAFECORE_API int32 ICL_NtohInt32(uchar *buf, int bufl, u_int32 *host);
#else
INI_VOID_LOADLIB_CORE(void, ICL_Uchar2Hex, (uchar c, char v[2]), (c,v[2]) );
INI_RET_LOADLIB_CORE(uchar, ICL_Hex2Uchar, (char v[2]), (v[2]), -10000);
INI_RET_LOADLIB_CORE(int32, ICL_HtonShort, (unsigned short host, uchar *buf, int bufsize), (host,buf,bufsize), -10000);
INI_RET_LOADLIB_CORE(int32, ICL_NtohShort, (uchar *buf, int bufl, unsigned short *host), (buf,bufl,host), -10000);
INI_RET_LOADLIB_CORE(int32, ICL_HtonInt, (unsigned int host, uchar *buf, int bufsize), (host,buf,bufsize), -10000);
INI_RET_LOADLIB_CORE(int32, ICL_NtohInt, (uchar *buf, int bufl, unsigned int *host), (buf,bufl,host), -10000);
INI_RET_LOADLIB_CORE(int32, ICL_HtonDouble, (double host, uchar *buf, int bufsize), (host,buf,bufsize), -10000);
INI_RET_LOADLIB_CORE(int32, ICL_NtohDouble, (uchar *buf, int bufl, double *host), (buf,bufl,host), -10000);
INI_RET_LOADLIB_CORE(int32, ICL_HtonFloat, (float host, uchar *buf, int bufsize), (host,buf,bufsize), -10000);
INI_RET_LOADLIB_CORE(int32, ICL_NtohFloat, (uchar *buf, int bufl, float *host), (buf,bufl,host), -10000);
INI_RET_LOADLIB_CORE(int32, hton_int16, (u_int16 host, uchar *buf, int bufsize), (host,buf,bufsize), -10000);
INI_RET_LOADLIB_CORE(int32, hton_int16, (u_int16 host, uchar *buf, int bufsize), (host,buf,bufsize), -10000);
INI_RET_LOADLIB_CORE(int32, ICL_NtohInt16, (uchar *buf, int bufl, u_int16 *host), (buf,bufl,host), -10000);
INI_RET_LOADLIB_CORE(int32, ICL_HtonInt32, (u_int32 host, uchar *buf, int bufsize), (host,buf,bufsize), -10000);
INI_RET_LOADLIB_CORE(int32, ICL_NtohInt32, (uchar *buf, int bufl, u_int32 *host), (buf,bufl,host), -10000);
#endif

#ifdef  __cplusplus
}
#endif

#endif /* INITECH_COMMON_BYTE_H */
