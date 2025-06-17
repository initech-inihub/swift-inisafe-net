#ifndef _COMMON_H_
#define _COMMON_H_

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WINDOWS
#include <strings.h>
#include <pthread.h>
#endif

#include <ctype.h>
#include <time.h>

#define SP 0x20
/* #define TAB 0x09 */
#define TAB '\t'

#define upper 0xF0
#define lower 0x0F

#define MAX_BUFFER 8192
#define KEY_LEN 16
#define ENC_SKEY_LEN 175

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned long u32;

/* Prototypes for compress.c */

#ifndef _WIN32_LOADLOBRARY_CORE_
INISAFECORE_API void ICL_SetCheckFlag(int start, int end, char *check, int flag);
INISAFECORE_API int ICL_SetBlankPattern (char *data, char *check, int size);
INISAFECORE_API int ICL_SetNumericPattern  (char *data, char *check, int size);
INISAFECORE_API int ICL_SetAlphaNumericCasePattern (char *data, char *check, int size);
INISAFECORE_API int ICL_SetLowerCasePattern (char *data, char *check, int size);
INISAFECORE_API int ICL_SetUpperCasePattern (char *data, char *check, int size);
INISAFECORE_API int ICL_SetControlASCIIPattern (char *data, char *check, int size);
INISAFECORE_API int ICL_SetControlFrontPattern (char *data, char *check, int size);
INISAFECORE_API int ICL_SetControlTailPattern (char *data, char *check, int size);
INISAFECORE_API int ICL_SetBinaryFrontPattern (char *data, char *check, int size);
INISAFECORE_API int ICL_SetBinaryTailPattern (char *data, char *check, int size);
INISAFECORE_API int ICL_SetBinaryPattern (char *data, char *check, int size);
INISAFECORE_API int ICL_Decompress(char *data, int size, char *outdata);
INISAFECORE_API int ICL_CompressPattern2(char *data, int start, int end, int *pos, char *zipdata);
INISAFECORE_API int ICL_Compress(char *data, char *check, int size, char *outdata);
INISAFECORE_API int ICL_CompressData(char *data, char *check, int size, char *outdata);
#else
INI_VOID_LOADLIB_CORE(void, ICL_SetCheckFlag, (int start, int end, char *check, int flag), (start,end,check,flag) );
INI_RET_LOADLIB_CORE(int, ICL_SetBlankPattern, (char *data, char *check, int size), (data,check,size), -10000);
INI_RET_LOADLIB_CORE(int, ICL_SetNumericPattern, (char *data, char *check, int size), (data,check,size), -10000);
INI_RET_LOADLIB_CORE(int, ICL_SetAlphaNumericCasePattern, (char *data, char *check, int size), (data,check,size), -10000);
INI_RET_LOADLIB_CORE(int, ICL_SetLowerCasePattern, (char *data, char *check, int size), (data,check,size), -10000);
INI_RET_LOADLIB_CORE(int, ICL_SetUpperCasePattern, (char *data, char *check, int size), (data,check,size), -10000);
INI_RET_LOADLIB_CORE(int, ICL_SetControlASCIIPattern, (char *data, char *check, int size), (data,check,size), -10000);
INI_RET_LOADLIB_CORE(int, ICL_SetControlFrontPattern, (char *data, char *check, int size), (data,check,size), -10000);
INI_RET_LOADLIB_CORE(int, ICL_SetControlTailPattern, (char *data, char *check, int size), (data,check,size), -10000);
INI_RET_LOADLIB_CORE(int, ICL_SetBinaryFrontPattern, (char *data, char *check, int size), (data,check,size), -10000);
INI_RET_LOADLIB_CORE(int, ICL_SetBinaryTailPattern, (char *data, char *check, int size), (data,check,size), -10000);
INI_RET_LOADLIB_CORE(int, ICL_SetBinaryPattern, (char *data, char *check, int size), (data,check,size), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Decompress, (char *data, int size, char *outdata), (data,size,outdata), -10000);
INI_RET_LOADLIB_CORE(int, ICL_CompressPattern2, (char *data, int start, int end, int *pos, char *zipdata), (data,start,end,pos,zipdata), -10000);
INI_RET_LOADLIB_CORE(int, ICL_Compress, (char *data, char *check, int size, char *outdata), (data,check,size,outdata), -10000);
INI_RET_LOADLIB_CORE(int, ICL_CompressData, (char *data, char *check, int size, char *outdata), (data,check,size,outdata), -10000);
#endif

/* Prototypes for base128.c */
/*int base128Encoding(const u8 *in, int inl, int limit, u8 **out); */
/*int base128Decoding(const u8 *in, int inl, u8 **out);            */
#ifdef  __cplusplus
}
#endif
#endif
