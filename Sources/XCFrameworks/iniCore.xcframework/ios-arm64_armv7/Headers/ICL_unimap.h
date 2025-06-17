/*============================================================
 * (c) 2007 INITECH Company co,.LTD
 *
 * Module Name    : unimap.h
 * Description    : export용 header file
 * Developer      :
 * Date           : 2007-07-29
 * Version        : 1.0
 * Remark         :
 *
 * ----------------------------------------------------------------
 * Date        Developer   Description
 * ----------------------------------------------------------------
 * 1998-01-01     정주원   1.0 support KSC-5601 hangul
 * 2000-01-01     권용철   1.1 support special characters and chineses
 * =============================================================== */
#ifndef _NO_UNIHAN_

#ifndef _UNIMAP_H_
#define _UNIMAP_H_

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

#ifndef _WINDOWS
#include <pthread.h>
#endif

#ifndef _WIN32_LOADLOBRARY_CORE_
INISAFECORE_API int ICL_IsOnlyUTF8(const char *s);
INISAFECORE_API int ICL_IsOnlyDBCS(const char *s);
INISAFECORE_API int ICL_IsOnlyASCII(const char *s);
INISAFECORE_API char *ICL_ConvertUTF8ToEUCKR(const char *u);
INISAFECORE_API char *ICL_ConvertEUCKRToUTF8(const char *k);
INISAFECORE_API char *ICL_ConvertUCS2ToEUCKR(const char *u,int l);
INISAFECORE_API char *ICL_ConvertEUCKRToUCS2(const char *k,int *l);
#else
INI_RET_LOADLIB_CORE(int, ICL_IsOnlyUTF8, (const char *s), (s), -10000);
INI_RET_LOADLIB_CORE(int, ICL_IsOnlyDBCS, (const char *s), (s), -10000);
INI_RET_LOADLIB_CORE(int, ICL_IsOnlyASCII, (const char *s), (s), -10000);
INI_RET_LOADLIB_CORE(char*, ICL_ConvertUTF8ToEUCKR, (const char *u), (u), NULL);
INI_RET_LOADLIB_CORE(char*, ICL_ConvertEUCKRToUTF8, (const char *k), (k), NULL);
INI_RET_LOADLIB_CORE(char*, ICL_ConvertUCS2ToEUCKR, (const char *u,int l), (u,l), NULL);
INI_RET_LOADLIB_CORE(char*, ICL_ConvertEUCKRToUCS2, (const char *k,int *l), (k,l), NULL);
#endif

#ifdef  __cplusplus
}
#endif

#endif
#endif
