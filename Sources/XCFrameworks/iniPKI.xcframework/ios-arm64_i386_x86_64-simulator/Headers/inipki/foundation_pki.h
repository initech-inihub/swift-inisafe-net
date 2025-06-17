#ifndef __INIPKI_FOUNDATION_H__
#define __INIPKI_FOUNDATION_H__

#ifdef WIN_INI_LOADLIBRARY_PKI

#if !defined(_WIN32) || defined(_WIN32_WCE) || defined(_INI_BADA)
#error Can not support "Loadlibrary"
#endif

#include <windows.h>

HMODULE g_inipkiLibrary;

#define INI_RET_LOADLIB_PKI(retType, functionName, fullTypeParam, callParam, retFail) \
	static retType functionName##fullTypeParam { \
	typedef retType(*p##functionName)##fullTypeParam; \
	static p##functionName f##functionName = NULL; \
	f##functionName = (f##functionName == NULL) ? \
	(p##functionName)GetProcAddress((HMODULE)g_inipkiLibrary, #functionName) : f##functionName; \
	return (f##functionName == NULL) ? retFail : f##functionName##callParam; \
}

#define INI_VOID_LOADLIB_PKI(retType, functionName, fullTypeParam, callParam) \
	static retType functionName##fullTypeParam { \
	typedef retType(*p##functionName)##fullTypeParam; \
	static p##functionName f##functionName = NULL; \
	f##functionName = (f##functionName == NULL) ? \
	(p##functionName)GetProcAddress((HMODULE)g_inipkiLibrary, #functionName) : f##functionName; \
	f##functionName##callParam; \
}

#endif /* #ifdef WIN_INI_LOADLIBRARY_CRYPTO */

#endif /* #ifndef __INIPKI_FOUNDATION_H__ */