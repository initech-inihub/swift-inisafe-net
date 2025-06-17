/*!
* \file version.h
* \brief Version 정보 확인
* \author sungwook.jang@initech.com
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef __INICRYPTO_VERSION_H__
#define __INICRYPTO_VERSION_H__

#include "foundation.h"

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO
ISC_API char *ISC_Get_Crypto_Version();
#else
ISC_RET_LOADLIB_CRYPTO(char*, ISC_Get_Crypto_Version, (void), (), NULL );
#endif

#ifdef  __cplusplus
}
#endif

#endif

