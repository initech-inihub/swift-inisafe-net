/**
 *      @file   : ICL_module_verify.h
 *      @brief  : 생성된 파일에 대한 서명을 생성하는 함수 
 *      @author : server team (r&d1_server@initech.com)
 *      @create : 2014. 06. 12
 */

#ifndef __MODULE_SIGNER_H__
#define __MODULE_SIGNER_H__

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

#include <inicrypto/rsa.h>
#include <inicrypto/biginteger.h>
#include <inicrypto/self_test.h>
#include <inicrypto/foundation.h>
#include <inipki/pkcs1.h>

#ifndef _WIN32_LOADLOBRARY_CORE_
INISAFECORE_API unsigned int ICL_sign_module(char *input, char *output, char *pkey);
INISAFECORE_API unsigned int ICL_verify_module(char *input, char *pkey);
#endif

#ifdef  __cplusplus
}
#endif
#endif /* __MODULE_SIGNER_H__ */
