/*!
* \file desmac.h
* \brief
* ISC_DES MAC 헤더 파일
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_DES_MAC_H
#define HEADER_DES_MAC_H

#include "foundation.h"
#include "mem.h"


#define ISC_DES_MAC_PROVEN_MODE  1    /*!<  0: 비검증 모드, 1: 검증모드 */

#ifdef ISC_NO_DES_MAC
#error ISC_DES_MAC is disabled.
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_DES_MAC 알고리즘 
* \param key
* ISC_DES_MAC에 사용되는 Key값
* \param in
* 입력 값
* \param inLen
* 입력 값의 길이
* \param output
* 출력 값 (ISC_DES_MAC값 길이는 64bits)
* \returns
* -# ISC_SUCCESS : Success\n
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_DES_MAC^ISC_F_DES_MAC^ISC_ERR_MEMORY_ALLOC : 동적 메모리 할당 실패
* -# ISC_L_DES_MAC^ISC_F_DES_MAC^ISC_ERR_NOT_PROVEN_ALGORITHM : 검증모드에서 비검증 알고리즘 사용
* -# ISC_L_DES_MAC^ISC_F_DES_MAC^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_DES_MAC^ISC_F_DES_MAC^ISC_ERR_INIT_BLOCKCIPHER_FAIL : INIT BlockCipher 실패
* -# ISC_L_DES_MAC^ISC_F_DES_MAC^ISC_ERR_UPDATE_BLOCKCIPHER_FAIL : UPDATE BlockCipher 실패
* -# ISC_L_DES_MAC^ISC_F_DES_MAC^ISC_ERR_FINAL_BLOCKCIPHER_FAIL : FINAL BlockCipher 실패
*/
ISC_API ISC_STATUS ISC_DES_MAC(uint8 *key, uint8 *in, int inLen, uint8 *output);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_DES_MAC, (uint8 *key, uint8 *in, int inLen, uint8 *output), (key, in, inLen, output), ISC_ERR_GET_ADRESS_LOADLIBRARY );

#endif


#ifdef  __cplusplus
}
#endif

#endif /*HEADER_DES_MAC_H*/
