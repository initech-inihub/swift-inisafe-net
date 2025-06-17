#ifndef HEADER_PBKDF_H
#define HEADER_PBKDF_H

#include "foundation.h"

#ifdef ISC_NO_PBKDF
#error HMAC is disabled.
#endif
																			   
#ifdef  __cplusplus																   
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* 패스워드를 입력받아 키유도하는 함수(PKCS#5 PBKDF2)
* \param password
* 패스워드
* \param passwordLen
* 패스워드 길이
* \param salt
* SALT 값
* \param saltLen
* SALT의 길이 (Byte)
* \param iter
* 반복횟수
* \param hash_alg
* 암호화 해시 알고리즘 ID
* \param key
* PBKDF2을 통해 생성된 키
* \param keyLen
* 생성된 키의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# LOCATION^ISC_F_PBKDF2^ISC_ERR_NOT_PROVEN_ALGORITHM : 검증모드에서 비검증 대상 알고리즘 사용 실패
* -# LOCATION^ISC_F_PBKDF2^ISC_ERR_NULL_INPUT : password, salt, iter가 NULL일때
* -# LOCATION^ISC_F_PBKDF2^ISC_ERR_INVALID_INPUT : 유효하지 않은 해시 알고리즘 입력
* -# LOCATION^ISC_F_PBKDF2^ISC_ERR_MEM_ALLOC : 메모리 동적 할당 실패
* -# LOCATION^ISC_F_PBKDF2^ISC_ERR_OPERATE_FUNCTION : HMAC 연산 실패
*/
ISC_API ISC_STATUS ISC_PBKDF2(uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int hash_alg, uint8* key, int keyLen);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_PBKDF2, (uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int hash_alg, uint8* key, int keyLen), (password, passwordLen, salt, saltLen, iter, hash_alg, key, keyLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );


#endif

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_PBKDF_H */


