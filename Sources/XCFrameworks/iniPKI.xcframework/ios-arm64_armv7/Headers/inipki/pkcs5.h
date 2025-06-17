/*!
* \file pkcs5.h
* \brief PKCS5 알고리즘
* PBE 기반의 암호화/복호화 표준
* \remarks
* PBES1, PBES2, KISA_PBES
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_PKCS5_H
#define HEADER_PKCS5_H

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/foundation.h>

#include "asn1.h"
#include "pkcs8.h"

#define IV_DEFALUT		0		/*!< KISA_PBES의 초기벡터: 정해진 벡터값 */
#define IV_GENERATE		1		/*!< KISA_PBES의 초기벡터: 기본값(ISC_SHA1이용) */


#ifdef  __cplusplus
extern "C" {
#endif

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* PBES1_KISA ENCRYPT 함수
* \param message
* 메시지
* \param messageLen
* 메세지의 길이
* \param password
* 패스워드
* \param passwordLen
* 패스워드 길이
* \param salt
* SALT 값
* \param saltLen
* SALT의 길이
* \param iter
* 중복값
* \param out
* 암호문
* \param outLen
* 암호문의 길이
* \param enc_alg
* 암호화 인크립션 알고리즘 ID
* \param hash_alg
* 암호화 해시 알고리즘 ID
* \param iv_opt
* 초기 벡터 ID
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ENC_PBES1_KISA^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_ENC_PBES1_KISA^ISC_ERR_INVALID_INPUT : input error
* -# PBKDF1()의 에러 코드\n
* -# ISC_Init_DIGEST()의 에러 코드\n
* -# ISC_Update_DIGEST()의 에러 코드\n
* -# ISC_Final_DIGEST()의 에러 코드\n
*/
ISC_API ISC_STATUS encrypt_PBES1_KISA(uint8* message, int messageLen, uint8* password, int passwordLen,
				  uint8* salt, int saltLen, int iter, uint8* out, int* outLen,
				  int enc_alg, int hash_alg, int iv_opt);

/*!
* \brief
* PBES1_GPKI DECRYPT 함수
* \param ciphertext
* 암호문
* \param ciphertextLen
* 암호문의 길이
* \param password
* 패스워드
* \param passwordLen
* 패스워드 길이
* \param salt
* SALT 값
* \param saltLen
* SALT의 길이
* \param iter
* 중복값
* \param out
* 암호문
* \param outLen
* 암호문의 길이
* \param enc_alg
* 암호화 디크립션 알고리즘 ID
* \param hash_alg
* 암호화 해시 알고리즘 ID
* \param iv_opt
* 초기 벡터 ID
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_DEC_PBES1_KISA^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_DEC_PBES1_KISA^ISC_ERR_INVALID_INPUT : input error
* -# PBKDF1()의 에러 코드\n
* -# ISC_Init_DIGEST()의 에러 코드\n
* -# ISC_Update_DIGEST()의 에러 코드\n
* -# ISC_Final_DIGEST()의 에러 코드\n
*/
ISC_API ISC_STATUS decrypt_PBES1_KISA(uint8* ciphertext, int ciphertextLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg, int iv_opt);

/*!
* \brief
* PBES1_GPKI ENCRYPT 함수
* \param message
* 메시지
* \param messageLen
* 메세지의 길이
* \param password
* 패스워드
* \param passwordLen
* 패스워드 길이
* \param salt
* SALT 값
* \param saltLen
* SALT의 길이
* \param iter
* 중복값
* \param out
* 암호문
* \param outLen
* 암호문의 길이
* \param enc_alg
* 암호화 인크립션 알고리즘 ID
* \param hash_alg
* 암호화 해시 알고리즘 ID
* \param iv_opt
* 초기 벡터 ID
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ENC_PBES1_KISA^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_ENC_PBES1_KISA^ISC_ERR_INVALID_INPUT : input error
* -# PBKDF1()의 에러 코드\n
* -# ISC_Init_DIGEST()의 에러 코드\n
* -# ISC_Update_DIGEST()의 에러 코드\n
* -# ISC_Final_DIGEST()의 에러 코드\n
*/
ISC_API ISC_STATUS encrypt_PBES1_GPKI(uint8* message, int messageLen, uint8* password, int passwordLen,
				  uint8* salt, int saltLen, int iter, uint8* out, int* outLen,
				  int enc_alg, int hash_alg);

/*!
* \brief
* PBES1_KISA DECRYPT 함수
* \param ciphertext
* 암호문
* \param ciphertextLen
* 암호문의 길이
* \param password
* 패스워드
* \param passwordLen
* 패스워드 길이
* \param salt
* SALT 값
* \param saltLen
* SALT의 길이
* \param iter
* 중복값
* \param out
* 암호문
* \param outLen
* 암호문의 길이
* \param enc_alg
* 암호화 디크립션 알고리즘 ID
* \param hash_alg
* 암호화 해시 알고리즘 ID
* \param iv_opt
* 초기 벡터 ID
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_DEC_PBES1_KISA^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_DEC_PBES1_KISA^ISC_ERR_INVALID_INPUT : input error
* -# PBKDF1()의 에러 코드\n
* -# ISC_Init_DIGEST()의 에러 코드\n
* -# ISC_Update_DIGEST()의 에러 코드\n
* -# ISC_Final_DIGEST()의 에러 코드\n
*/
ISC_API ISC_STATUS decrypt_PBES1_GPKI(uint8* ciphertext, int ciphertextLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg);

/*!
* \brief
* PBES1 ENCRYPT 함수
* \param message
* 메시지
* \param messageLen
* 메세지의 길이
* \param password
* 패스워드
* \param passwordLen
* 패스워드 길이
* \param salt
* SALT 값
* \param saltLen
* SALT의 길이
* \param iter
* 중복값
* \param out
* 암호문
* \param outLen
* 암호문의 길이
* \param enc_alg
* 암호화 인크립션 알고리즘 ID
* \param hash_alg
* 암호화 해시 알고리즘 ID
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ENCRYPT_PBES1^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_ENCRYPT_PBES1^ISC_ERR_INVALID_INPUT : input error
* -# PBKDF1()의 에러 코드\n
* -# ISC_BLOCK_CIPHER()의 에러 코드\n
*/
ISC_API ISC_STATUS encrypt_PBES1(uint8* message, int messageLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg);

/*!
* \brief
* PBES1 DECRYPT 함수
* \param ciphertext
* 암호문
* \param ciphertextLen
* 암호문의 길이
* \param password
* 패스워드
* \param passwordLen
* 패스워드 길이
* \param salt
* SALT 값
* \param saltLen
* SALT의 길이
* \param iter
* 중복값
* \param out
* 암호문
* \param outLen
* 암호문의 길이
* \param enc_alg
* 암호화 디크립션 알고리즘 ID
* \param hash_alg
* 암호화 해시 알고리즘 ID
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_DECRYPT_PBES1^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_DECRYPT_PBES1^ISC_ERR_INVALID_INPUT : input error
* -# PBKDF1()의 에러 코드\n
* -# ISC_BLOCK_CIPHER()의 에러 코드\n
*/
ISC_API ISC_STATUS decrypt_PBES1(uint8* ciphertext, int ciphertextLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg);

/*!
* \brief
* PBES2 ENCRYPT 함수
* \param message
* 메시지
* \param messageLen
* 메세지의 길이
* \param password
* 패스워드
* \param passwordLen
* 패스워드 길이
* \param salt
* SALT 값
* \param saltLen
* SALT의 길이
* \param iter
* 중복값
* \param out
* 암호문
* \param outLen
* 암호문의 길이
* \param iv
* 초기벡터
* \param ivLen
* 초기벡터의 길이
* \param enc_alg
* 암호화 인크립션 알고리즘 ID
* \param hash_alg
* 암호화 해시 알고리즘 ID
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ENCRYPT_PBES2^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_ENCRYPT_PBES2^ISC_ERR_INVALID_INPUT : input error
* -# PBKDF2()의 에러 코드\n
* -# ISC_BLOCK_CIPHER()의 에러 코드\n
*/
ISC_API ISC_STATUS encrypt_PBES2(uint8* message, int messageLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, uint8** iv, int* ivLen, int enc_alg, int hash_alg);

/*!
* \brief
* PBES2 DECRYPT 함수
* \param message
* 암호문
* \param messageLen
* 암호문의 길이
* \param password
* 패스워드
* \param passwordLen
* 패스워드 길이
* \param salt
* SALT 값
* \param saltLen
* SALT의 길이
* \param iter
* 중복값
* \param out
* 평문
* \param outLen
* 평문의 길이
* \param iv
* 초기벡터
* \param enc_alg
* 암호화 인크립션 알고리즘 ID
* \param hash_alg
* 암호화 해시 알고리즘 ID
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_DECRYPT_PBES2^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_DECRYPT_PBES2^ISC_ERR_INVALID_INPUT : input error
* -# PBKDF2()의 에러 코드\n
* -# ISC_BLOCK_CIPHER()의 에러 코드\n
*/
ISC_API ISC_STATUS decrypt_PBES2(uint8* message, int messageLen,uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen,  uint8* iv,  int enc_alg, int hash_alg);

/*!
* \brief
* PBKDF1
* \param password
* 패스워드
* \param passwordLen
* 패스워드 길이
* \param salt
* SALT 값
* \param saltLen
* SALT의 길이
* \param iter
* 중복값
* \param hash_alg
* 암호화 해시 알고리즘 ID
* \param out
* PBKDF1을 통해 생성된 키
* \param outLen
* 생성될 키의 길이
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
* -# LOCATION^F_PBKDF1^ISC_ERR_INVALID_OUTPUT : input error
* -# PBKDF2()의 에러 코드\n
* -# ISC_Init_DIGEST()의 에러 코드\n
* -# ISC_Update_DIGEST()의 에러 코드\n
* -# ISC_Final_DIGEST()의 에러 코드\n
*/
ISC_API ISC_STATUS PBKDF1(uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int hash_alg, uint8* out, int outLen);
/*!
* \brief
* PBKDF2
* \param password
* 패스워드
* \param passwordLen
* 패스워드 길이
* \param salt
* SALT 값
* \param saltLen
* SALT의 길이
* \param iter
* 중복값
* \param hash_alg
* 암호화 해시 알고리즘 ID
* \param key
* PBKDF2을 통해 생성된 키
* \param keyLen
* 생성된 키의 길이
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_PBKDF2^ISC_ERR_INVALID_OUTPUT : input error
* -# PBKDF2()의 에러 코드\n
* -# ISC_Init_HMAC()의 에러 코드\n
* -# ISC_Update_HMAC()의 에러 코드\n
* -# ISC_Final_HMAC()의 에러 코드\n
*/
ISC_API ISC_STATUS PBKDF2(uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int hash_alg, uint8* key, int keyLen);

/*!
* \brief
* PBE ENCRYPT 함수
* \param priv_unit
* encryption의 대상인 P8_PRIV_KEY_INFO 구조체
* \param p8_out
* decrypt후 정보가 저장될 P8_ENCRYPTED_KEY 구조체
* \param password
* 패스워드
* \param passwordLen
* 패스워드 길이
* \param salt
* SALT 값
* \param saltLen
* SALT의 길이
* \param iter
* 중복값
* \param oid_index
* PBE관련 OBJECT IDENTIFIER의 ID
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
* -# LOCATION^F_ENC_PKCS5^ISC_ERR_NULL_INPUT : Null Input
* -# LOCATION^F_ENC_PKCS5^ISC_ERR_INVALID_OUTPUT : input error
* -# encrypt_PBES1_KISA()의 에러 코드\n
* -# encrypt_PBES1()의 에러 코드\n
* -# encrypt_PBES2()의 에러 코드\n
*/
ISC_API ISC_STATUS encrypt_PKCS5(P8_PRIV_KEY_INFO* priv_unit, P8_ENCRYPTED_KEY** p8_out, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int oid_index);

/*!
* \brief
* PBE ENCRYPT 함수
* \param priv_unit
* encryption의 대상인 P8_PRIV_KEY_INFO 구조체
* \param p8_out
* decrypt후 정보가 저장될 P8_ENCRYPTED_KEY 구조체
* \param password
* 패스워드
* \param passwordLen
* 패스워드 길이
* \param salt
* SALT 값
* \param saltLen
* SALT의 길이
* \param iter
* 중복값
* \param oid_index
* PBE관련 OBJECT IDENTIFIER의 ID
* \param alg_index
* 암호알고리즘 관련 OBJECT IDENTIFIER의 ID
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
* -# LOCATION^F_ENC_PKCS5^ISC_ERR_NULL_INPUT : Null Input
* -# LOCATION^F_ENC_PKCS5^ISC_ERR_INVALID_OUTPUT : input error
* -# encrypt_PBES1_KISA()의 에러 코드\n
* -# encrypt_PBES1()의 에러 코드\n
* -# encrypt_PBES2()의 에러 코드\n
*/
ISC_API ISC_STATUS encrypt_PKCS5_ex(P8_PRIV_KEY_INFO* priv_unit, P8_ENCRYPTED_KEY** p8_out, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int oid_index, int alg_index);

/*!
* \brief
* PBE ENCRYPT 함수
* \param priv_unit
* encryption의 대상인 P8_PRIV_KEY_INFO 구조체
* \param p8_out
* decrypt후 정보가 저장될 P8_ENCRYPTED_KEY 구조체
* \param password
* 패스워드
* \param passwordLen
* 패스워드 길이
* \param salt
* SALT 값
* \param saltLen
* SALT의 길이
* \param iter
* 중복값
* \param oid_index
* PBE관련 OBJECT IDENTIFIER의 ID
* \param alg_index
* 암호알고리즘 관련 OBJECT IDENTIFIER의 ID
* \param prf_alg_index
* PBKDF2의 prf 알고리즘의 OBJECT IDENTIFIER의 ID
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
* -# LOCATION^F_ENC_PKCS5^ISC_ERR_NULL_INPUT : Null Input
* -# LOCATION^F_ENC_PKCS5^ISC_ERR_INVALID_OUTPUT : input error
* -# encrypt_PBES1_KISA()의 에러 코드\n
* -# encrypt_PBES1()의 에러 코드\n
* -# encrypt_PBES2()의 에러 코드\n
*/
ISC_API ISC_STATUS encrypt_PKCS5_Apply_PBES2(P8_PRIV_KEY_INFO* priv_unit, P8_ENCRYPTED_KEY** p8_out, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int oid_index, int alg_index, int prf_alg_index);

/*!
* \brief
* PBE DECRYPT 함수
* \param unit
* decrypt의 대상인 P8_ENCRYPTED_KEY 구조체
* \param priv_unit
* decrypt후 정보가 저장될 P8_PRIV_KEY_INFO 구조체
* \param password
* 패스워드
* \param passwordLen
* 패스워드 길이
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
* -# LOCATION^F_DEC_PKCS5^ISC_ERR_NULL_INPUT : Null Input
* -# decrypt_PBES1_KISA()의 에러 코드\n
* -# decrypt_PBES1()의 에러 코드\n
* -# decrypt_PBES2()의 에러 코드\n
*/
ISC_API ISC_STATUS decrypt_PKCS5(P8_ENCRYPTED_KEY* unit, P8_PRIV_KEY_INFO** priv_unit, uint8* password, int passwordLen);

/*!
* \brief
* PBE ENCRYPT 함수
* \param priv_unit
* encryption의 대상인 P8_PRIV_KEY_INFO 구조체
* \param p8_out
* decrypt후 정보가 저장될 P8_ENCRYPTED_KEY 구조체
* \param password
* 패스워드
* \param passwordLen
* 패스워드 길이
* \param salt
* SALT 값
* \param saltLen
* SALT의 길이
* \param iter
* 중복값
* \param oid_index
* PBE관련 OBJECT IDENTIFIER의 ID
* \param alg_index
* 암호알고리즘 관련 OBJECT IDENTIFIER의 ID
* \param prf_alg_index
* PBKDF2의 prf 알고리즘의 OBJECT IDENTIFIER의 ID
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
* -# LOCATION^F_ENC_PKCS5^ISC_ERR_NULL_INPUT : Null Input
* -# LOCATION^F_ENC_PKCS5^ISC_ERR_INVALID_OUTPUT : input error
* -# encrypt_PBES1_KISA()의 에러 코드\n
* -# encrypt_PBES1()의 에러 코드\n
* -# encrypt_PBES2()의 에러 코드\n
*/
ISC_API ISC_STATUS encrypt_PKCS5_Apply_PBES2(P8_PRIV_KEY_INFO* priv_unit, P8_ENCRYPTED_KEY** p8_out, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int oid_index, int alg_index, int prf_alg_index);

#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(ISC_STATUS, encrypt_PBES1_KISA, (uint8* message, int messageLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg, int iv_opt), (message,messageLen,password,passwordLen,salt,saltLen,iter,out,outLen,enc_alg,hash_alg,iv_opt), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, decrypt_PBES1_KISA, (uint8* ciphertext, int ciphertextLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg, int iv_opt), (ciphertext,ciphertextLen,password,passwordLen,salt,saltLen,iter,out,outLen,enc_alg,hash_alg,iv_opt), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encrypt_PBES1_GPKI, (uint8* message, int messageLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg), (message,messageLen,password,passwordLen,salt,saltLen,iter,out,outLen,enc_alg,hash_alg), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, decrypt_PBES1_GPKI, (uint8* ciphertext, int ciphertextLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg), (ciphertext,ciphertextLen,password,passwordLen,salt,saltLen,iter,out,outLen,enc_alg,hash_alg), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encrypt_PBES1, (uint8* message, int messageLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg), (message,messageLen,password,passwordLen,salt,saltLen,iter,out,outLen,enc_alg,hash_alg), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, decrypt_PBES1, (uint8* ciphertext, int ciphertextLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg), (ciphertext,ciphertextLen,password,passwordLen,salt,saltLen,iter,out,outLen,enc_alg,hash_alg), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encrypt_PBES2, (uint8* message, int messageLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, uint8** iv, int* ivLen, int enc_alg, int hash_alg), (message,messageLen,password,passwordLen,salt,saltLen,iter,out,outLen,iv,ivLen,enc_alg,hash_alg), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, decrypt_PBES2, (uint8* message, int messageLen,uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, uint8* iv, int enc_alg, int hash_alg), (message,messageLen,password,passwordLen,salt,saltLen,iter,out,outLen,iv,enc_alg,hash_alg), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, PBKDF1, (uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int hash_alg, uint8* out, int outLen), (password,passwordLen,salt,saltLen,iter,hash_alg,out,outLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, PBKDF2, (uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int hash_alg, uint8* key, int keyLen), (password,passwordLen,salt,saltLen,iter,hash_alg,key,keyLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encrypt_PKCS5, (P8_PRIV_KEY_INFO* priv_unit, P8_ENCRYPTED_KEY** p8_out, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int oid_index), (priv_unit,p8_out,password,passwordLen,salt,saltLen,iter,oid_index), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encrypt_PKCS5_ex, (P8_PRIV_KEY_INFO* priv_unit, P8_ENCRYPTED_KEY** p8_out, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int oid_index, int alg_index), (priv_unit,p8_out,password,passwordLen,salt,saltLen,iter,oid_index,alg_index), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, decrypt_PKCS5, (P8_ENCRYPTED_KEY* unit, P8_PRIV_KEY_INFO** priv_unit, uint8* password, int passwordLen), (unit,priv_unit,password,passwordLen), ISC_FAIL);

#endif

#ifdef  __cplusplus
}
#endif
#endif

