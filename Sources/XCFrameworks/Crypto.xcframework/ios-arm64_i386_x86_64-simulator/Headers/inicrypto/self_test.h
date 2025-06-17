/*!
* \file self_test.h
* \brief 자가시험 헤더파일
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_SELF_TEST_H
#define HEADER_SELF_TEST_H

#include "stdio.h"
#include "foundation.h"
#include "rsa.h"
#include "biginteger.h"
#include "drbg.h"

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO
/*!
* \brief
* 자가 테스트
* \returns
* -# TEST_SUCCESS : Success\n
* -# ISC_L_SELF_TEST^ISC_F_LIB_INTEGRITY_CHECK^ISC_ERR_MEM_ALLOC : 무결성점검 실패
* -# ISC_L_SELF_TEST^ISC_F_LIB_INTEGRITY_CHECK^ISC_ERR_READ_FROM_FILE : 무결성점검 실패
* -# ISC_L_SELF_TEST^ISC_F_LIB_INTEGRITY_CHECK^ISC_ERR_INIT_FAILURE : 무결성점검 실패
* -# ISC_L_SELF_TEST^ISC_F_LIB_INTEGRITY_CHECK^ISC_ERR_UPDATE_FAILURE : 무결성점검 실패
* -# ISC_L_SELF_TEST^ISC_F_LIB_INTEGRITY_CHECK^ISC_ERR_FINAL_FAILURE : 무결성점검 실패
* -# ISC_L_SELF_TEST^ISC_F_CONTEXT_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : 콘텐츠생성 실패
* -# ISC_L_SELF_TEST^ISC_F_VERSION_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : 버전점검 실패
* -# ISC_L_SELF_TEST^ISC_F_ENTROPY_CHECK^ISC_ERR_ENTROPY_FAIL : 엔트로피 생성 실패
* -# ISC_L_SELF_TEST^ISC_F_DRBG_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : DRBG 실패
* -# ISC_L_SELF_TEST^ISC_F_HMAC_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : HMAC 실패
* -# ISC_L_SELF_TEST^ISC_F_DIGEST_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : 해시 실패
* -# ISC_L_SELF_TEST^ISC_F_SYMMETIC_KEY_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : 블록 암호키 생성 실패
* -# ISC_L_SELF_TEST^ISC_F_SYMMETIC_ALGORITHM_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : 블록암호 실패
* -# ISC_L_SELF_TEST^ISC_F_ASYMMETIC_KEY_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : 공개키 암호키생성 실패
* -# ISC_L_SELF_TEST^ISC_F_RSAES_OAEP_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : 공개키 암호 실패
* -# ISC_L_SELF_TEST^ISC_F_KCDSA_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : 전자서명 실패
* -# ISC_L_SELF_TEST^ISC_F_ECDSA_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : ECDSA 실패
* -# ISC_L_SELF_TEST^ISC_F_ECDH_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : ECDH 실패
* -# ISC_L_SELF_TEST^ISC_F_SYMMETIC_MAC_ALGORITHM_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : 블록암호 기밀성/인증 실패
* -# ISC_L_SELF_TEST^ISC_F_PBKDF_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : 키유도 실패
*/
ISC_API ISC_STATUS ISC_Crypto_Self_Test();

#else

ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Crypto_Self_Test, (void), (), ISC_ERR_GET_ADRESS_LOADLIBRARY );

#endif

/*!
* \brief
* 무결성점검 함수
* \returns
* -# ISC_F_LIB_INTEGRITY_CHECK :실패
* -# ISC_SUCCESS : 테스트 통과
*/
ISC_INTERNAL ISC_STATUS isc_Verify_DLL();
ISC_INTERNAL ISC_STATUS isc_Verify_Dat();

/*!
* \brief
* 콘텐츠생성 함수
* \returns
* -# ISC_F_CONTEXT_CHECK :실패
* -# ISC_SUCCESS : 테스트 통과
*/
ISC_INTERNAL ISC_STATUS isc_Context_Check();

/*!
* \brief
* 버전점검함수
* \returns
* -# ISC_F_VERSION_CHECK :실패
* -# ISC_SUCCESS : 테스트 통과
*/
ISC_INTERNAL ISC_STATUS isc_Version_Check();

/*!
* \brief
* 엔트로피 점검 함수
* \returns
* -# ISC_F_ENTROPY_CHECK :실패
* -# ISC_SUCCESS : 테스트 통과
*/
ISC_INTERNAL ISC_STATUS isc_Entropy_Check();

/*!
* \brief
* 난수생성기 점검 함수
* \returns
* -# ISC_F_DRBG_CHECK :실패
* -# ISC_SUCCESS : 테스트 통과
*/
ISC_INTERNAL ISC_STATUS isc_DRBG_Check();

/*!
* \brief
* hmac 점검함수
* \returns
* -# ISC_F_HMAC_CHECK :실패
* -# ISC_SUCCESS : 테스트 통과
*/
ISC_INTERNAL ISC_STATUS isc_HMAC_Check();

/*!
* \brief
* 해시함수 점검함수
* \returns
* -# ISC_F_DIGEST_CHECK :실패
* -# ISC_SUCCESS : 테스트 통과
*/
ISC_INTERNAL ISC_STATUS isc_DIGEST_Check();

/*!
* \brief
* 블록암호 생성 점검함수
* \returns
* -# ISC_F_SYMMETIC_KEY_CHECK :실패
* -# ISC_SUCCESS : 테스트 통과
*/
ISC_INTERNAL ISC_STATUS isc_Sym_Key_Check();

/*!
* \brief
* 블록암호 알고리즘 점검함수
* \returns
* -# ISC_F_SYMMETIC_ALGORITHM_CHECK :실패
* -# ISC_SUCCESS : 테스트 통과
*/
ISC_INTERNAL ISC_STATUS isc_Sym_Check();

/*!
* \brief
* 블록암호 기밀성/인증 알고리즘 점검함수
* \returns
* -# ISC_F_SYMMETIC_MAC_ALGORITHM_CHECK :실패
* -# ISC_SUCCESS : 테스트 통과
*/
ISC_INTERNAL ISC_STATUS isc_Sym_MAC_Check();

/*!
* \brief
* 공개키 생성 점검함수
* \returns
* -# ISC_F_ASYMMETIC_KEY_CHECK :실패
* -# ISC_SUCCESS : 테스트 통과
*/
ISC_INTERNAL ISC_STATUS isc_Asym_Key_Check();

/*!
* \brief
* RSA 암호화 알고리즘 점검함수
* \returns
* -# ISC_F_RSAES_OAEP_CHECK :실패
* -# ISC_SUCCESS : 테스트 통과
*/
ISC_INTERNAL ISC_STATUS isc_RSAES_Check();

/*!
* \brief
* RSA 서명 알고리즘 점검함수
* \returns
* -# ISC_F_RSASSA_CHECK :실패
* -# ISC_SUCCESS : 테스트 통과
*/
ISC_INTERNAL ISC_STATUS isc_RSASSA_Check();

/*!
* \brief
* KCDSA 서명 알고리즘 점검함수
* \returns
* -# ISC_F_KCDSA_CHECK :실패
* -# ISC_SUCCESS : 테스트 통과
*/
ISC_INTERNAL ISC_STATUS isc_KCDSA_Check();

/*!
* \brief
* DH 키설정 알고리즘 점검함수
* \returns
* -# ISC_F_DH_CHECK :실패
* -# ISC_SUCCESS : 테스트 통과
*/
ISC_INTERNAL ISC_STATUS isc_DH_Check();

/*!
* \brief
* ECDH 키설정 알고리즘 점검함수
* \returns
* -# ISC_F_ECDH_CHECK :실패
* -# ISC_SUCCESS : 테스트 통과
*/
ISC_INTERNAL ISC_STATUS isc_ECDH_Check();

/*!
* \brief
* ECDSA 키설정 알고리즘 점검함수
* \returns
* -# ISC_F_ECDSA_CHECK :실패
* -# ISC_SUCCESS : 테스트 통과
*/
ISC_INTERNAL ISC_STATUS isc_ECDSA_Check();

/*!
* \brief
* ECKCDSA 키설정 알고리즘 점검함수
* \returns
* -# ISC_F_ECKCDSA_CHECK :실패
* -# ISC_SUCCESS : 테스트 통과
*/
ISC_INTERNAL ISC_STATUS isc_ECKCDSA_Check();

/*!
* \brief
* PBKDF 키유도 알고리즘 점검함수
* \returns
* -# ISC_F_PBKDF_CHECK :실패
* -# ISC_SUCCESS : 테스트 통과
*/
ISC_INTERNAL ISC_STATUS isc_PBKDF_Check();

ISC_INTERNAL int SearchProcessLoadedDll(char * pOutBuffer);
ISC_INTERNAL int SearchProcessLoadedDat(char *pOutBuffer);
ISC_INTERNAL int isc_Find_Crypto_Modul_From_Path(char *path, char *out);
ISC_INTERNAL ISC_STATUS check_digest_sha();
ISC_INTERNAL ISC_STATUS check_digest_lsh();
ISC_INTERNAL int isc_Find_Dat_From_Path(char *path, char *out);

#ifdef  __cplusplus
}
#endif

#endif/* HEADER_SELF_TEST_H */
