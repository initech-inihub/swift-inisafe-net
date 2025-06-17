/*!
* \file ecdsa.h
* \brief ecdsa 헤더파일
* \author
* Copyright (c) 2013 by \<INITech\>
*/

#ifndef HEADER_ECDSA_H
#define HEADER_ECDSA_H


#if defined(ISC_NO_ECC)
#define ISC_NO_ECDSA
#error ISC_ECDSA is disabled.
#endif

#ifdef ISC_NO_ECDSA
#error ISC_ECDSA is disabled.
#endif

#include "biginteger.h"
#include "digest.h"
#include "foundation.h"
#include "ecc.h"

#define ISC_ECDSA_PROVEN_MODE	1		/*!<  0: 비검증 모드, 1: 검증모드 */

#define ISC_ECDSA_SIGN			1		/*!< ISC_ECDSA_SIGN*/
#define ISC_ECDSA_VERIFY		0		/*!< ISC_ECDSA_VERIFY*/

/* ISC_ECDSA Alias				0x50000000 ------------------------------------------------ */
#define ISC_ECDSA				0x50000000   /*!< ISC_ECDSA 알고리즘 ID */

/*!
* \brief
* ISC_ECDSA 알고리즘을 위한 구조체
*/
struct isc_ecdsa_st
{
	ISC_ECC_KEY_UNIT *key;			/*!< ISC_ECC_KEY_UNIT*/
	ISC_DIGEST_UNIT *d_unit;		/*!< ISC_DIGEST_UNIT*/
	ISC_BIGINT *k;					/*!< 마지막에 사용한 랜덤 k값 */
	ISC_ECPOINT *kG;				/*!< 마지막에 사용한 랜덤 kG값 */
	ISC_BIGINT_POOL *pool;			/*!< 연산 효율을 위한 풀 */
	int is_private;					/*!< Public : 0 , Private : 1 */
	ISC_BIGINT *kkey;				/*!< 벡터값. 사용하지 않는다. */
};	

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_ECDSA_UNIT 구조체의 메모리 할당
* \returns
* ISC_ECDSA_UNIT 구조체
*/
ISC_API ISC_ECDSA_UNIT *ISC_New_ECDSA(void);

/*!
* \brief
* ISC_ECDSA_UNIT 메모리 해제 함수
* \param unit
* 메모리 해제할 ISC_ECDSA_UNIT
*/
ISC_API void ISC_Free_ECDSA(ISC_ECDSA_UNIT *unit);

/*!
* \brief
* ISC_ECDSA_UNIT 메모리 초기화 함수
* \param unit
* 초기화 할 ISC_ECDSA_UNIT
*/
ISC_API void ISC_Clean_ECDSA(ISC_ECDSA_UNIT *unit);

/*!
* \brief
* ECDSA 전자서명 알고리즘 초기화
* \param ecdsa
* 초기화 될 ISC_ECDSA_UNIT
* \param digest_alg
* 해시 알고리즘 ID
* \param sign
* (ISC_ECDSA_SIGN)1 : 서명, (ISC_ECDSA_VERIFY)0 : 검증
* \param user_seed
* 유저가 지정하는 랜덤 seed값
* \param user_seedLen
* 유저가 지정하는 랜덤 seed값의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# LOCATION^ISC_F_INIT_ECDSA^ISC_ERR_NOT_PROVEN_ALGORITHM : 비검증대상알고리즘 오류
* -# LOCATION^ISC_F_INIT_ECDSA^ISC_ERR_NULL_INPUT : NULL 데이터 입력
* -# LOCATION^ISC_F_INIT_ECDSA^ISC_ERR_MEM_ALLOC : 메모리 할당 실패
* -# LOCATION^ISC_F_INIT_ECDSA^ISC_ERR_INIT_DIGEST_FAIL : 해시 초기화 실패
*/
ISC_API ISC_STATUS ISC_Init_ECDSA(ISC_ECDSA_UNIT *unit, int digest_alg, int sign, uint8* user_seed, int user_seedLen);

/*!
* \brief
* ISC_ECDSA 전자서명 메시지 입력(Update) 함수
* \param ecdsa
* ISC_ECDSA_UNIT 구조체 포인터
* \param data
* 입력될 데이터(여러번 입력 가능)
* \param dataLen
* 데이터의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_UPDATE_ECDSA^ISC_ERR_NULL_INPUT : 입력된 RSA_UNIT이 NULL일 경우
* -# LOCATION^ISC_F_UPDATE_ECDSA^ISC_ERR_UPDATE_DIGEST_FAIL : 내부 Digest 함수 실패 
*/
ISC_API ISC_STATUS ISC_Update_ECDSA(ISC_ECDSA_UNIT *unit, const uint8 *data, int dataLen);

/*!
* \brief
* ISC_ECDSA 전자서명의 서명값 생성 / 검증 함수
* \param ecdsa
* ISC_ECDSA_UNIT 구조체 포인터
* \param r
* 서명값 r
* \param rLen
* 서명값 r의 길이
* \param s
* 서명값 s
* \param sLen
* 서명값 s의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_FINAL_ECDSA^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# LOCATION^ISC_F_FINAL_ECDSA^ISC_ERR_NO_PRIVATE_VALUE : 서명키가 없이 서명 시도
* -# LOCATION^ISC_F_FINAL_ECDSA^ISC_ERR_SIGN_DSA_FAIL : 서명 실패
* -# LOCATION^ISC_F_FINAL_ECDSA^ISC_ERR_VERIFY_ECDSA_FAIL : 검증 실패
*/
ISC_API ISC_STATUS ISC_Final_ECDSA(ISC_ECDSA_UNIT *unit, uint8 *r, int *rLen,  uint8 *s, int *sLen);

/*!
* \brief
* ISC_ECDSA_UNIT에 입력된 파라메터 설정
* \param ecdsa
* target ISC_ECDSA_UNIT 구조체
* \param field_id
* curve id값
* \param x
* 개인키 값
* \param y
* 공개키 값
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_ECDSA^ISC_F_SET_ECDSA_PARAMS_EX^ISC_ERR_NULL_INPUT : NULL값 입력
* -# ISC_L_ECDSA^ISC_F_SET_ECDSA_PARAMS_EX^ISC_ERR_MEM_ALLOC : 메모리 생성 실패
* -# ISC_L_ECDSA^ISC_F_SET_ECDSA_PARAMS_EX^ISC_ERR_SET_ECC_KEY_PARAMS_EX : 커브 설정 실패
*/
ISC_API ISC_STATUS ISC_Set_ECDSA_Params(ISC_ECDSA_UNIT *unit, const int field_id, const ISC_BIGINT* x, const ISC_ECPOINT* y);

/*!
* \brief
* ISC_ECDSA_UNIT에 입력된 파라메터 설정
* \param ecdsa
* target ISC_ECDSA_UNIT 구조체
* \param curve
* curve 값
* \param x
* 개인키 값
* \param y
* 공개키 값
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_ECDSA^ISC_F_SET_ECDSA_PARAMS^ISC_ERR_NULL_INPUT : NULL값 입력
* -# ISC_L_ECDSA^ISC_F_SET_ECDSA_PARAMS^ISC_ERR_MEM_ALLOC : 메모리 생성 실패
* -# ISC_L_ECDSA^ISC_F_SET_ECDSA_PARAMS^ISC_ERR_OPERATE_FUNCTION : 커브 설정 실패
* -# ISC_L_ECDSA^ISC_F_SET_ECDSA_PARAMS^ISC_F_SET_ECDSA_PARAMS^ISC_ERR_COPY_BIGINT_FAIL : BIGINT_COPY 실패
*/
ISC_API ISC_STATUS ISC_Set_ECDSA_Params_Ex(ISC_ECDSA_UNIT *unit, const ISC_ECURVE* curve, const ISC_BIGINT* x, const ISC_ECPOINT* y);

/*!
* \brief
* 공개키, 개인키 키쌍을 생성
* \param key
* ISC_ECC_KEY_UNIT 구조체 포인터로 curve값 세팅이 되었어야 한다. 성공 시 키쌍을 저장한다.
* -# ISC_SUCCESS : Success
* -# ISC_L_ECDSA^ISC_F_GENERATE_ECDSA_KEY_PAIR^ISC_ERR_NULL_INPUT : NULL값 입력
* -# ISC_L_ECDSA^ISC_F_GENERATE_ECDSA_KEY_PAIR^ISC_ERR_GENERATE_KEY_PAIR : 키쌍 생성 실패
*/
ISC_API ISC_STATUS ISC_Generate_ECDSA_Key_Pair(ISC_ECDSA_UNIT *unit);

/*!
* \brief
* ISC_ECDSA 전자서명의 서명값 생성
* \param ecdsa
* ISC_ECDSA_UNIT 구조체 포인터
* \param r
* 서명값 r
* \param rLen
* 서명값 r의 길이
* \param s
* 서명값 s
* \param sLen
* 서명값 s의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_INIT_PRNG_FAIL : ISC_Init_PRNG 실패
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_START_BIGINT_POOL_FAIL : START_BIGINT_POOL 실패
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_FINAL_DIGEST_FAIL : FINAL_DIGEST 실패
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_GET_BIGINT_POOL_FAIL : GET_BIGINT_POOL 실패
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_GET_RAND_DSA_BIGINT_FAIL : 난수 K 생성 실패
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_MTP_FP_ECC : ECC 곱셈 연산 실패
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_ADD_BIGINT_FAIL : ADD_BIGINT 실패
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_ADD_FP_ECC : ECC 덧셈 연산 실패
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_MOD_INVERSE_BIGINT_FAIL : MOD_INVERSE_BIGINT 실패
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY_TO_BIGINT 실패
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_MOD_BIGINT_FAIL : MOD_BIGINT 실패
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_MOD_MTP_BIGINT_FAIL : MOD_MTP_BIGINT 실패
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_ADD_BIGINT_FAIL : ADD_BIGINT 실패
*/
ISC_INTERNAL ISC_STATUS isc_Sign_ECDSA(ISC_ECDSA_UNIT *unit, uint8 *r, int *rLen, uint8 *s, int *sLen);

/*!
* \brief
* ISC_ECDSA 전자서명의 서명값 검증
* \param ecdsa
* ISC_ECDSA_UNIT 구조체 포인터
* \param r
* 서명값 r
* \param rLen
* 서명값 r의 길이
* \param s
* 서명값 s
* \param sLen
* 서명값 s의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_START_BIGINT_POOL_FAIL : START_BIGINT_POOL 실패
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_FINAL_DIGEST_FAIL : FINAL_DIGEST 실패
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY_TO_BIGINT 실패
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_MOD_INVERSE_BIGINT_FAIL : MOD_INVERSE_BIGINT 실패
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_MEMORY_ALLOC : MEMORY_ALLOC 실패
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_MOD_MTP_BIGINT_FAIL : MOD_MTP_BIGINT 실패
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_GET_BIGINT_POOL_FAIL : GET_BIGINT_POOL 실패
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_MTP_FP_ECC : ECC 곱셈 실패
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_ADD_FP_ECC : ECC 덧셈 실패
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_VERIFY_FAILURE : 검증 실패
*/
ISC_INTERNAL ISC_STATUS isc_Verify_ECDSA(ISC_ECDSA_UNIT *unit, uint8 *r, int rLen, uint8 *s, int sLen);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_ECDSA_UNIT*, ISC_New_ECDSA, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_ECDSA, (ISC_ECDSA_UNIT *unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_ECDSA, (ISC_ECDSA_UNIT *unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_ECDSA, (ISC_ECDSA_UNIT *unit, int digest_alg, int sign, uint8* user_seed, int user_seedLen), (unit, digest_alg, sign, user_seed, user_seedLen), ISC_ERR_GET_ADRESS_LOADLIBRARY);
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Update_ECDSA, (ISC_ECDSA_UNIT *unit, const uint8 *data, int dataLen), (unit, data, dataLen), ISC_ERR_GET_ADRESS_LOADLIBRARY);
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Final_ECDSA, (ISC_ECDSA_UNIT *unit, uint8 *r, int *rLen,  uint8 *s, int *sLen), (unit, r, rLen, s, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY);
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_ECDSA_Params, (ISC_ECDSA_UNIT *unit, const int field_id, const ISC_BIGINT* x, const ISC_ECPOINT* y), (unit, field_id, x, y), ISC_ERR_GET_ADRESS_LOADLIBRARY);
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_ECDSA_Params_Ex, (ISC_ECDSA_UNIT *unit, const ISC_ECURVE* curve, const ISC_BIGINT* x, unit ISC_ECPOINT* y), (unit, curve, x, y), ISC_ERR_GET_ADRESS_LOADLIBRARY);
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_ECDSA_Key_Pair, (ISC_ECDSA_UNIT *unit), (unit), ISC_ERR_GET_ADRESS_LOADLIBRARY);

#endif /* #ifndef ISC_WIN_LOADLIBRARY_CRYPTO */

#ifdef  __cplusplus
}
#endif

#endif /* #ifndef HEADER_ECDSA_H */
