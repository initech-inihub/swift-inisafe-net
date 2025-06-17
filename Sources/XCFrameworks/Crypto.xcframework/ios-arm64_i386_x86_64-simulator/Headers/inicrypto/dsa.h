/*!
* \file dsa.h
* \brief dsa 헤더파일
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_DSA_H
#define HEADER_DSA_H


#if defined(ISC_NO_SHA) || defined (ISC_NO_SHA1)
#define ISC_NO_DSA
#error ISC_DSA is disabled.
#endif

#ifdef ISC_NO_DSA
#error ISC_DSA is disabled.
#endif

#include "biginteger.h"
#include "digest.h"
#include "foundation.h"

#define ISC_DSA_PROVEN_MODE  1    /*!<  0: 비검증 모드, 1: 검증모드 */

#define ISC_DSA_SIGN			1		/*!< ISC_DSA_SIGN*/
#define ISC_DSA_VERIFY			0		/*!< ISC_DSA_VERIFY*/

/*ISC_DSA Alias				0x30000000 ------------------------------------------------ */
#define ISC_DSA				0x30000000   /*!< ISC_DSA 알고리즘 ID */

/*!
* \brief
* ISC_DSA 알고리즘을 위한 구조체
*/
struct isc_dsa_st
{
	ISC_DIGEST_UNIT *d_unit;		/*!< ISC_DIGEST_UNIT*/
	ISC_PRNG_UNIT *prng;			/*!< ISC_PRNG_UNIT*/
	uint8* seed;				/*!< 랜덤 seed 저장*/
	int seedLen;				/*!< 랜덤 seed 길이*/
	ISC_BIGINT *p;					/*!< 소수 p*/
	ISC_BIGINT *q;					/*!< 소수 q*/
	ISC_BIGINT *g;					/*!< Generator g*/
	ISC_BIGINT *y;					/*!< 공개 파라미터 y = g^x*/
	ISC_BIGINT *x; /* private */	/*!< 비밀키 x */
	ISC_BIGINT_POOL *pool;			/*!< 연산 효율을 위한 풀 */
	int is_private;				/*!<Public : 0 , Private : 1*/
};	

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* DSA Parameter 입력
* \param dsa
* Parameter가 입력될 ISC_DSA_UNIT
* \param p
* 소수 p
* \param q
* 소수 q
* \param g
* Generator g
* \param x
* 비밀값 x
* \param y
* 공개값 y=g^x
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_DSA^ISC_F_SET_DSA_PARAMS^ISC_ERR_INVALID_INPUT : 잘못된 입력값 입력
*/
ISC_API ISC_STATUS ISC_Set_DSA_Params(ISC_DSA_UNIT *dsa,
				   const ISC_BIGINT* p,
				   const ISC_BIGINT* q,
				   const ISC_BIGINT* g,
				   const ISC_BIGINT* x,
				   const ISC_BIGINT* y);

/*!
* \brief
* ISC_DSA_UNIT 구조체의 메모리 할당
* \returns
* ISC_DSA_UNIT 구조체
*/
ISC_API ISC_DSA_UNIT *ISC_New_DSA(void);

/*!
* \brief
* ISC_DSA_UNIT 메모리 해제 함수
* \param unit
* 메모리 해제할 ISC_DSA_UNIT
*/
ISC_API void ISC_Free_DSA(ISC_DSA_UNIT *unit);

/*!
* \brief
* ISC_DSA_UNIT 메모리 초기화 함수
* \param unit
* 초기화 할 ISC_DSA_UNIT
*/
ISC_API void ISC_Clean_DSA (ISC_DSA_UNIT *unit);

/*!
* \brief
* DSA 전자서명 알고리즘 초기화
* \param dsa
* 초기화 될 ISC_DSA_UNIT
* \param sign
* (ISC_DSA_SIGN)1 : 서명, (ISC_DSA_VERIFY)0 : 검증
* \param user_seed
* 유저가 지정하는 랜덤 seed값
* \param user_seedLen
* 유저가 지정하는 랜덤 seed값의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_DSA^ISC_F_INIT_DSA^ISC_ERR_NOT_PROVEN_ALGORITHM : 검증모드에 비검증 알고리즘 사용
* -# ISC_L_DSA^ISC_F_INIT_DSA^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_DSA^ISC_F_INIT_DSA^ISC_ERR_MEM_ALLOC : 동적 메모리 할당
* -# ISC_L_DSA^ISC_F_INIT_DSA^ISC_ERR_INIT_DIGEST_FAIL : INIT DIGEST 연산 실패
*/
ISC_API ISC_STATUS ISC_Init_DSA(ISC_DSA_UNIT *dsa, int digest_alg, int sign, uint8* user_seed, int user_seedLen);

/*!
* \brief
* ISC_DSA 전자서명 메시지 입력(Update) 함수
* \param dsa
* ISC_DSA_UNIT 구조체 포인터
* \param data
* 입력될 데이터(여러번 입력 가능)
* \param dataLen
* 데이터의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_DSA^ISC_F_UPDATE_DSA^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_DSA^ISC_F_UPDATE_DSA^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST 연산 실패
*/
ISC_API ISC_STATUS ISC_Update_DSA(ISC_DSA_UNIT *dsa, const uint8 *data, int dataLen);

/*!
* \brief
* DSA 전자서명의 서명값 생성 / 검증 함수
* \param dsa
* ISC_DSA_UNIT 구조체 포인터
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
* -# ISC_L_DSA^ISC_F_FINAL_DSA^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_DSA^ISC_F_FINAL_DSA^ISC_ERR_NO_PRIVATE_VALUE : 서명시 개인키 설정값이 없음
* -# ISC_L_DSA^ISC_F_FINAL_DSA^ISC_ERR_SIGN_DSA_FAIL : 서명 실패
* -# ISC_L_DSA^ISC_F_FINAL_DSA^ISC_ERR_VERIFY_DSA_FAIL : 검증 실패
*/
ISC_API ISC_STATUS ISC_Final_DSA(ISC_DSA_UNIT *dsa, uint8 *r, int *rLen,  uint8 *s, int *sLen);

/*!
* \brief
* ISC_DSA 전자서명의 서명값 생성
* \param dsa
* ISC_DSA_UNIT 구조체 포인터
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
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_INIT_PRNG_FAIL : INIT PRNG 연산 실패
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL 연산 실패
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_NULL_INPUT : : NULL 입력값 입력
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_FINAL_DIGEST_FAIL : FINAL DIGEST 연산 실패
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL 연산 실패
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL 연산 실패
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_GET_RAND_DSA_BIGINT_FAIL : 난수생성 실패
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : MOD EXP MONT BIGINT 연산 실패
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_MOD_BIGINT_FAIL : MOD BIGINT 연산 실패
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_MOD_INVERSE_BIGINT_FAIL : MOD INVERSE BIGINT 연산 실패
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY -> BIGINT 변환 실패
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_MOD_MTP_BIGINT_FAIL : MOD MTP BIGINT 연산 실패
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_ADD_BIGINT_FAIL : ADD BIGINT 연산 실패
*/
ISC_API ISC_STATUS ISC_Sign_DSA(ISC_DSA_UNIT *dsa, uint8 *r, int *rLen, uint8 *s, int *sLen);

/*!
* \brief
* ISC_DSA 전자서명의 서명값 검증
* \param dsa
* ISC_DSA_UNIT 구조체 포인터
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
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL 연산 실패
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_FINAL_DIGEST_FAIL : FINAL DIGEST 연산 실패
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY -> BIGINT 변환 실패
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_MOD_INVERSE_BIGINT_FAIL : MOD INVERSE BIGINT 연산 실패
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_MALLOC : 동적 메모리 할당 실패
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_MOD_MTP_BIGINT_FAIL : MOD MTP BIGINT 연산 실패
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL 연산 실패
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : MOD EXP MONT BIGINT 연산 실패
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_MOD_BIGINT_FAIL : MOD BIGINT 연산 실패
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_VERIFY_DSA_FAIL : 검증 실패
*/
ISC_API ISC_STATUS ISC_Verify_DSA(ISC_DSA_UNIT *dsa, uint8 *r,  int rLen, uint8 *s, int sLen);

/*!
* \brief
* 지정된 소수 p의 길이에 기반한 ISC_DSA Parameters p, q, g 생성 함수
* \param dsa
* ISC_DSA_UNIT 구조체 포인터
* \param p_bits
* ISC_DSA 소수 p의 길이
* \param user_seed
* 사용자 지정 랜덤 seed값(20 bytes), NULL은 알고리즘 내에서 seed를 임의로 지정
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_SUB_OPERATION_FAILURE : 내부함수 연산 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL 연산 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL 연산 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_MALLOC : 동적 메모리 할당 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_LEFT_SHIFT_BIGINT_FAIL : LEFT SHIFT BIGINT 연산 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_INIT_PRNG_FAIL : INIT PRNG 연산 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_INIT_DIGEST_FAIL : INIT DIGEST 연산 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_GET_RAND_FAIL : 난수생성 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST 연산 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_FINAL_DIGEST_FAIL : FINAL DIGEST 연산 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY -> BIGINT 변환 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_ADD_BIGINT_FAIL : ADD BIGINT 연산 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_COPY_BIGINT_FAIL : COPY BIGINT 연산 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_MOD_BIGINT_FAIL : MOD BIGINT 연산 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_SUB_BIGINT_FAIL : SUB BIGINT 연산 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_DIV_BIGINT_FAIL : DIV BIGINT 연산 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_SET_BIGINT_FAIL : SET BIGINT 연산 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : MOD EXP MONT BIGINT 연산 실패
*/
ISC_API ISC_STATUS ISC_Generate_DSA_Params(ISC_DSA_UNIT *dsa, int digest_alg, int p_bits, uint8* user_seed);

/*!
* \brief
* 입력받은 ISC_DSA_UNIT에 저장된 p, q, g 값을 토대로 비밀값 x와 공개값 y 생성
* \param dsa
* ISC_DSA_UNIT 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_KEY_PAIR^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_KEY_PAIR^ISC_ERR_MEMORY_ALLOC : 동적 메모리 할당 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_KEY_PAIR^ISC_ERR_INIT_PRNG_FAIL : INIT PRNG 연산 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_KEY_PAIR^ISC_ERR_GET_RAND_DSA_BIGINT_FAIL : 난수생성 실패
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_KEY^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : MOD EXP MONT BIGINT 연산 실패
*/
ISC_API ISC_STATUS ISC_Generate_DSA_Key_Pair(ISC_DSA_UNIT *dsa);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_DSA_Params, (ISC_DSA_UNIT *dsa, const ISC_BIGINT* p, const ISC_BIGINT* q, const ISC_BIGINT* g, const ISC_BIGINT* x, const ISC_BIGINT* y), (dsa, p, q, g, x, y), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_DSA_UNIT*, ISC_New_DSA, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_DSA, (ISC_DSA_UNIT *unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_DSA, (ISC_DSA_UNIT *unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_DSA, (ISC_DSA_UNIT *dsa, int digest_alg, int sign, uint8* user_seed, int user_seedLen), (dsa, digest_alg, sign, user_seed, user_seedLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Update_DSA, (ISC_DSA_UNIT *dsa, const uint8 *data, int dataLen), (dsa, data, dataLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Final_DSA, (ISC_DSA_UNIT *dsa, uint8 *r, int *rLen,  uint8 *s, int *sLen), (dsa, r, rLen,  s, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Sign_DSA, (ISC_DSA_UNIT *dsa, uint8 *r, int *rLen, uint8 *s, int *sLen), (dsa, r, rLen, s, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Verify_DSA, (ISC_DSA_UNIT *dsa, uint8 *r,  int rLen, uint8 *s, int sLen), (dsa, r, rLen, s, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_DSA_Params, (ISC_DSA_UNIT *dsa, int digest_alg, int p_bits, uint8* user_seed), (dsa, digest_alg, p_bits, user_seed), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_DSA_Key_Pair, (ISC_DSA_UNIT *dsa), (dsa), ISC_ERR_GET_ADRESS_LOADLIBRARY );

#endif

#ifdef  __cplusplus
}
#endif
#endif



