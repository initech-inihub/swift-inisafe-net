/*!
* \file kcdsa.h
* \brief kcdsa 헤더파일
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_KCDSA_H
#define HEADER_KCDSA_H


#include "biginteger.h"
#include "foundation.h"


#ifdef ISC_NO_HAS160
#define ISC_NO_KCDSA
#endif

#ifdef ISC_NO_KCDSA
#error ISC_KCDSA is disabled.
#endif

#define ISC_KCDSA_SIGN				1			/*!< ISC_KCDSA_SIGN*/
#define ISC_KCDSA_VERIFY			0			/*!< ISC_KCDSA_VERIFY*/

/*ISC_KCDSA Alias				0x40000000 ------------------------------------------------ */
#define ISC_KCDSA				0x40000000   /*!< ISC_KCDSA 알고리즘 ID */

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* ISC_KCDSA 알고리즘을 위한 구조체
*/
struct isc_kcdsa_st	{
	ISC_DIGEST_UNIT *d_unit;			/*!< ISC_DIGEST_UNIT*/
	ISC_PRNG_UNIT *prng;				/*!< ISC_PRNG_UNIT*/
	ISC_BIGINT *p;						/*!< 소수 p*/
	ISC_BIGINT *q;						/*!< 소수 q*/
	ISC_BIGINT *g;						/*!< Generator g*/
	ISC_BIGINT* x;						/*!< 비밀키 x */
	ISC_BIGINT* y;						/*!< 공개 파라미터 y = g^x*/
	ISC_BIGINT* z;						/*!< ISC_KCDSA z 값 */
	ISC_BIGINT* j;						/*!< ISC_KCDSA j 값 */
	int count;						/*!< 키 생성 과정에서 count저장 */				
	uint8* seed;					/*!< 랜덤 seed 저장*/
	int seedLen;					/*!< 랜덤 seed 길이*/
	int is_private;					/*!< Public : 0 , Private : 1*/
	ISC_BIGINT_POOL *pool;				/*!< 연산 효율을 위한 풀 */
	ISC_BIGINT *XKEY;					/*!< ISC_BIGINT XKEY의 포인터*/
	ISC_BIGINT *XSEED;					/*!< ISC_BIGINT XSEED의 포인터*/
	uint8 *oupri;					/*!< XSEED의 사용자 임의 입력값 (OUPRI) */
	int oupri_len;					/*!< oupri의 길이 */
	ISC_BIGINT *small_g;				/* G값을 만들기 위한 난수 g값 */	
};

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* KCDSA_UNIT 구조체의 메모리 할당
* \returns
* ISC_KCDSA_UNIT 구조체
*/
ISC_API ISC_KCDSA_UNIT* ISC_New_KCDSA(void);
/*!
* \brief
* KCDSA_UNIT 메모리 해제 함수
* \param unit
* 메모리 해제할 ISC_KCDSA_UNIT
*/
ISC_API void ISC_Free_KCDSA(ISC_KCDSA_UNIT* unit);
/*!
* \brief
* ISC_KCDSA_UNIT 메모리 초기화 함수
* \param unit
* 초기화 할 ISC_KCDSA_UNIT
*/
ISC_API void ISC_Clean_KCDSA(ISC_KCDSA_UNIT *unit);

/*!
* \brief
* KCDSA Parameter 입력
* \param kcdsa
* Parameter가 입력될 ISC_KCDSA_UNIT
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
* -# ISC_L_KCDSA^ISC_F_SET_KCDSA_PARAMS^ISC_ERR_INVALID_INPUT : 잘못된 입력값 입력
* -# ISC_L_KCDSA^ISC_F_SET_KCDSA_PARAMS^ISC_ERR_SUB_OPERATION_FAILURE : 내부함수 연산(BIGINT) 실패
* -# ISC_Mod_Exp_Mont_BIGINT() 애러코드
*/
ISC_API ISC_STATUS ISC_Set_KCDSA_Params(ISC_KCDSA_UNIT *kcdsa,
					 const ISC_BIGINT* p,
					 const ISC_BIGINT* q,
					 const ISC_BIGINT* g,
					 const ISC_BIGINT* x,
					 const ISC_BIGINT* y);

/*!
* \brief
* KCDSA 전자서명 알고리즘 초기화 (해시 알고리즘 입력)
* \param kcdsa
* 초기화 될 ISC_KCDSA_UNIT
* \param sign
* (ISC_KCDSA_SIGN)1 : 서명, (ISC_KCDSA_VERIFY)0 : 검증
* \param digest_alg
* HASH 알고리즘
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_KCDSA^ISC_F_INIT_KCDSA_EX^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_KCDSA^ISC_F_INIT_KCDSA_EX^ISC_ERR_NOT_SUPPORTED : 지원하지 않는 키 길이 입력
* -# ISC_L_KCDSA^ISC_F_INIT_KCDSA_EX^ISC_ERR_NOT_PROVEN_ALGORITHM : 검증모드일때 비검증 알고리즘 사용
* -# ISC_L_KCDSA^ISC_F_INIT_KCDSA_EX^ISC_ERR_MEM_ALLOC : 동적 메모리 할당 실패
* -# ISC_L_KCDSA^ISC_F_INIT_KCDSA_EX^ISC_ERR_INIT_DIGEST_FAIL : ISC_Init_DIGEST() 연산 실패
*/
ISC_API ISC_STATUS ISC_Init_KCDSA_Ex(ISC_KCDSA_UNIT *kcdsa, int sign, int digest_alg);

/*!
* \brief
* KCDSA 전자서명 알고리즘 초기화
* \param kcdsa
* 초기화 될 ISC_KCDSA_UNIT
* \param sign
* (ISC_KCDSA_SIGN)1 : 서명, (ISC_KCDSA_VERIFY)0 : 검증
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_KCDSA^ISC_F_INIT_KCDSA^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_KCDSA^ISC_F_INIT_KCDSA^ISC_ERR_MEM_ALLOC : 동적 메모리 항당 실패 
* -# ISC_L_KCDSA^ISC_F_INIT_KCDSA^ISC_ERR_INIT_DIGEST_FAIL : ISC_Init_DIGEST() 연산 실패
*/
ISC_API ISC_STATUS ISC_Init_KCDSA(ISC_KCDSA_UNIT *kcdsa, int sign);

/*!
* \brief
* ISC_KCDSA 전자서명 메시지 입력(Update) 함수
* \param kcdsa
* ISC_KCDSA_UNIT 구조체 포인터
* \param data
* 입력될 데이터(여러번 입력 가능)
* \param dataLen
* 데이터의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_KCDSA^ISC_F_UPDATE_KCDSA^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_KCDSA^ISC_F_UPDATE_KCDSA^ISC_ERR_SUB_OPERATION_FAILURE : 내부함수 연산(z_KCDSA) 실패
* -# ISC_L_KCDSA^ISC_F_UPDATE_KCDSA^ISC_ERR_MALLOC : 동적 메모리 할당 실패
* -# ISC_L_KCDSA^ISC_F_UPDATE_KCDSA^ISC_ERR_SUB_OPERATION_FAILURE : 내부함수 BIGINT 연산 실패
* -# ISC_L_KCDSA^ISC_F_UPDATE_KCDSA^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST 연산 실패
*/
ISC_API ISC_STATUS ISC_Update_KCDSA(ISC_KCDSA_UNIT *kcdsa, const uint8 *data, uint32 dataLen);

/*!
* \brief
* KCDSA 전자서명의 서명값 생성 / 검증 함수
* \param kcdsa
* ISC_KCDSA_UNIT 구조체 포인터
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
* -# ISC_L_KCDSA^ISC_F_FINAL_KCDSA^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_KCDSA^ISC_F_FINAL_KCDSA^ISC_ERR_NOT_SUPPORTED : 지원하지 않는 키 길이 입력
* -# ISC_Sign_KCDSA()의 에러코드
* -# ISC_Verify_KCDSA()의 에러코드
*/
ISC_API ISC_STATUS ISC_Final_KCDSA(ISC_KCDSA_UNIT *kcdsa, uint8 *r, int *rLen,  uint8 *s, int *sLen);

/*!
* \brief
* ISC_KCDSA 전자서명의 서명값 생성
* \param kcdsa
* ISC_KCDSA_UNIT 구조체 포인터
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
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_FINAL_DIGEST_FAIL : FINAL DIGEST 연산 실패
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_GET_BIGINT_POOL_FAIL : BIGINT POOL 연산 실패
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_GET_RAND_FAIL : 랜덤 생성 실패
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : MOD EXP MONT BIGINT 연산 실패
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_INIT_DIGEST_FAIL : INIT DIGEST 연산 실패
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST 연산 실패
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY TO BIGINT 연산 실패
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_SUB_OPERATION_FAILURE : 내부함수 BIGINT 연산 실패
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_SUB_BIGINT_FAIL : SUB BIGINT 연산 실패
*/
ISC_API ISC_STATUS ISC_Sign_KCDSA(ISC_KCDSA_UNIT *kcdsa, uint8 *r, int *rLen, uint8 *s, int *sLen);

/*!
* \brief
* KCDSA 전자서명의 서명값 검증
* \param kcdsa
* ISC_KCDSA_UNIT 구조체 포인터
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
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_NULL_INPUT: NULL 입력값 입력
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_FINAL_DIGEST_FAIL : FINAL DIGEST 실패
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_SUB_OPERATION_FAILURE : 내부함수 연산(BIGINT) 실패
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL 연산 실패
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY TO BIGINT 연산 실패
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_IS_BIGINT_ZERO_FAIL : BIGINT의 사이즈가 ZERO
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_CMP_BIGINT_FAIL : Cmp BIGINT 연산  실패
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : Mod Exp MONT BIGINT 연산 실패
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_INIT_DIGEST_FAIL : INIT DIGEST 연산 실패
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST 연산 실패
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_VERIFY_FAILURE : 서명검증 실패
*/
ISC_API ISC_STATUS ISC_Verify_KCDSA(ISC_KCDSA_UNIT *kcdsa, uint8 *r, int *rLen, uint8 *s, int *sLen);

/*!
* \brief
* 지정된 소수 p, q의 길이에 기반한 KCDSA Parameters p, q, g 생성 함수 (해시알고리즘 입력)
* \param kcdsa
* ISC_KCDSA_UNIT 구조체 포인터
* \param digest_alg
* HASH 알고리즘
* \param p_bits
* ISC_KCDSA 소수 p의 길이
* \param q_bits
* ISC_KCDSA 소수 q의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_NULL_INPUT: NULL 입력값 입력
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_NOT_SUPPORTED: 지원하지 않는 키길이
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_NOT_PROVEN_ALGORITHM: 비검증 알고리즘
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_MEMORY_ALLOC: 동적 메모리 할당 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_RANDOM_GEN_FAILURE: 난수생성 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_BINARY_TO_BIGINT_FAIL: Binary -> Bigint 전환 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_IS_BIGINT_PRIME: 강한소수판정 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : MOD EXP MONT BIGINT 연산 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_SUB_OPERATION_FAILURE : 내부함수 연산(BIGINT/PRNG_KCDSA) 연산 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_MTP_BIGINT_FAIL : MTP BIGINT 연산 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_LEFT_SHIFT_BIGINT_FAIL : LEFT SHIFT BIGINT 연산 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_GET_RAND_FAIL : 난수생성 실패
*/
ISC_API ISC_STATUS ISC_Generate_KCDSA_Params_Ex(ISC_KCDSA_UNIT *kcdsa, int digest_alg, int p_bits, int q_bits);

/*!
* \brief
* 지정된 소수 p, q의 길이에 기반한 IKCDSA Parameters p, q, g 생성 함수
* \param kcdsa
* ISC_KCDSA_UNIT 구조체 포인터
* \param p_bits
* ISC_KCDSA 소수 p의 길이
* \param q_bits
* ISC_KCDSA 소수 q의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_NOT_SUPPORTED : 지원하지 않는 키길이
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_MEMORY_ALLOC : 동적 메모리 할당 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_INIT_PRNG_FAIL : INIT PRNG 연산 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_GET_RAND_FAIL : 난수생성 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_BINARY_TO_BIGINT_FAIL : Binary -> Bigint 전환 실패 
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_IS_BIGINT_PRIME : 강한소수판정 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_SUB_OPERATION_FAILURE : 내부함수 연산(BIGINT/PRNG_KCDSA) 연산 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_MTP_BIGINT_FAIL : MTP BIGINT 연산 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_LEFT_SHIFT_BIGINT_FAIL : LEFT SHIFT BIGINT 연산 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : MOD EXP MONT BIGINT 연산 실패
*/
ISC_API ISC_STATUS ISC_Generate_KCDSA_Params(ISC_KCDSA_UNIT *kcdsa, int p_bits, int q_bits);

/*!
* \brief
* 입력받은 ISC_KCDSA_UNIT의 P, Q, G 값을 이용해 비밀키 X, 공개키 Y 생성 (해시 알고리즘 입력 받음)
* \param unit
* ISC_KCDSA_UNIT 구조체 포인터
* \param digest_alg
* HASH 알고리즘
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR_EX^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR_EX^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL 연산 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR_EX^ISC_ERR_MEM_ALLOC : 동적 메모리 할당 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR_EX^ISC_ERR_GET_RAND_FAIL : 난수생성 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR_EX^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL 연산 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR_EX^ISC_ERR_MOD_INVERSE_BIGINT_FAIL : MOD INVERSE BIGINT 연산 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR_EX^ISC_ERR_SUB_OPERATION_FAILURE : 내부함수 연산(BIGINT) 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR_EX^ISC_ERR_KEY_GEN_FAIL : 키 유효성 검사 실패
*/
ISC_API ISC_STATUS ISC_Generate_KCDSA_Key_Pair_Ex(ISC_KCDSA_UNIT* unit, int digest_alg);

/*!
* \brief
* 입력받은 ISC_KCDSA_UNIT에 저장된 p, q, g 값을 토대로 비밀값 x와 공개값 y 생성
* \param unit
* ISC_KCDSA_UNIT 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR^ISC_ERR_MEM_ALLOC : 동적 메모리 할당 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR^ISC_ERR_INIT_PRNG_FAIL : INIT PRNG 연산 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR^ISC_ERR_GET_RAND_FAIL : 난수생성 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BITINT POOL 연산 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR^ISC_ERR_MOD_INVERSE_BIGINT_FAIL : MOD INVERSE BIGINT 연산 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR^ISC_ERR_SUB_OPERATION_FAILURE : 내부함수 연산(BIGINT) 실패
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR^ISC_ERR_KEY_GEN_FAIL : 키 유효성 검사 실패
*/
ISC_API ISC_STATUS ISC_Generate_KCDSA_Key_Pair(ISC_KCDSA_UNIT* unit);

/*!
* \brief
* ISC_KCDSA의 q 길이를 반환
* \param kcdsa
* ISC_KCDSA_UNIT 구조체 포인터
* \returns
* -# Modulas 길이
* -# ISC_INVALID_SIZE : KCDSA q 길이 가져오기 실패
*/
ISC_API int ISC_Get_KCDSA_Length(ISC_KCDSA_UNIT* kcdsa);


/*!
* \brief
* TIAS.KO-12.001/R1에 나오는 PRNG를 구하는 함수. x(0<x<q)를 ISC_BIGINT 형식으로 출력한다.
* \param unit
* ISC_KCDSA_UNIT 구조체의 포인터
* \param hash_id
* TIAS.KO-12.001/R1에 나오는 PRNG를 구하기 위한 해시 알고리즘
* \param output
* 랜덤 값을 저장하기 위한 ISC_BIGINT의 포인터
* \param q
* 랜덤 값의 범위를 결정하는 prime(mod q 연산을 통해 랜덤 값의 범위 결정) q의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_PRNG^ISC_F_GET_RAND^ISC_ERR_RANDOM_GEN_FAILURE : Fail
* -# ISC_L_PRNG^ISC_F_GET_RAND^ISC_ERR_NULL_XKEY_VALUE : XKEY가 NULL일 경우
*/
ISC_INTERNAL ISC_STATUS isc_Get_Rand_KCDSA_BIGINT(ISC_KCDSA_UNIT *unit, int hash_id, ISC_BIGINT *output, ISC_BIGINT *q);

ISC_INTERNAL ISC_STATUS isc_KCDSA_Mod_Hash(uint8 *ret, int *ret_len, ISC_KCDSA_UNIT *kcdsa, uint8 *hashed_value, int hashed_value_len);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_KCDSA_UNIT*, ISC_New_KCDSA, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_KCDSA, (ISC_KCDSA_UNIT* unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_KCDSA, (ISC_KCDSA_UNIT* unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_KCDSA_Params, (ISC_KCDSA_UNIT *kcdsa, const ISC_BIGINT* p, const ISC_BIGINT* q, const ISC_BIGINT* g, const ISC_BIGINT* x, const ISC_BIGINT* y), (kcdsa, p, q, g, x, y), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_KCDSA, (ISC_KCDSA_UNIT *kcdsa, int sign), (kcdsa, sign), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Update_KCDSA, (ISC_KCDSA_UNIT *kcdsa, const uint8 *data, uint32 dataLen), (kcdsa, data, dataLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Final_KCDSA, (ISC_KCDSA_UNIT *kcdsa, uint8 *r, int *rLen,  uint8 *s, int *sLen), (kcdsa, r, rLen, s, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Sign_KCDSA, (ISC_KCDSA_UNIT *kcdsa, uint8 *r, int *rLen, uint8 *s, int *sLen), (kcdsa, r, rLen, s, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Verify_KCDSA, (ISC_KCDSA_UNIT *kcdsa, uint8 *r, int *rLen, uint8 *s, int *sLen), (kcdsa, r, rLen, s, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_KCDSA_Params, (ISC_KCDSA_UNIT *kcdsa, int p_bits, int q_bits), (kcdsa, p_bits, q_bits), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_KCDSA_Key_Pair, (ISC_KCDSA_UNIT* unit), (unit), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(int, ISC_Get_KCDSA_Length, (ISC_KCDSA_UNIT* kcdsa), (kcdsa), 0 );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_KCDSA_Ex, (ISC_KCDSA_UNIT *kcdsa, int sign, int digest_alg), (kcdsa, sign, digest_alg), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_KCDSA_Params_Ex, (ISC_KCDSA_UNIT *kcdsa, int digest_alg, int p_bits, int q_bits), (kcdsa, digest_alg, p_bits, q_bits), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_KCDSA_Key_Pair_Ex, (ISC_KCDSA_UNIT* unit, int digest_alg), (unit,digest_alg), ISC_ERR_GET_ADRESS_LOADLIBRARY );
#endif

#ifdef  __cplusplus
}
#endif

#endif


