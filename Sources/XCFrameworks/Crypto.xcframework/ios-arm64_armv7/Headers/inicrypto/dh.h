/*!
* \file dh.h
* \brief dh 헤더파일
* \author
* Copyright (c) 2013 by \<INITech\>
*/

#ifndef HEADER_DH_H
#define HEADER_DH_H

#include "biginteger.h"
#include "foundation.h"

#ifdef ISC_NO_HAS160
#define ISC_NO_DH
#endif

#ifdef ISC_NO_DH
#error ISC_DH is disabled.
#endif

#define ISC_DH_PROVEN_MODE  0    /*!<  0: 비검증 모드, 1: 검증모드 */

/*ISC_DH Alias				0x70000000 ------------------------------------------------ */
#define ISC_DH				0x70000000   /*!< ISC_DH 알고리즘 ID */

#define ISC_DH_PRIVATE_LEN		32		/*!< q값이 없을 때 디폴트 개인키 길이 */

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* ISC_DH 알고리즘을 위한 구조체
*/
struct isc_dh_params_st {
	ISC_BIGINT *p;					/*!< 소수 p*/
	ISC_BIGINT *q;					/*!< 소수 q*/
	ISC_BIGINT *g;					/*!< Generator g, 생성원*/
	ISC_BIGINT* j;					/*!< j 값 */
	ISC_BIGINT *small_g;			/*!< G값을 만들기 위한 난수 g값 */	
	int count;						/*!< 키 생성 과정에서 count저장 */				
	uint8* seed;					/*!< 랜덤 seed 저장*/
	int seedLen;					/*!< 랜덤 seed 길이*/
	ISC_BIGINT *XKEY;				/*!< ISC_BIGINT XKEY의 포인터*/
	ISC_BIGINT *XSEED;				/*!< ISC_BIGINT XSEED의 포인터*/
	uint8 *oupri;					/*!< XSEED의 사용자 임의 입력값 (OUPRI) */
	int oupri_len;					/*!< oupri의 길이 */
	ISC_BIGINT_POOL *pool;			/*!< 연산 효율을 위한 풀 */
};
typedef struct isc_dh_params_st ISC_DH_PARAMS_UNIT;

struct isc_dh_st {
	ISC_BIGINT *ra;					/*!< a의 개인키. 자신의 비밀키 */
	ISC_BIGINT *kta;				/*!< a의 공개키. 자신의 공개키 */
	ISC_BIGINT_POOL *pool;			/*!< 연산 효율을 위한 풀 */
	ISC_DH_PARAMS_UNIT *params;		/*!< 키생성에 사용되는 파라메터 */
};

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_DH_UNIT 구조체의 메모리 할당
* \returns
* ISC_DH_UNIT 구조체
*/
ISC_API ISC_DH_UNIT* ISC_New_DH(void);

/*!
* \brief
* ISC_DH_UNIT 메모리 해제 함수
* \param unit
* 메모리 해제할 ISC_DH_UNIT
*/
ISC_API void ISC_Free_DH(ISC_DH_UNIT* unit);

/*!
* \brief
* ISC_DH_UNIT 메모리 초기화 함수
* \param unit
* 초기화 할 ISC_DH_UNIT
*/
ISC_API void ISC_Clean_DH(ISC_DH_UNIT *unit);

/*!
* \brief
* ISC_DH_PARAMS_UNIT 구조체의 메모리 할당
* \returns
* ISC_DH_UNIT 구조체
*/
ISC_API ISC_DH_PARAMS_UNIT* ISC_New_DH_Params(void);

/*!
* \brief
* ISC_DH_PARAMS_UNIT 메모리 해제 함수
* \param unit
* 메모리 해제할 ISC_DH_UNIT
*/
ISC_API void ISC_Free_DH_Params(ISC_DH_PARAMS_UNIT* unit);

/*!
* \brief
* ISC_DH_PARAMS_UNIT 메모리 초기화 함수
* \param unit
* 초기화 할 ISC_DH_UNIT
*/
ISC_API void ISC_Clean_DH_Params(ISC_DH_PARAMS_UNIT *unit);

/*!
* \brief
* DH 구조체를 입력된 파라메터로 초기화 한다.
* \param dh
* 입력된 Parameter로 세팅될 ISC_DH_UNIT 구조체
* \param ra
* 자신의 개인키값
* \param kta
* 자신의 공개키값
* \param params
* 키생성에 필요한 공유 파라메터값
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# LOCATION^ISC_F_INIT_DH^ISC_ERR_INVALID_INPUT : 잘못된 입력값 입력
* -# LOCATION^ISC_F_INIT_DH^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : 공개키값 ktb의 연산 검증 실패
* -# LOCATION^ISC_F_INIT_DH^ISC_ERR_INVALID_KEY_PAIR : 공개키값 ktb의 연산 검증 실패
* -# ISC_L_DH^ISC_F_INIT_DH_PARAMS^ISC_ERR_SUB_OPERATION_FAILURE : 입력된 G값 검증 실패
*/
ISC_API ISC_STATUS ISC_Init_DH(ISC_DH_UNIT *dh,
					  const ISC_BIGINT *ra,
					  const ISC_BIGINT *kta,
					  const ISC_DH_PARAMS_UNIT *params);

/*!
* \brief
* DH Parameter를 입력된 파라메터로 초기화 한다.
* \param params
* Parameter가 입력될 ISC_DH_PARAMS_UNIT
* \param p
* 소수 p
* \param q
* 소수 q
* \param g
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_DH^ISC_F_INIT_DH_PARAMS^ISC_ERR_INVALID_INPUT : 잘못된 입력값 입력
* -# ISC_L_DH^ISC_F_INIT_DH^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : 입력된 G값 검증 실패
* -# ISC_L_DH^ISC_F_INIT_DH_PARAMS^ISC_ERR_SUB_OPERATION_FAILURE : 입력된 G값 검증 실패
*/
ISC_API ISC_STATUS ISC_Set_DH_Params(ISC_DH_PARAMS_UNIT *params,
							 const ISC_BIGINT *p,
							 const ISC_BIGINT *q,
							 const ISC_BIGINT *g);

/*!
* \brief
* 지정된 소수 p, q의 길이에 기반한 DH Parameters p, q, g 생성 함수 (해시알고리즘 입력)
* \param unit
* ISC_DH_UNIT 구조체 포인터
* \param digest_alg
* HASH 알고리즘
* \param p_bits
* ISC_DH 소수 p의 길이
* \param q_bits
* ISC_DH 소수 q의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_NULL_INPUT: NULL 입력값 입력
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_NOT_SUPPORTED: 지원하지 않는 키길이
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_NOT_PROVEN_ALGORITHM: 비검증 알고리즘
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_MEMORY_ALLOC: 동적 메모리 할당 실패
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_RANDOM_GEN_FAILURE: 난수생성 실패
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_BINARY_TO_BIGINT_FAIL: Binary -> Bigint 전환 실패
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_IS_BIGINT_PRIME: 강한소수판정 실패
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : MOD EXP MONT BIGINT 연산 실패
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_SUB_OPERATION_FAILURE : 내부함수 연산(BIGINT/PRNG_DH) 연산 실패
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_MTP_BIGINT_FAIL : MTP BIGINT 연산 실패
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_LEFT_SHIFT_BIGINT_FAIL : LEFT SHIFT BIGINT 연산 실패
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_GET_RAND_FAIL : 난수생성 실패
*/
ISC_API ISC_STATUS ISC_Generate_DH_Params(ISC_DH_PARAMS_UNIT *unit, int digest_alg, int p_bits, int q_bits);

/*!
* \brief
* 입력받은 ISC_DH_UNIT의 P, Q, G 값을 이용해 비밀키 ra, 공개키 kta 생성한다. 
* 개인키 ra가 dh 구조체에 이미 있으면, 개인키를 생성하지 않고 있는 키를 사용한다.
* 공개키는 무조건 새로 생성한다.
* \param unit
* ISC_DH_UNIT 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_DH^ISC_F_GENERATE_DH_KEY_PAIR^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_DH^ISC_F_GENERATE_DH_KEY_PAIR^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL 연산 실패
* -# ISC_L_DH^ISC_F_GENERATE_DH_KEY_PAIR^ISC_ERR_MEM_ALLOC : 동적 메모리 할당 실패
* -# ISC_L_DH^ISC_F_GENERATE_DH_KEY_PAIR^ISC_ERR_GET_RAND_FAIL : 난수생성 실패
* -# ISC_L_DH^ISC_F_GENERATE_DH_KEY_PAIR^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : 공개키 생성 실패
* -# ISC_L_DH^ISC_F_GENERATE_DH_KEY_PAIR^ISC_ERR_INVALID_KEY_PAIR : 생성된 공개키 검증 실패
* -# ISC_L_DH^ISC_F_GENERATE_DH_KEY_PAIR^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL 연산 실패
* -# ISC_L_DH^ISC_F_GENERATE_DH_KEY_PAIR^ISC_ERR_SUB_OPERATION_FAILURE : 내부함수 연산(BIGINT) 실패
* -# ISC_L_DH^ISC_F_GENERATE_DH_KEY_PAIR^ISC_ERR_KEY_GEN_FAIL : 키 유효성 검사 실패
*/
ISC_API ISC_STATUS ISC_Generate_DH_Key_Pair(ISC_DH_UNIT *dh);

/*!
* \brief
* 입력받은 ISC_DH_UNIT의 자신의 비밀키 ra, 상대방의 공개키 ktb를 이용해 공유키 kab를 생성한다. kab = ktb^ra mod p
* \param key
* 리턴할 uint8형의 공유키값
* \param key_len
* 리턴할 uint8형의 공유키값 길이
* \param dh
* 공유키를 만들기 위한 파라메터 값
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_DH^ISC_F_COMPUTE_KEY^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_DH^ISC_F_COMPUTE_KEY^ISC_ERR_MEM_ALLOC : 동적 메모리 할당 실패
* -# ISC_L_DH^ISC_F_COMPUTE_KEY^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : 공유키 생성 실패
*/
ISC_API ISC_STATUS ISC_Compute_Key(ISC_DH_UNIT *dh, ISC_BIGINT *pub_key, uint8 *key, int *key_len);

/*!
* \brief
* ISC_DH_PARAMS_UNIT의 q 길이를 반환
* \param unit
* ISC_DH_PARAMS_UNIT 구조체 포인터
* \returns
* -# Modulas 길이
* -# ISC_INVALID_SIZE : DH q 길이 가져오기 실패
*/
ISC_API int ISC_Get_DH_PARAMS_Length(ISC_DH_PARAMS_UNIT* unit);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_DH_UNIT*, ISC_New_DH, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_DH, (ISC_DH_UNIT* unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_DH, (ISC_DH_UNIT* unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_DH_UNIT*, ISC_New_DH_Params, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_DH_Params, (ISC_DH_PARAMS_UNIT* unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_DH_Params, (ISC_DH_PARAMS_UNIT* unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_DH, (ISC_DH_UNIT *dh, const ISC_BIGINT *ra, const ISC_BIGINT *kta, const ISC_DH_PARAMS_UNIT *params), (dh, ra, kab), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_DH_Params, (ISC_DH_PARAMS_UNIT *params, const ISC_BIGINT* p, const ISC_BIGINT* q, const ISC_BIGINT* g), (params, p, q, g), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_DH_Params, (ISC_DH_PARAMS_UNIT *unit, int digest_alg, int p_bits, int q_bits), (unit, digest_alg, p_bits, q_bits), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_DH_Key_Pair, (ISC_DH_UNIT* dh), (dh), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Compute_Key, (ISC_DH_UNIT *dh, ISC_BIGINT *pub_key, uint8 *key, int *key_len), (dh, pub_key, key, key_len), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(int, ISC_Get_DH_PARAMS_Length, (ISC_DH_PARAMS_UNIT* unit), (unit), 0 );
#endif

#ifdef  __cplusplus
}
#endif

#endif


