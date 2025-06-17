/*!
* \file drbg.h
* \brief DRBG; Deterministic Random Bit Generator Algorithm
* \remarks
* NIST SP800-90 문서를 기준으로 작성 되었음.
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_DRBG_H
#define HEADER_DRBG_H

#include "foundation.h"
#include "mem.h"
#include "entropy.h"
#include "drbg.h"

#ifndef ISC_NO_DRBG

#ifndef ISC_NO_BIGINT
#include "biginteger.h"
#endif

#ifdef  __cplusplus
extern "C" {
#endif

/* DRBG Type */
#define ISC_DRBG_HASH_MODE						0
#define ISC_DRBG_HMAC_MODE						1
#define ISC_DRBG_CTR_MODE						2

/* under 2^35 bit */
#define ISC_DRBG_MAX_LENGTH						0x7ffffff0
#define ISC_DRBG_MAX_REQUEST_LENGTH				0x8000
#define ISC_DRBG_MAX_RESEED_COUNTER				0x5F5E100		/* 1억 (표준 MAX : 2^48) */

#define ISC_MAX_HASH_DRBG_OUTLEN_BYTES			ISC_SHA512_OUTLEN_BYTES
#define ISC_MAX_HASH_DRBG_SEED_LENGTH_BYTES		ISC_SHA512_SEED_LENGTH_BYTES

#define ISC_HAS160_SECURITY_STRENGTH_BITS		80
#define ISC_HAS160_SECURITY_STRENGTH_BYTES		10
#define ISC_HAS160_SEED_LENGTH_BYTES			55
#define ISC_HAS160_OUTLEN_BYTES					20

#define ISC_SHA1_SECURITY_STRENGTH_BITS			80
#define ISC_SHA1_SECURITY_STRENGTH_BYTES		10
#define ISC_SHA1_SEED_LENGTH_BYTES				55
#define ISC_SHA1_OUTLEN_BYTES					20

#define ISC_SHA224_SECURITY_STRENGTH_BITS		112
#define ISC_SHA224_SECURITY_STRENGTH_BYTES		14
#define ISC_SHA224_SEED_LENGTH_BYTES			55
#define ISC_SHA224_OUTLEN_BYTES					28

#define ISC_SHA256_SECURITY_STRENGTH_BITS		128
#define ISC_SHA256_SECURITY_STRENGTH_BYTES		16
#define ISC_SHA256_SEED_LENGTH_BYTES			55
#define ISC_SHA256_OUTLEN_BYTES					32

#define ISC_SHA384_SECURITY_STRENGTH_BITS		192
#define ISC_SHA384_SECURITY_STRENGTH_BYTES		24
#define ISC_SHA384_SEED_LENGTH_BYTES			111
#define ISC_SHA384_OUTLEN_BYTES					48

#define ISC_SHA512_SECURITY_STRENGTH_BITS		256
#define ISC_SHA512_SECURITY_STRENGTH_BYTES		32
#define ISC_SHA512_SEED_LENGTH_BYTES			111
#define ISC_SHA512_OUTLEN_BYTES					64

#define ISC_DRBG_NON_PREDICTION_RESISTANCE_MODE	0	/*!< 비예측 내성 */
#define ISC_DRBG_PREDICTION_RESISTANCE_MODE		1	/*!< 예측 내성 */

#define ISC_DRBG_PROVEN_MODE  		1		/*!<  0: 비검증 모드, 1: 검증모드 */

/* Entropy internal state */
typedef struct isc_drbg_entropy_input_st {
	uint8	status;
	int		collection_mode;
	int		entropy_input_len;
	int		nonce_len;
	int		personalization_string_len;
	uint8   *entropy_input;
	uint8   *nonce;
	uint8   *personalization_string;
} ISC_DRBG_ENTROPY_INPUT;

/*!
* \brief
* DRBG에서 쓰이는 정보를 담고 있는 구조체
* \remarks
*/
struct isc_drbg_st {
	int		type;
	int		status;
	int		algo_id;

	int		min_entropy;
	int		max_entropy;
	int		min_nonce;
	int		max_nonce;

	int		max_personal_string;
	int		max_additional_input;

	int		max_request;
	int		reseed_interval;

	int		block_len;
	int		security_len;

	uint8	*v;
	uint8	*c;

	int		seed_len;
	uint8	*seed;
	
	int		additional_input_len;
	uint8	*additional_input;

	int		returned_bytes_len;
	uint8	*returned_bytes;

	int		prediction_resistance_flag; 
	int		reseed_counter;
	
	uint8	rbg_block[ISC_MAX_HASH_DRBG_OUTLEN_BYTES];		/* 연속적 난수발생기 체크를 위한 block 저장 변수 */
	uint8	rbg_block_len;								/* 연속적 난수발생기 체크를 위한 block 길이 변수 */

	ISC_DRBG_ENTROPY_INPUT *entropy;
};

#define ISC_RAND_BYTES(x, y) ISC_Rand_Bytes((x), (y))

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* DRBG 랜덤 생성 후 리턴하는 함수
* \param *drbg_input
* 리턴할 랜덤값
* \param drbg_input_length
* 리턴할 랜덤값 길이
* \param operation_mode
* DRBG 운영 모드 (ISC_DRBG_HASH_MODE, ISC_DRBG_HMAC_MODE, ISC_DRBG_CTR_MODE)
* \param hash_id
* 난수생성 시 사용할 해쉬 알고리즘
* \param prediction_resistance_flag
* 예측내성 설정(예측내성 : ISC_DRBG_PREDICTION_RESISTANCE_MODE, 
* 비예측내성 : ISC_DRBG_NON_PREDICTION_RESISTANCE_MODE)
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_DRBG^ISC_F_RAND_BYTES_DRBG^ISC_ERR_MUTEX_LOCK_FAIL: Mutex Lock 실패
* -# ISC_L_DRBG^ISC_F_RAND_BYTES_DRBG^ISC_ERR_MEM_ALLOC: DRBG 구조체 할당 실패
* -# ISC_L_DRBG^ISC_F_RAND_BYTES_DRBG^ISC_ERR_MUTEX_UNLOCK_FAIL: Mutex Unlock 실패
* -# ISC_L_DRBG^ISC_F_RAND_BYTES_DRBG^ISC_ERR_INIT_DRBG_FAIL : INIT DRBG 실패
* -# ISC_L_DRBG^ISC_F_RAND_BYTES_DRBG^ISC_ERR_INSTANTIATE_DRBG_FAIL : INSTANTIATE DRBG 실패
* -# ISC_L_DRBG^ISC_F_RAND_BYTES_DRBG^ISC_ERR_GENERATE_DRBG_FAIL : GENERATE DRBG 실패
*/
ISC_API ISC_STATUS ISC_Rand_Bytes_DRBG(uint8 *drbg_input, int drbg_input_length, int operation_mode, int hash_id, int prediction_resistance_flag);

/*!
* \brief
* DRBG 난수 생성 후 리턴하는 함수
* \param *rand
* 리턴할 랜덤값
* \param length
* 리턴할 랜덤값 길이 입력
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS ISC_Rand_Bytes(uint8 *rand, int length);

/*!
* \brief
* DRBG 내부설정값(V, C 등) 삭제
* \returns
* -# 없음
*/
ISC_API void ISC_Uninstantiate_DRBG();

/*!
* \brief
* 랜덤한 수를 ISC_BIGINT 형식으로 얻기 위한 함수,
* NIST FIPS PUB186-2 Appendix 3.1 & 3.2 문서를 기준으로 작성 되었음.
* 랜덤 x(0<x<q)값을 구하기 위한 알고리즘으로
* 일반적인 랜덤 값을 얻을 때에는 mod q 연산이 불필요하기 때문에 mod
* q연산은 하지 않았음.
* \param output
* 랜덤 값을 저장하기 위한 ISC_BIGINT의 포인터
* \param bit_length
* 원하는 랜덤 값의 길이(bit)
* \returns
* -# ISC_Get_Rand()의 에러코드\n
* -# ISC_SUCCESS : Success\n
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_DRBG^ISC_F_GET_RAND_BIGINT_EX^ISC_ERR_GET_RAND_FAIL : 난수 생성 실패
* -# ISC_L_DRBG^ISC_F_GET_RAND_BIGINT_EX^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY_TO_BIGINT 실패
*/
ISC_API ISC_STATUS ISC_Get_Rand_BIGINT_Ex(ISC_BIGINT *output, int bit_length);

/*!
* \brief
* ISC_DRBG_ENTROPY_INPUT 생성 함수
* \returns
* 생성된 ISC_DRBG_ENTROPY_INPUT의 포인터
*/
 ISC_DRBG_ENTROPY_INPUT *isc_New_DRBG_ENTROPY_Input(void);

/*!
* \brief
* ISC_DRBG_ENTROPY_INPUT의 값 초기화 함수
* \param entropy
* ISC_DRBG_ENTROPY_INPUT 구조체의 포인터
*/
 void isc_Clean_DRBG_ENTROPY_Input(ISC_DRBG_ENTROPY_INPUT *entropy);

/*!
* \brief
* ISC_DRBG_ENTROPY_INPUT 삭제 함수
* \param entropy
* ISC_DRBG_ENTROPY_INPUT 구조체의 포인터
*/
 void isc_Free_DRBG_ENTROPY_Input(ISC_DRBG_ENTROPY_INPUT *entropy);

 ISC_STATUS isc_Get_Rand_Bytes_DRBG(uint8 *drbg_input, int drbg_input_length, int operation_mode, int hash_id, int prediction_resistance_flag, ISC_DRBG_ENTROPY_INPUT *entropy);

#ifndef ISC_CRYPTO_VS_TEST /* IUT 테스트 할때만 외부함수로 쓴다. */

/*!
* \brief
* ISC_DRBG_UNIT 생성 함수
* \returns
* 생성된 ISC_DRBG_UNIT의 포인터
*/
ISC_DRBG_UNIT *isc_New_DRBG_Unit(void);

/*!
* \brief
* ISC_DRBG_UNIT의 값 초기화 함수
* \param drbg
* ISC_DRBG_UNIT 구조체의 포인터
*/
 void isc_Clean_DRBG_Unit(ISC_DRBG_UNIT *drbg);

/*!
* \brief
* ISC_DRBG_UNIT 삭제 함수
* \param drbg
* ISC_DRBG_UNIT 구조체의 포인터
*/
 void isc_Free_DRBG_Unit(ISC_DRBG_UNIT *drbg);

/*!
* \brief
* DRBG 초기화 함수
* \param drbg
* ISC_DRBG_UNIT 구조체 포인터
* \param algo_id
* 해시 알고리즘 ISC_SHA1/ISC_SHA224/ISC_SHA256/ISC_SHA384/ISC_SHA512/ISC_HAS160
* \param operation_mode
* drbg 운영모드(ISC_DRBG_HASH_MODE)
* \param prediction_resistance_flag
* 예측내성 설정(예측내성 : ISC_DRBG_PREDICTION_RESISTANCE_MODE, 비예측내성 : ISC_DRBG_NON_PREDICTION_RESISTANCE_MODE)
* \param entropy_collection_mode
* 엔트로피 수집 모드(ISC_ENTROPY_FAST_MODE, ISC_ENTROPY_NORMAL_MODE, ISC_ENTROPY_SLOW_MODE)
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# LOCATION^ISC_F_INIT_DRBG^ISC_ERR_NULL_INPUT : 초기값을 NULL로 입력
* -# LOCATION^ISC_F_INIT_DRBG^ ISC_ERR_NOT_SUPPORTED: 지원하지 않는 알고리즘 입력
* -# LOCATION^ISC_F_INIT_HASHDRBG^ISC_ERR_NULL_INPUT : 초기값을 NULL로 입력
* -# LOCATION^ISC_F_INIT_HASHDRBG^ISC_ERR_NOT_PROVEN_ALGORITHM : 비검증 알고리즘 입력
* -# LOCATION^ISC_F_INIT_HASHDRBG^ISC_ERR_NOT_SUPPORTED : 지원하지 않는 알고리즘 입력
*/
 ISC_STATUS isc_Init_DRBG(ISC_DRBG_UNIT *drbg, int algo_id, int operation_mode, int prediction_resistance_flag, int entropy_collection_mode);

/*!
* \brief
* DRBG instantiate 함수
* \param drbg
* ISC_DRBG_UNIT 구조체 포인터
* \param requested_instantiation_security_strength 
* 사용자입력 보안강도길이
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INSTANTIATE_DRBG^ISC_ERR_NULL_INPUT: 초기값을 NULL로 입력
* -# LOCATION^ISC_F_INSTANTIATE_DRBG^ISC_ERR_COMPARE_FAIL: 데이터 비교 실패
* -# LOCATION^ISC_F_INSTANTIATE_DRBG^ISC_ERR_NOT_SUPPORTED: 지원하지 않는 알고리즘 입력
* -# LOCATION^ISC_F_INSTANTIATE_HASHDRBG^ISC_ERR_NULL_INPUT : 초기값을 NULL로 입력
* -# LOCATION^ISC_F_INSTANTIATE_HASHDRBG^ISC_ERR_INPUT_BUF_TOO_BIG : 버퍼보다 큰 입력
* -# LOCATION^ISC_F_INSTANTIATE_HASHDRBG^ISC_ERR_HASH_DF_FAIL : HASH DF 실패
*/
ISC_STATUS isc_Instantiate_DRBG(ISC_DRBG_UNIT *drbg, int requested_instantiation_security_strength);

/*!
* \brief
* DRBG Reseed 함수
* \param drbg
* ISC_DRBG_UNIT 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_RESEED_DRBG^ISC_ERR_NULL_INPUT: 초기값을 NULL로 입력
* -# LOCATION^ISC_F_RESEED_DRBG^ISC_ERR_COMPARE_FAIL: 데이터 비교 실패
* -# LOCATION^ISC_F_RESEED_DRBG^ISC_ERR_NOT_SUPPORTED: 지원하지 않는 알고리즘 입력
* -# LOCATION^ISC_F_RESEED_DRBG^ISC_ERR_SUB_OPERATION_FAILURE: 엔트로피 수집 실패
* -# LOCATION^ISC_F_RESEED_HASHDRBG^ISC_ERR_NULL_INPUT : 초기값을 NULL로 입력
* -# LOCATION^ISC_F_RESEED_HASHDRBG^ISC_ERR_INPUT_BUF_TOO_BIG: 버퍼보다 큰 입력
* -# LOCATION^ISC_F_RESEED_HASHDRBG^ISC_ERR_HASH_DF_FAIL : HASH DF 실패
*/
 ISC_STATUS isc_Reseed_DRBG(ISC_DRBG_UNIT *drbg);

/*!
* \brief
* DRBG 생성 함수
* \param drbg
* ISC_DRBG_UNIT 구조체 포인터
* \param *output
* 생성된 drbg 랜덤 값
* \param output_len
* 리턴할 랜덤값의 길이
* \param output_len
* 결과버퍼 길이
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_GENERATE_DRBG^ISC_ERR_NULL_INPUT: 초기값을 NULL로 입력
* -# LOCATION^ISC_F_GENERATE_DRBG^ISC_ERR_INVALID_INPUT: 잘못된 초기화값 입력
* -# LOCATION^ISC_F_GENERATE_DRBG^ISC_ERR_SUB_OPERATION_FAILURE: RESEED 연산 실패
* -# LOCATION^ISC_F_GENERATE_DRBG^ISC_ERR_NOT_SUPPORTED: 지원하지 않는 알고리즘 입력
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_NULL_INPUT: 초기값을 NULL로 입력
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_INPUT_BUF_TOO_BIG: 버퍼보다 큰 입력
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_MALLOC: 메모리 할당 실패
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_INIT_DIGEST_FAIL: 해시 초기화 실패
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_UPDATE_DIGEST_FAIL: 해시 업데이트 실패
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_FINAL_DIGEST_FAIL: 해시 파이널 실패
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_HASH_GEN_FAIL: HASH GEN 연산실패
*/
ISC_STATUS isc_Generate_DRBG(ISC_DRBG_UNIT *drbg, uint8 *output, int output_len);

/*!
* \brief
* isc_Instantiate_DRBG 함수의 입력값 세팅 함수 (필요시 사용)
* \param *drbg
* ISC_DRBG_UNIT 구조체 포인터
* \param *entropy_input
* 세팅할 entropy 입력값
* \param entropy_input_len
* 세팅할 entropy 입력값 길이
* \param *nonce_input
* 세팅할 nonce 입력값
* \param nonce_len
* 세팅할 nonce 입력값 길이
* \param *personalization_string
* 세팅할 personalization_string 입력값
* \param personalization_string_len
* 세팅할 personalization_string 입력값 길이
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_STATUS isc_Set_Instantiate_DRBG_Param(ISC_DRBG_UNIT *drbg, const uint8 *entropy_input, uint8 entropy_input_len, const uint8 *nonce, uint8 nonce_len, const uint8 *personalization_string, uint8 personalization_string_len);

/*!
* \brief
* isc_Reseed_DRBG 함수의 입력값 세팅 함수 (필요시 사용)
* \param *drbg
* ISC_DRBG_UNIT 구조체 포인터
* \param *additional_input
* 세팅할 additional_input 입력값
* \param additional_input_len
* 세팅할 additional_input 입력값 길이
* \param *entropy_pr_input
* 세팅할 entropy_pr 입력값
* \param entropy_pr_input_len
* 세팅할 entropy_pr 입력값 길이
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_STATUS isc_Set_Reseed_DRBG_Param(ISC_DRBG_UNIT *drbg, const uint8 *additional_input, uint8 additional_input_len, const uint8 *entropy_input_pr, uint8 entropy_input_pr_len);

/*!
* \brief
* isc_Generate_DRBG 함수의 입력값 세팅 함수 (필요시 사용)
* \param *drbg
* ISC_DRBG_UNIT 구조체 포인터
* \param *additional_input
* 세팅할 additional_input 입력값
* \param additional_input_len
* 세팅할 additional_input 입력값 길이
* \param *entropy_pr_input
* 세팅할 reseed 함수에 전달 될 entropy_pr 입력값
* \param entropy_pr_input_len
* 세팅할 reseed 함수에 전달 될 entropy_pr 입력값 길이
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
 ISC_STATUS isc_Set_Generate_DRBG_Param(ISC_DRBG_UNIT *drbg, const uint8 *additional_input, uint8 additional_input_len, const uint8 *entropy_input_pr, uint8 entropy_input_pr_len);

#else /* #ifndef ISC_CRYPTO_VS_TEST */

ISC_API ISC_DRBG_UNIT *isc_New_DRBG_Unit(void);
ISC_API void isc_Clean_DRBG_Unit(ISC_DRBG_UNIT *drbg);
ISC_API void isc_Free_DRBG_Unit(ISC_DRBG_UNIT *drbg);
ISC_API ISC_STATUS isc_Init_DRBG(ISC_DRBG_UNIT *drbg, int algo_id, int operation_mode, int prediction_resistance_flag, int entropy_collection_mode);
ISC_API ISC_STATUS isc_Instantiate_DRBG(ISC_DRBG_UNIT *drbg, int requested_instantiation_security_strength);
ISC_API ISC_STATUS isc_Reseed_DRBG(ISC_DRBG_UNIT *drbg);
ISC_API ISC_STATUS isc_Generate_DRBG(ISC_DRBG_UNIT *drbg, uint8 *output, int output_len);
ISC_API ISC_STATUS isc_Set_Instantiate_DRBG_Param(ISC_DRBG_UNIT *drbg, const uint8 *entropy_input, uint8 entropy_input_len, const uint8 *nonce, uint8 nonce_len, const uint8 *personalization_string, uint8 personalization_string_len);
ISC_API ISC_STATUS isc_Set_Reseed_DRBG_Param(ISC_DRBG_UNIT *drbg, const uint8 *additional_input, uint8 additional_input_len, const uint8 *entropy_input_pr, uint8 entropy_input_pr_len);
ISC_API ISC_STATUS isc_Set_Generate_DRBG_Param(ISC_DRBG_UNIT *drbg, const uint8 *additional_input, uint8 additional_input_len, const uint8 *entropy_input_pr, uint8 entropy_input_pr_len);

#endif /* #ifdef ISC_CRYPTO_VS_TEST */	

#else
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Rand_Bytes_DRBG, (uint8 *drbg_input, int drbg_input_length, int operation_mode, int hash_id int prediction_resistance_flag), (drbg_input, drbg_input_length, operation_mode, hash_id, prediction_resistance_flag), NULL );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_RAND_BYTES, (uint8 *rand, int length), (rand, length), NULL);
ISC_RET_LOADLIB_CRYPTO(void, ISC_Uninstantiate_DRBG, (void), (), NULL );
#endif

#ifdef  __cplusplus
}
#endif

#endif
#endif /* HEADER_DRBG_H */
