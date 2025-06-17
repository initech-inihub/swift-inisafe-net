/*!
* \file sha.h
* \brief entropy 헤더
* \author
* Copyright (c) 2012 by \<INITech\>
*/

#ifndef HEADER_ENTROPY_H
#define HEADER_ENTROPY_H

#if defined(NO_ENTROPY) || defined(ISC_NO_DRBG)
#error entropy is disabled.
#endif

#define ISC_ENTROPY_PROVEN_MODE  1    /*!<  0: 비검증 모드, 1: 검증모드 */

#include "foundation.h"
#include "mem.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* ENTROPY에서 쓰이는 정보를 담고 있는 구조체
*/

#define ISC_ENTROPY_ALLOC_SIZE		128
#define ISC_ENTROPY_DEVRANDOM_BYTES 64

#define ISC_MAX_ENTROPY_LENGTH		64
#define ISC_MAX_ENTROPY_SAVE		1024

/*!
* \brief
* ENTROPY 모드에 따라 수집하는 갯수가 달라진다.
*/
#define ISC_ENTROPY_NULL_MODE		0
#define ISC_ENTROPY_FAST_MODE		1
#define ISC_ENTROPY_NORMAL_MODE		2
#define ISC_ENTROPY_SLOW_MODE		3

#define ISC_ENTORPY_SECURITY_STRENGTHS_112	14
#define ISC_ENTORPY_SECURITY_STRENGTHS_128	16
#define ISC_ENTORPY_SECURITY_STRENGTHS_192	24
#define ISC_ENTORPY_SECURITY_STRENGTHS_256	32

struct isc_entropy_st {
	int status;							/* 구조체 현재 상태 */
	int collection_mode;				/* entropy를 수집하는 모드 */
	uint8 *entropy;						/* 반환할 entropy 데이터 */
	uint32 e_len;						/* 반환할 entropy 길이 */
	uint32 valid_len;					/* 유효한 entropy 길이 */
	uint32 buf_len; 					/* buf 데이터 길이 */
	uint32 buf_index;					/* 할당된 buf의 길이 */
	uint8 *buf;							/* 수집한 entropy 데이터 */
#ifdef ISC_DEBUG_PRINT_ENTROPY
	char name[128];					/* for cmvp 엔트로피 테스트 */
#endif
};

/*!* \brief
 * 입력된 길이만큼 시스템의 엔트로피를 수집하여 해시 후 리턴해주는 함수
 * \param *out
 * 생성된 랜덤 값을 저장하기 위한 배열의 포인터
 * \param out_len
 * 생성하길 원하는 랜덤 값의 길이(Byte)
 * \param collection_mode
 * 엔트로피 수집 모드(FAST, NORMAL, SLOW)
 * \param alg
 * 엔트로피를 해시할 알고리즘
 * \returns
 * -# ISC_SUCCESS : Success
 * -# LOCATION^ISC_F_GET_ENTROPY^ISC_ERR_NULL_INPUT: 초기값을 NULL로 입력
 * -# LOCATION^ISC_F_GET_ENTROPY^ISC_ERR_ENTROPY_FAIL: 엔트로피 수집 실패
 * -# LOCATION^ISC_F_GET_ENTROPY^ISC_ERR_COMPARE_FAIL: 출력된 길이 비교 실패
 */
ISC_INTERNAL ISC_STATUS isc_Get_ENTROPY(uint8 *out, uint32 out_len, uint32 collection_mode, int alg);

/*!* \brief
 * 입력된 안전한 길이만큼 시스템의 엔트로피를 수집하여 해시 후 리턴해주는 함수
 * \param **entropy_input
 * 생성된 엔트로피를 저장하기 위한 포인터주소
 * \param *entropy_input_length
 * 생성된 엔트로피의 길이(Byte)
 * \param security_len
 * 엔트로피의 보안강도 길이 (보안강도 길이에 따라 엔트로피 생성하는 길이가 달라진다)
 * (ISC_ENTORPY_SECURITY_STRENGTHS_112, ISC_ENTORPY_SECURITY_STRENGTHS_128, ISC_ENTORPY_SECURITY_STRENGTHS_192, ISC_ENTORPY_SECURITY_STRENGTHS_256)
 * \param collection_mode
 * 엔트로피 수집 모드(ISC_ENTROPY_FAST_MODE, ISC_ENTROPY_NORMAL_MODE, ISC_ENTROPY_SLOW_MODE)
 * \returns 
 * -# ISC_SUCCESS : Success
 * -# LOCATION^ISC_F_GET_ENTROPY_INPUT^ISC_ERR_INVALID_INPUT : 잘못된 입력값 입력
 * -# LOCATION^ISC_F_GET_ENTROPY_INPUT^ISC_ERR_ENTROPY_FAIL : 엔트로피 수집 실패
 * -# LOCATION^ISC_F_GET_ENTROPY_AND_NONCE_INPUT^ISC_ERR_COMPARE_FAIL: 엔트로피 연속성 검증 실패
 */
ISC_INTERNAL ISC_STATUS isc_Get_ENTROPY_Input(uint8 **entropy_input, int *entropy_input_length, int security_len, int collection_mode);

/*!* \brief
 * 입력된 안전한 길이만큼 시스템의 엔트로피와 Nonce를 만들어 리턴해주는 함수
 * \param **entropy_input
 * 생성된 엔트로피를 저장하기 위한 포인터주소
 * \param *entropy_input_length
 * 생성된 엔트로피의 길이(Byte)
 * \param **nonce_input
 * 생성된 Nonce를 저장하기 위한 포인터주소
 * \param *nonce_input_length
 * 생성된 Nonce의 길이(Byte)
 * \param security_len
 * 엔트로피의 보안강도 길이 (보안강도 길이에 따라 엔트로피 생성하는 길이가 달라진다)
 * (ISC_ENTORPY_SECURITY_STRENGTHS_112, ISC_ENTORPY_SECURITY_STRENGTHS_128, ISC_ENTORPY_SECURITY_STRENGTHS_192, ISC_ENTORPY_SECURITY_STRENGTHS_256)
 * \param collection_mode
 * 엔트로피 수집 모드(ISC_ENTROPY_FAST_MODE, ISC_ENTROPY_NORMAL_MODE, ISC_ENTROPY_SLOW_MODE)
 * \returns 
 * -# ISC_SUCCESS : Success
 * -# LOCATION^ISC_F_GET_ENTROPY_AND_NONCE_INPUT^ ISC_ERR_NULL_INPUT: NULL 입력값 입력
 * -# LOCATION^ISC_F_GET_ENTROPY_AND_NONCE_INPUT^ISC_ERR_INVALID_INPUT: 잘못된 입력값 입력
 * -# LOCATION^ISC_F_GET_ENTROPY_AND_NONCE_INPUT^ISC_ERR_ENTROPY_FAIL: 엔트로피 수집 실패
 * -# LOCATION^ISC_F_GET_ENTROPY_AND_NONCE_INPUT^ISC_ERR_COMPARE_FAIL: 엔트로피 연속성 검증 실패
 * -# LOCATION^ISC_F_CHECK_AND_GET_ENTROPY^ISC_ERR_CONDITION_TEST_FAIL : 조건부 난수발생기 엔트로피 시험 실패
 */
ISC_INTERNAL ISC_STATUS isc_Get_ENTROPY_Input_With_Nonce_Input(uint8 **entropy_input, int *entropy_input_length, uint8 **nonce_input, int *nonce_input_length, int security_len, int collection_mode);

/*!* \brief
 * 시스템의 엔트로피를 수집하여 리턴해주는 함수 
 * \param *unit
 * ISC_ENTROPY_UNIT 구조체의 포인터
 * \returns
 * -# ISC_SUCCESS : Success
 * -# ISC_FAIL : Fail
 */
ISC_INTERNAL ISC_STATUS isc_Collect_ENTROPY(ISC_ENTROPY_UNIT *unit);

/*!* \brief
 * 수집된 엔트로피를 버퍼에 저장하는 함수
 * \param *unit
 * ISC_ENTROPY_UNIT 구조체의 포인터
 * \param *buf
 * 버퍼에 저장될 수집된 엔트로피
 * \param len
 * 수집된 엔트로피 buf의 길이
 * \param add_len
 * 수집된 엔트로피 실제 변동 길이
 * \returns
 * -# ISC_SUCCESS : Success
 * -# LOCATION^ISC_F_ADD_ENTROPY^ISC_ERR_INVALID_INPUT: 잘못된 입력값 입력
 */
ISC_INTERNAL ISC_STATUS isc_Add_ENTROPY(ISC_ENTROPY_UNIT *unit, const void *buf, uint32 len, uint32 add_len);

ISC_INTERNAL void isc_Set_Print_Entropy(ISC_ENTROPY_UNIT *unit, char *name);

#ifdef ISC_DEBUG_PRINT_ENTROPY
ISC_API ISC_ENTROPY_UNIT *isc_New_ENTROPY_Unit(void);
ISC_API void isc_Clean_ENTROPY_Unit(ISC_ENTROPY_UNIT *unit);
ISC_API void isc_Free_ENTROPY_Unit(ISC_ENTROPY_UNIT *unit);
#else 
/*!
  * \brief
  * ISC_ENTROPY_UNIT 구조체의 메모리 할당
  * \returns
  * ISC_ENTROPY_UNIT 구조체
  */
ISC_INTERNAL ISC_ENTROPY_UNIT *isc_New_ENTROPY_Unit(void);

/*!
  * \brief
  * ISC_ENTROPY_UNIT 초기화 함수
  * \param unit
  * ISC_ENTROPY_UNIT의 포인터
  */
ISC_INTERNAL void isc_Clean_ENTROPY_Unit(ISC_ENTROPY_UNIT *unit);

/*!
  * \brief
  * ISC_ENTROPY_UNIT 메모리 해제 함수
  * \param unit
  * 메모리 해제할 ISC_ENTROPY_UNIT
  * \returns
  * -# ISC_SUCCESS : Success
  * -# others : 실패 (에러코드)
  */
ISC_INTERNAL void isc_Free_ENTROPY_Unit(ISC_ENTROPY_UNIT *unit);
#endif

#ifdef  __cplusplus
}
#endif

#endif/* HEADER_ENTROPY_H */


