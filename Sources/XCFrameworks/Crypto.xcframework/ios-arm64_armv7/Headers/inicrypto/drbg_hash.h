/*!
* \file drbg_hash.h
* \brief DRBG; Deterministic Random Bit Generator Algorithm
* \remarks
* NIST SP800-90 문서를 기준으로 작성 되었음.
* \author myoungjoong kim
* Copyright (c) 2012 by \<INITech\>
*/

#ifndef HEADER_DRBG_HASH_H
#define HEADER_DRBG_HASH_H

#include "foundation.h"

#ifdef  __cplusplus
extern "C" {
#endif /* __cplusplus */

/*!
* \brief
* Hash DRBG 초기화 함수
* \param drbg
* ISC_DRBG_UNIT 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_HASHDRBG^ISC_ERR_NOT_PROVEN_ALGORITHM : 검증모드대상 알고리즘이 아님
* -# LOCATION^ISC_F_INIT_HASHDRBG^ISC_ERR_NOT_SUPPORTED : 입력값이 지원하지 않는 파라미터임
* -# LOCATION^ISC_F_DIGEST^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
*/
ISC_INTERNAL ISC_STATUS isc_Init_HashDRBG(ISC_DRBG_UNIT *drbg);

/*!
* \brief
* HASH DRBG 인스턴스 함수
* \param drbg
* ISC_DRBG_UNIT 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INSTANTIATE_HASHDRBG^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
* -# LOCATION^ISC_F_INSTANTIATE_HASHDRBG^ISC_ERR_INPUT_BUF_TOO_BIG : 입력값이 버퍼 크기보다 큼
* -# LOCATION^ISC_F_INSTANTIATE_HASHDRBG^ISC_ERR_HASH_DF_FAIL : HASH DF 연산 실패
*/
ISC_INTERNAL ISC_STATUS isc_Instantiate_HashDRBG(ISC_DRBG_UNIT *drbg);

/*!
* \brief
* HASH DRBG Reseed 함수
* \param drbg
* ISC_DRBG_UNIT 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_RESEED_HASHDRBG^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
* -# LOCATION^ISC_F_RESEED_HASHDRBG^ISC_ERR_INPUT_BUF_TOO_BIG : 입력값이 버퍼 크기보다 큼
* -# LOCATION^ISC_F_RESEED_HASHDRBG^ISC_ERR_HASH_DF_FAIL : HASH DF 연산 실패
*/
ISC_INTERNAL ISC_STATUS isc_Reseed_HashDRBG(ISC_DRBG_UNIT *drbg);

/*!
* \brief
* DRBG 생성 함수
* \param drbg
* ISC_DRBG_UNIT 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_INPUT_BUF_TOO_BIG : 입력값이 버퍼 크기보다 큼
* -# LOCATION^ISC_F_DIGEST^ISC_ERR_MALLOC : 메모리 할당 실패
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_HASH_GEN_FAIL : HASH GEN 연산 실패
* -# LOCATION^ISC_F_DIGEST^ISC_ERR_INIT_DIGEST_FAIL : 해시 초기화 실패
* -# LOCATION^ISC_F_DIGEST^ISC_ERR_UPDATE_DIGEST_FAIL : 해시 업데이트 실패
* -# LOCATION^ISC_F_DIGEST^ISC_ERR_FINAL_DIGEST_FAIL : 해시 FINAL 실패
*/
ISC_INTERNAL ISC_STATUS isc_Generate_HashDRBG(ISC_DRBG_UNIT *drbg);

#ifdef  __cplusplus
}
#endif /* __cplusplus */

#endif /* HEADER_DRBG_HASH_H */
