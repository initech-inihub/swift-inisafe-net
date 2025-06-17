/*!
* \file sha3.h
* \brief SHA3 알고리즘(224, 256, 384, 512) 헤더파일
* \author
* Copyright (c) 2021 by \<INITech\>
*/

#ifndef HEADER_SHA3_H
#define HEADER_SHA3_H


#define ISC_SHA3_PROVEN_MODE  	1    /*!<  0: 비검증 모드, 1: 검증모드 */

#include "foundation.h"
#include "mem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ISC_SHA3_ROUND		    24
#define ISC_SHA3_SUFFIX		    0x06
#define ISC_SHA3_SPONGE_BIT     1600	/* state 크기 (비트) */
#define ISC_SHA3_STATE_SIZE     200		/* state 크기 (바이트) */

/*--------------------------------------------------*/
#define ISC_SHA3_224_NAME				"SHA3-224"
#define ISC_SHA3_224_BLOCK_SIZE			144
#define ISC_SHA3_224_DIGEST_LENGTH		28
#define ISC_SHA3_224_INIT				isc_Init_SHA3_224
#define ISC_SHA3_224_UPDATE				isc_Update_SHA3_224
#define ISC_SHA3_224_FINAL				isc_Final_SHA3_224
#define ISC_SHA3_224_STATE_SIZE			sizeof(ISC_SHA3_STATE)
/*--------------------------------------------------*/

/*--------------------------------------------------*/
#define ISC_SHA3_256_NAME				"SHA3-256"
#define ISC_SHA3_256_BLOCK_SIZE			136
#define ISC_SHA3_256_DIGEST_LENGTH		32
#define ISC_SHA3_256_INIT				isc_Init_SHA3_256
#define ISC_SHA3_256_UPDATE				isc_Update_SHA3_256
#define ISC_SHA3_256_FINAL				isc_Final_SHA3_256
#define ISC_SHA3_256_STATE_SIZE			sizeof(ISC_SHA3_STATE)
/*--------------------------------------------------*/

/*--------------------------------------------------*/
#define ISC_SHA3_384_NAME				"SHA3-384"
#define ISC_SHA3_384_BLOCK_SIZE			104
#define ISC_SHA3_384_DIGEST_LENGTH		48
#define ISC_SHA3_384_INIT				isc_Init_SHA3_384
#define ISC_SHA3_384_UPDATE				isc_Update_SHA3_384
#define ISC_SHA3_384_FINAL				isc_Final_SHA3_384
#define ISC_SHA3_384_STATE_SIZE			sizeof(ISC_SHA3_STATE)
/*--------------------------------------------------*/

/*--------------------------------------------------*/
#define ISC_SHA3_512_NAME				"SHA3-512"
#define ISC_SHA3_512_BLOCK_SIZE			72
#define ISC_SHA3_512_DIGEST_LENGTH		64
#define ISC_SHA3_512_INIT				isc_Init_SHA3_512
#define ISC_SHA3_512_UPDATE				isc_Update_SHA3_512
#define ISC_SHA3_512_FINAL				isc_Final_SHA3_512
#define ISC_SHA3_512_STATE_SIZE			sizeof(ISC_SHA3_STATE)
/*--------------------------------------------------*/


#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* ISC_SHA3에서 쓰이는 정보를 담고 있는 구조체
*/
typedef struct isc_sha3_state_st {
	int bitSize;		/* 출력 해시값 길이(비트) */
	int outLen;			/* 출력 해시값 길이(바이트) */
	int Capacity;		/* 해시값 길이 * 2 */
	int Rate;			/* 블록 크기 */
	int end_offset;		
	uint8 state[ISC_SHA3_STATE_SIZE]; 
} ISC_SHA3_STATE;

/*!
* \brief
* SHA3 sponge 구조의 keccak absorb 함수
* \param sha3
* ISC_SHA3_STATE 구조체의 포인터
* \param input
* 해쉬를 할 메시지의 포인터
* \param inLen
* 해쉬를 할 메시지의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_UPDATE_SHA3_224^ISC_ERR_INVALID_INPUT : 입력값 오류
*/
ISC_INTERNAL ISC_STATUS keccak_absorb(ISC_SHA3_STATE *sha3, uint8* input, int inLen);

/*!
* \brief
* SHA3 sponge 구조의 keccak squeeze 함수
* \param sha3
* ISC_SHA3_STATE 구조체의 포인터
* \param output
* 해쉬의 결과를 저장할 버퍼의 포인터
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS keccak_squeeze(ISC_SHA3_STATE *sha3, uint8* output);

/*!
* \brief
* ISC_SHA3_224 초기화 함수
* \param sha3_224
* ISC_SHA3_STATE 구조체의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_SHA3_224^ISC_ERR_NULL_INPUT : 초기값을 NULL로 입력
*/
ISC_INTERNAL ISC_STATUS isc_Init_SHA3_224(ISC_SHA3_STATE *sha3_224);

/*!
* \brief
* ISC_SHA3_224 업데이트 함수
* \param sha3_224
* ISC_SHA3_STATE 구조체의 포인터
* \param input
* 해쉬를 할 메시지의 포인터
* \param inLen
* 해쉬를 할 메시지의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_SHA3_224^ISC_ERR_NULL_INPUT : 초기값을 NULL로 입력
* -# LOCATION^ISC_F_UPDATE_SHA3_224^ISC_ERR_INVALID_INPUT : 입력값 오류
* -# LOCATION^ISC_F_UPDATE_SHA3_224^ISC_ERR_UPDATE_FAILURE : absorb 함수 실패
*/
ISC_INTERNAL ISC_STATUS isc_Update_SHA3_224(ISC_SHA3_STATE *sha3_224, uint8 *input, int inLen);

/*!
* \brief
* ISC_SHA3_224 파이널 함수
* \param sha3_224
* ISC_SHA3_STATE 구조체의 포인터
* \param output
* 해쉬의 결과를 저장할 버퍼의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_FINAL_SHA3_224^ISC_ERR_NULL_INPUT : 초기값을 NULL로 입력
*/
ISC_INTERNAL ISC_STATUS isc_Final_SHA3_224(ISC_SHA3_STATE *sha3_224, uint8 *output);

/*!
* \brief
* ISC_SHA3_256 초기화 함수
* \param sha3_256
* ISC_SHA3_STATE 구조체의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_SHA3_256^ISC_ERR_NULL_INPUT : 초기값을 NULL로 입력
*/
ISC_INTERNAL ISC_STATUS isc_Init_SHA3_256(ISC_SHA3_STATE *sha3_256);

/*!
* \brief
* ISC_SHA3_256 업데이트 함수
* \param sha3_256
* ISC_SHA3_STATE 구조체의 포인터
* \param input
* 해쉬를 할 메시지의 포인터
* \param inLen
* 해쉬를 할 메시지의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_SHA3_256^ISC_ERR_NULL_INPUT : 초기값을 NULL로 입력
* -# LOCATION^ISC_F_UPDATE_SHA3_256^ISC_ERR_INVALID_INPUT : 입력값 오류
* -# LOCATION^ISC_F_UPDATE_SHA3_256^ISC_ERR_UPDATE_FAILURE : absorb 함수 실패
*/
ISC_INTERNAL ISC_STATUS isc_Update_SHA3_256(ISC_SHA3_STATE *sha3_256, uint8 *input, int inLen);

/*!
* \brief
* ISC_SHA3_256 파이널 함수
* \param sha3_256
* ISC_SHA3_STATE 구조체의 포인터
* \param output
* 해쉬의 결과를 저장할 버퍼의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_FINAL_SHA3_256^ISC_ERR_NULL_INPUT : 초기값을 NULL로 입력
*/
ISC_INTERNAL ISC_STATUS isc_Final_SHA3_256(ISC_SHA3_STATE *sha3_256, uint8 *output);

/*!
* \brief
* ISC_SHA3_384 초기화 함수
* \param sha3_384
* ISC_SHA3_STATE 구조체의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_SHA3_384^ISC_ERR_NULL_INPUT : 초기값을 NULL로 입력
*/
ISC_INTERNAL ISC_STATUS isc_Init_SHA3_384(ISC_SHA3_STATE *sha3_384);

/*!
* \brief
* ISC_SHA3_384 업데이트 함수
* \param sha3_384
* ISC_SHA3_STATE 구조체의 포인터
* \param input
* 해쉬를 할 메시지의 포인터
* \param inLen
* 해쉬를 할 메시지의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_SHA3_384^ISC_ERR_NULL_INPUT : 초기값을 NULL로 입력
* -# LOCATION^ISC_F_UPDATE_SHA3_384^ISC_ERR_INVALID_INPUT : 입력값 오류
* -# LOCATION^ISC_F_UPDATE_SHA3_384^ISC_ERR_UPDATE_FAILURE : absorb 함수 실패
*/
ISC_INTERNAL ISC_STATUS isc_Update_SHA3_384(ISC_SHA3_STATE *sha3_384, uint8 *input, int inLen);

/*!
* \brief
* ISC_SHA3_384 파이널 함수
* \param sha3_384
* ISC_SHA3_STATE 구조체의 포인터
* \param output
* 해쉬의 결과를 저장할 버퍼의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_FINAL_SHA3_384^ISC_ERR_NULL_INPUT : 초기값을 NULL로 입력
*/
ISC_INTERNAL ISC_STATUS isc_Final_SHA3_384(ISC_SHA3_STATE *sha3_384, uint8 *output);

/*!
* \brief
* ISC_SHA3_512 초기화 함수
* \param sha3_512
* ISC_SHA3_STATE 구조체의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_SHA3_512^ISC_ERR_NULL_INPUT : 초기값을 NULL로 입력
*/
ISC_INTERNAL ISC_STATUS isc_Init_SHA3_512(ISC_SHA3_STATE *sha3_512);

/*!
* \brief
* ISC_SHA3_512 업데이트 함수
* \param sha3_512
* ISC_SHA3_STATE 구조체의 포인터
* \param input
* 해쉬를 할 메시지의 포인터
* \param inLen
* 해쉬를 할 메시지의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_SHA3_512^ISC_ERR_NULL_INPUT : 초기값을 NULL로 입력
* -# LOCATION^ISC_F_UPDATE_SHA3_512^ISC_ERR_INVALID_INPUT : 입력값 오류
* -# LOCATION^ISC_F_UPDATE_SHA3_512^ISC_ERR_UPDATE_FAILURE : absorb 함수 실패
*/
ISC_INTERNAL ISC_STATUS isc_Update_SHA3_512(ISC_SHA3_STATE *sha3_512, uint8 *input, int inLen);

/*!
* \brief
* ISC_SHA3_512 파이널 함수
* \param sha3_512
* ISC_SHA3_STATE 구조체의 포인터
* \param output
* 해쉬의 결과를 저장할 버퍼의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_FINAL_SHA3_512^ISC_ERR_NULL_INPUT : 초기값을 NULL로 입력
*/
ISC_INTERNAL ISC_STATUS isc_Final_SHA3_512(ISC_SHA3_STATE *sha3_512, uint8 *output);


#ifdef  __cplusplus
}
#endif

#endif/* HEADER_SHA3_H */

