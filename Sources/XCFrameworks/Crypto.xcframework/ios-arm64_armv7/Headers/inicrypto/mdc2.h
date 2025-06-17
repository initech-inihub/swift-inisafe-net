/*!
* \file mdc2.h
* \brief ISC_MDC2 헤더파일
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_MDC2_H
#define HEADER_MDC2_H

#include "foundation.h"
#include "mem.h"

#define ISC_MDC2_PROVEN_MODE  1    /*!<  0: 비검증 모드, 1: 검증모드 */

#ifdef ISC_NO_MDC2
#error ISC_MDC2 is disabled.
#endif

#include "des.h"
#include "utils.h"

/*--------------------------------------------------*/
#define ISC_MDC2_NAME				"MDC2"
#define ISC_MDC2_BLOCK_SIZE			8
#define ISC_MDC2_DIGEST_LENGTH		16
#define ISC_MDC2_INIT				isc_Init_MDC2
#define ISC_MDC2_UPDATE				isc_Update_MDC2
#define ISC_MDC2_FINAL				isc_Final_MDC2
#define ISC_MDC2_STATE_SIZE			sizeof(ISC_MDC2_STATE)
/*--------------------------------------------------*/

#define ISC_CH2LONG(ch, lng) \
	(lng =((uint32)(*((ch)++))), \
	lng |= ((uint32)(*((ch)++))) << 8L, \
	lng |= ((uint32)(*((ch)++))) << 16L, \
	lng |= ((uint32)(*((ch)++))) << 24L)

#define ISC_LONG2CH(lng, ch) \
	(*((ch)++) = (uint8)(((lng)) & 0xff), \
	*((ch)++) = (uint8)(((lng) >> 8L) & 0xff), \
	*((ch)++) = (uint8)(((lng) >> 16L) & 0xff), \
	*((ch)++) = (uint8)(((lng) >> 24L) & 0xff))

#ifdef __cplusplus
extern "C" {
#endif

/*!
* \brief
* ISC_MDC2에서 쓰이는 정보를 담고 있는 구조체
* \remarks
* ISC_DES 암호화 과정에 쓰이는 key 두개 저장
*/
typedef struct isc_mdc2_state_st {
	uint32 index;
	uint8 message[8];
	uint8 mdc2DesKey1[8];
	uint8 mdc2DesKey2[8];
	int paddingType;
} ISC_MDC2_STATE;

/*!
* \brief
* ISC_MDC2 초기화 함수
* \param mdc2
* ISC_MDC2_STATE 구조체의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_ERR_NOT_PROVEN_ALGORITHM : 검증상태에서 비검증 알고리즘 호출 
* -# LOCATION^ISC_F_INIT_MDC2^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
* -# ISC_Crypto_Initialize()의 에러코드
*/
ISC_INTERNAL ISC_STATUS isc_Init_MDC2(ISC_MDC2_STATE *mdc2);

/*!
* \brief
* ISC_MDC2 업데이트 함수
* \param mdc2
* ISC_MDC2_STATE 구조체의 포인터
* \param data
* 해쉬를 할 메시지의 포인터
* \param count
* 해쉬를 할 메시지의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^UPDATE_MDC2^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
*/
ISC_INTERNAL ISC_STATUS isc_Update_MDC2(ISC_MDC2_STATE *mdc2, const uint8 *data, uint32 count);

/*!
* \brief
* ISC_MDC2 파이널 함수
* \param mdc2
* ISC_MDC2_STATE 구조체의 포인터
* \param md
* 해쉬의 결과를 저장할 버퍼의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -#  LOCATION^ISC_F_FINAL_MDC2^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
*/
ISC_INTERNAL ISC_STATUS isc_Final_MDC2(ISC_MDC2_STATE *mdc2, uint8 *md);

#ifdef __cplusplus
}
#endif

#endif/* HEADER_MDC2_H */

