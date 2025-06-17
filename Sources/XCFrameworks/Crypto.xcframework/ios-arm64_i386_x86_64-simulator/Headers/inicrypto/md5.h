/*!
* \file md5.h
* \brief ISC_MD5 헤더파일
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_MD5_H
#define HEADER_MD5_H

#ifdef ISC_NO_MD5
#error ISC_MD5 is disabled.
#endif

#include "foundation.h"
#include "mem.h"

/*--------------------------------------------------*/
#define ISC_MD5_NAME			"MD5"
#define ISC_MD5_BLOCK_SIZE		64
#define ISC_MD5_DIGEST_LENGTH	16
#define ISC_MD5_INIT			isc_Init_MD5
#define ISC_MD5_UPDATE			isc_Update_MD5
#define ISC_MD5_FINAL			isc_Final_MD5
#define ISC_MD5_STATE_SIZE		sizeof(ISC_MD5_STATE)
/*--------------------------------------------------*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* ISC_MD5에서 쓰이는 정보를 담고 있는 구조체
*/
typedef struct isc_md5_state_st {
	uint8 buff[ISC_MD5_BLOCK_SIZE];
	uint64 len;
	uint32 len2;
	uint32 state[4];
	uint8 dataBuf[ISC_MD5_BLOCK_SIZE];
	uint8 dataBufLen;
} ISC_MD5_STATE;

/*!
* \brief
* ISC_MD5 초기화 함수
* \param state
* ISC_MD5_STATE 구조체의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_MD5^ISC_ERR_NULL_INPUT : 초기값을 NULL로 입력
* -# ISC_Crypto_Initialize()의 에러코드
*/
ISC_INTERNAL ISC_STATUS isc_Init_MD5(ISC_MD5_STATE *md5);

/*!
* \brief
* ISC_MD5 업데이트 함수
* \param state
* ISC_MD5_STATE 구조체의 포인터
* \param data
* 해쉬를 할 메시지의 포인터
* \param count
* 해쉬를 할 메시지의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_UPDATE_MD5^ISC_ERR_NULL_INPUT  : 초기값을 NULL로 입력
* -# LOCATION^ISC_F_UPDATE_MD5^ISC_ERR_SUB_OPERATION_FAILURE : compare 실패
*/
ISC_INTERNAL ISC_STATUS isc_Update_MD5(ISC_MD5_STATE *md5, const uint8 *data, uint32 count);

/*!
* \brief
* ISC_MD5 파이널 함수
* \param state
* ISC_MD5_STATE 구조체의 포인터
* \param out
* 해쉬의 결과를 저장할 버퍼의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_FINAL_MD5^ISC_ERR_SUB_OPERATION_FAILURE : compare 실패
*/
ISC_INTERNAL ISC_STATUS isc_Final_MD5(ISC_MD5_STATE *md5, uint8 *out);

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_MD5_H */


