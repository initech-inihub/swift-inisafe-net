/*!
* \file has160.h
* \brief ISC_HAS160 헤더파일
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_HAS160_H
#define HEADER_HAS160_H

#ifdef ISC_NO_HAS160
#error ISC_HAS160 is disabled.
#endif

#include "foundation.h"
#include "mem.h"

/*--------------------------------------------------*/
#define ISC_HAS160_NAME				"HAS160"
#define ISC_HAS160_BLOCK_SIZE		64
#define ISC_HAS160_DIGEST_LENGTH	20
#define ISC_HAS160_INIT				isc_Init_HAS160
#define ISC_HAS160_UPDATE			isc_Update_HAS160
#define ISC_HAS160_FINAL			isc_Final_HAS160
#define ISC_HAS160_STATE_SIZE		sizeof(ISC_HAS160_STATE)
/*--------------------------------------------------*/

#define ISC_HAS160_DWORD unsigned int
#define ISC_HAS160_BYTE unsigned char

#define ISC_HAS160_PROVEN_MODE    1    /*!<  0: 비검증 모드, 1: 검증모드 */

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* ISC_HAS160에서 쓰이는 정보를 담고 있는 구조체
*/
typedef struct isc_has160_state_st{
	uint32 state[5];
	uint32 length[2];
	uint8 data[64];
} ISC_HAS160_STATE;

/*!
* \brief
* ISC_HAS160 초기화 함수
* \param has160
* ISC_HAS160_STATE 구조체의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_HAS160^ISC_F_INIT_HAS160^ISC_ERR_NULL_INPUT : 초기값이 NULL인 경우
* -# ISC_Crypto_Initialize()의 에러코드
*/
ISC_INTERNAL ISC_STATUS isc_Init_HAS160(ISC_HAS160_STATE *has160);

/*!
* \brief
* ISC_HAS160 업데이트 함수
* \param has160
* ISC_HAS160_STATE 구조체의 포인터
* \param data
* 해쉬를 할 메시지의 포인터
* \param count
* 해쉬를 할 메시지의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_HAS160^ISC_F_UPDATE_HAS160^ISC_ERR_NULL_INPUT : 초기값이 NULL인 경우
*/
ISC_INTERNAL ISC_STATUS isc_Update_HAS160(ISC_HAS160_STATE *has160, const uint8 *data, uint32 count);

/*!
* \brief
* ISC_HAS160 파이널 함수
* \param has160
* ISC_HAS160_STATE 구조체의 포인터
* \param out
* 해쉬 결과를 저장할 버퍼의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_HAS160^ISC_F_FINAL_HAS160^ISC_ERR_NULL_INPUT : 초기값이 NULL인 경우
*/
ISC_INTERNAL ISC_STATUS isc_Final_HAS160(ISC_HAS160_STATE *has160, uint8* out);

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_HAS160_H */


