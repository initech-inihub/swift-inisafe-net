/*!
* \file cbcmac.h
* \brief
* CBC MAC 헤더 파일
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_CBCMAC_H
#define HEADER_CBCMAC_H

#include "foundation.h"
#include "mem.h"

#define ISC_CBC_MAC_PROVEN_MODE    1    /*!<  0: 비검증 모드, 1: 검증모드 */

#ifdef ISC_NO_CBC_MAC
#error ISC_CBC_MAC is disabled.
#endif

#define ISC_CBC_MAC_STATE_SIZE 64

#define ISC_CBC_MAC_AL_MASK		0x00F00000
#define ISC_CBC_MAC_AL1			0x00100000
#define ISC_CBC_MAC_AL2			0x00200000
#define ISC_CBC_MAC_AL3			0x00300000

/* PAD1 is Zero Padding */
#define ISC_CBC_MAC_PAD_MASK	0x0000000F
#define ISC_CBC_MAC_PAD1		0x00000001
#define ISC_CBC_MAC_PAD2		0x00000002

/*!
* \brief
* ISC_CBC_MAC에서 쓰이는 정보를 담고 있는 구조체
*/
struct isc_cbc_mac_st
{
	ISC_BLOCK_CIPHER_UNIT *cipher;			/*!< ISC_BLOCK_CIPHER_UNIT 구조체 포인터*/
	uint8 state[ISC_CBC_MAC_STATE_SIZE];	/*!< 각 단계별 값을 임시로 저장*/
	uint8 buf[ISC_CBC_MAC_STATE_SIZE];		/*!< 임시 저장*/
	int bufLen;							/*!< buf의 길이 */
	ISC_BLOCK_CIPHER_UNIT *cipher2;
	int mode;								/* 알고리즘과 패딩 방법 */
};

#ifdef  __cplusplus
extern "C" {
#endif


#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_CBC_MAC_UNIT 생성 함수
* \returns
* 생성된 ISC_CBC_MAC_UNIT의 포인터
*/
ISC_API ISC_CBC_MAC_UNIT* ISC_New_CBC_MAC_Unit();

/*!
* \brief
* ISC_CBC_MAC_UNIT 초기화 함수
* \param unit
* ISC_CBC_MAC_UNIT의 포인터
*/
ISC_API void ISC_Clean_CBC_MAC_Unit(ISC_CBC_MAC_UNIT *unit);

/*!
* \brief
* ISC_CBC_MAC_UNIT 제거 함수
* \param unit
* ISC_CBC_MAC_UNIT의 포인터
*/
ISC_API void ISC_Free_CBC_MAC_Unit(ISC_CBC_MAC_UNIT *unit);

/*!
* \brief
* ISC_CBC_MAC 초기화 함수
* \param unit
* ISC_CBC_MAC_UNIT의 포인터
* \param block_algo_id
* 블럭 알고리즘 ID
* \param key
* ISC_CBC_MAC 키의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()함수의 에러코드
* -# ISC_L_CBC_MAC^ISC_F_INIT_CBC_MAC^ISC_ERR_NOT_PROVEN_ALGORITHM : 검증모드에서 비검증 알고리즘 사용
* -# ISC_L_CBC_MAC^ISC_F_INIT_CBC_MAC^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_CBC_MAC^ISC_F_INIT_CBC_MAC^ISC_ERR_INIT_BLOCKCIPHER_FAIL : INIT BLOCKCIPHER 실패
*/
ISC_API ISC_STATUS ISC_Init_CBC_MAC(ISC_CBC_MAC_UNIT *unit, int cbc_algo_id, const uint8 *key);

/*!
* \brief
* ISC_CBC_MAC 업데이트 함수
* \param unit
* ISC_CBC_MAC_UNIT의 포인터
* \param in
* 입력값
* \param inLen
* 입력값의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_CBC_MAC^ISC_F_UPDATE_CBC_MAC^ISC_ERR_UPDATE_BLOCKCIPHER_FAIL : UPDATE BLOCKCIPHER 실패
*/
ISC_API ISC_STATUS ISC_Update_CBC_MAC(ISC_CBC_MAC_UNIT *unit, const uint8* in, int inLen);

/*!
* \brief
* ISC_CBC_MAC final 함수
* \param unit
* ISC_CBC_MAC_UNIT의 포인터
* \param out
* 출력값
* \param outLen
* 출력값의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_CBC_MAC^ISC_F_UPDATE_CBC_MAC^ISC_ERR_UPDATE_BLOCKCIPHER_FAIL : UPDATE BLOCKCIPHER 실패
*/
ISC_API ISC_STATUS ISC_Final_CBC_MAC(ISC_CBC_MAC_UNIT *unit, uint8* out, int* outLen);

/*!
* \brief
* CBC-MAC 단일 처리 함수
* \param block_algo_id
* CBC MAC에 사용될 블럭 암호의 Algo ID
* \param key
* 키값
* \param in
* 입력값
* \param inLen
* 입력값의 길이
* \param out
* 출력값 (MAC값)
* \param outLen
* 출력값의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_CBC_MAC^ISC_F_CBC_MAC^ISC_ERR_MEM_ALLOC : 동적 메모리 할당 실패
* -# ISC_L_CBC_MAC^ISC_F_CBC_MAC^ISC_ERR_INIT_FAILURE : INIT CBCMAC 실패
* -# ISC_L_CBC_MAC^ISC_F_CBC_MAC^ISC_ERR_UPDATE_FAILURE : UPDATE CBCMAC 실패
* -# ISC_L_CBC_MAC^ISC_F_CBC_MAC^ISC_ERR_FINAL_FAILURE :  FINAL CBCMAC 실패
*/
ISC_API ISC_STATUS ISC_CBC_MAC(int block_algo_id,uint8* key,uint8* in,int inLen,uint8* out, int* outLen);

#else
ISC_RET_LOADLIB_CRYPTO(ISC_CBC_MAC_UNIT*, ISC_New_CBC_MAC_Unit, (void), (), NULL );
ISC_RET_LOADLIB_CRYPTO(void, ISC_Clean_CBC_MAC_Unit, (ISC_CBC_MAC_UNIT *unit), (unit), 0 );
ISC_RET_LOADLIB_CRYPTO(void, ISC_Free_CBC_MAC_Unit, (ISC_CBC_MAC_UNIT *unit), (unit), 0 );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_CBC_MAC, (ISC_CBC_MAC_UNIT *unit, int block_algo_id, const uint8 *key), (unit, block_algo_id, key), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Update_CBC_MAC, (ISC_CBC_MAC_UNIT *unit, const uint8* in, int inLen), (unit, in, inLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Final_CBC_MAC, (ISC_CBC_MAC_UNIT *unit, uint8* out, int* outLen), (unit, out, outLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_CBC_MAC, (int block_algo_id,uint8* key,uint8* in,int inLen,uint8* out, int* outLen), (block_algo_id, key, in, inLen, out, outLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
#endif

#ifdef  __cplusplus
}
#endif

#endif /*HEADER_CBCMAC_H*/
