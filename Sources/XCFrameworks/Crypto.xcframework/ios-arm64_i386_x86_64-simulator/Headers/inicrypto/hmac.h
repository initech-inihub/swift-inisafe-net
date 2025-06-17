/*!
* \file hmac.h
* \brief HMAC 헤더파일
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_HMAC_H
#define HEADER_HMAC_H

#include "foundation.h"
#include "mem.h"
#include "digest.h"

#ifdef ISC_NO_HMAC
#error HMAC is disabled.
#endif

#define ISC_MAX_HMAC_BLOCK 256 /* HMAC 중 가장 큰 사이즈 : ISC_LSH512_BLOCK_SIZE */
#define ISC_OPAD 0x5C
#define ISC_IPAD 0x36

/*Flag Definition
 |---------------------------------------------------------------|
 |------------Algorithm Identification-----------|-------|-------|
 | 4bits | 4bits | 4bits | 4bits | 4bits | 4bits | 4bits | 4bits |
 |---------------------------------------------------------------|
--------------------------------------------------------------------------------- */
/*HMAC Alias					0x10000000 ------------------------------------------------*/
#define ISC_HMAC_NAME			"HMAC"
#define ISC_HMAC_ID				0x10000000
#define ISC_HMAC_SHA1			0x15000100                                                 /*!< ISC_HMAC_SHA1 알고리즘 ID*/
#define ISC_HMAC_SHA224			0x15000200												   /*!< ISC_HMAC_SHA224 알고리즘 ID*/
#define ISC_HMAC_SHA256			0x15000300												   /*!< ISC_HMAC_SHA256 알고리즘 ID*/
#define ISC_HMAC_SHA384			0x15000400												   /*!< ISC_HMAC_SHA384 알고리즘 ID*/
#define ISC_HMAC_SHA512			0x15000500												   /*!< ISC_HMAC_SHA512 알고리즘 ID*/
#define ISC_HMAC_SHA3_224		0x15000600												   /*!< ISC_HMAC_SHA3_224 알고리즘 ID*/
#define ISC_HMAC_SHA3_256		0x15000700												   /*!< ISC_HMAC_SHA3_256 알고리즘 ID*/
#define ISC_HMAC_SHA3_384		0x15000800												   /*!< ISC_HMAC_SHA3_384 알고리즘 ID*/
#define ISC_HMAC_SHA3_512		0x15000900												   /*!< ISC_HMAC_SHA3_512 알고리즘 ID*/
#define ISC_HMAC_MD5			0x16000100												   /*!< ISC_HMAC_MD5 알고리즘 ID*/
#define ISC_HMAC_HAS160			0x17000100												   /*!< ISC_HMAC_HAS160 알고리즘 ID*/
#define ISC_HMAC_MDC2			0x18000100												   /*!< ISC_HMAC_MDC2 알고리즘 ID*/
#define ISC_HMAC_LSH256_224		0x19000100												   /*!< ISC_HMAC_LSH256_224 알고리즘 ID*/
#define ISC_HMAC_LSH256_256		0x19000200												   /*!< ISC_HMAC_LSH256_256 알고리즘 ID*/
#define ISC_HMAC_LSH512_224		0x19001100												   /*!< ISC_HMAC_LSH512_224 알고리즘 ID*/
#define ISC_HMAC_LSH512_256		0x19001200												   /*!< ISC_HMAC_LSH512_256 알고리즘 ID*/
#define ISC_HMAC_LSH512_384		0x19001300												   /*!< ISC_HMAC_LSH512_384 알고리즘 ID*/
#define ISC_HMAC_LSH512_512		0x19001400												   /*!< ISC_HMAC_LSH512_512 알고리즘 ID*/

																				   
#ifdef  __cplusplus																   
extern "C" {
#endif

/*!
* \brief
* HMAC에서 쓰이는 정보를 담고 있는 구조체
*/
struct isc_hmac_unit_st
{
	uint32 algorithm;       /*!< HMAC 알고리즘 ID*/
	ISC_DIGEST_UNIT *md_unit; /*!< ISC_DIGEST_UNIT 구조체 포인터*/
	void* state_i;        /*!< HMAC state_i*/
	void* state_o;        /*!< HMAC state_o*/
	uint32 state_length;    /*!< 해쉬 STATE의 길이*/
	uint8 key[ISC_MAX_HMAC_BLOCK];       /*!< HMAC 키 배열*/ 
	int key_length;       /*!< HMAC 키의 길이*/ 
	int hmac_status;      /*!< HMAC 상태 정보 \n 0:Just Created \n 1:init done(ready to update) \n 2:in update progress \n 3:flushed(final)*/
	int unit_status;
	uint8 isproven;		  /*!< 암호화 검증에 사용된 알고리즘만 제한 여부 */
};

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_HMAC_UNIT 생성 함수
* \returns
* 생성된 ISC_HMAC_UNIT의 포인터
*/
ISC_API ISC_HMAC_UNIT *ISC_New_HMAC_Unit(void);


/*!
* \brief
* ISC_HMAC_UNIT 초기화 함수
* \param unit
* ISC_HMAC_UNIT의 포인터
*/
ISC_API void ISC_Clean_HMAC_Unit(ISC_HMAC_UNIT *unit);

/*!
* \brief
* ISC_HMAC_UNIT 구조체 메모리 해제 함수
* \param unit
* ISC_HMAC_UNIT의 포인터
*/
ISC_API void ISC_Free_HMAC_Unit(ISC_HMAC_UNIT *unit);

/*!
* \brief
* HMAC 초기화 함수
* \param unit
* ISC_HMAC_UNIT의 포인터
* \param digest_id
* 해쉬 알고리즘 ID
* \param key
* HMAC 키의 포인터
* \param keyLen
* HMA 키의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_HMAC^ISC_F_INIT_HMAC^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_HMAC^ISC_F_INIT_HMAC^ISC_ERR_INIT_DIGEST_FAIL : INIT DIGEST 실패
* -# ISC_L_HMAC^ISC_F_INIT_HMAC^ISC_ERR_SUB_OPERATION_FAILURE : 내부 연산 실패
* -# ISC_L_HMAC^ISC_F_INIT_HMAC^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST 실패
* -# ISC_L_HMAC^ISC_F_INIT_HMAC^ISC_ERR_FINAL_DIGEST_FAIL : FINAL DIGEST 실패
*/
ISC_API ISC_STATUS ISC_Init_HMAC(ISC_HMAC_UNIT *unit, int digest_id, uint8 *key, int keyLen);

/*!
* \brief
* HMAC 업데이트 함수
* \param unit
* ISC_HMAC_UNIT의 포인터
* \param data
* 해쉬를 할 메시지의 포인터
* \param len
* 해쉬를 할 메시지의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_HMAC^ISC_F_UPDATE_HMAC^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_HMAC^ISC_F_UPDATE_HMAC^ISC_ERR_INVALID_INPUT : 잘못된 입력값 입력
* -# ISC_L_HMAC^ISC_F_UPDATE_HMAC^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST 실패
*/
ISC_API ISC_STATUS ISC_Update_HMAC(ISC_HMAC_UNIT *unit, const uint8 *data, int len);

/*!
* \brief
* HMAC 파이널 함수
* \param unit
* ISC_HMAC_UNIT의 포인터
* \param digest
* 해쉬 결과를 저장할 버퍼의 포인터
* \param len
* 해쉬 결과의 길이를 저장할 변수의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_HMAC^ISC_F_FINAL_HMAC^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_HMAC^ISC_F_FINAL_HMAC^ISC_ERR_FINAL_DIGEST_FAIL : FINAL DIGEST 실패
* -# ISC_L_HMAC^ISC_F_FINAL_HMAC^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST 실패
*/
ISC_API ISC_STATUS ISC_Final_HMAC(ISC_HMAC_UNIT *unit, uint8 *digest, int *len);

/*!
* \brief
* ISC_Init_HMAC(), ISC_Update_HMAC(), final_HAMC()을 한 번에 하는 함수
* \param algorithm_id
* 해쉬 알고리즘 ID
* \param key
* HMAC 키의 포인터
* \param keyLen
* HMAC 키의 길이
* \param data
* 해쉬를 할 메시지의 포인터
* \param dataLen
* 해쉬를 할 메시지의 길이
* \param digest
* 해쉬 결과를 저장할 버퍼의 포인터
* \param digestLen
* 해쉬 결과의 길이를 저장할 변수의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_HMAC^ISC_F_HMAC^ISC_ERR_MEM_ALLOC : 동적 메모리 할당 실패
* -# ISC_L_HMAC^ISC_F_HMAC^ISC_ERR_INIT_FAILURE : INIT HMAC 실패
* -# ISC_L_HMAC^ISC_F_HMAC^ISC_ERR_UPDATE_FAILURE : UPDATE HMAC 실패
* -# ISC_L_HMAC^ISC_F_HMAC^ISC_ERR_FINAL_FAILURE : FINAL HMAC 실패
*/
ISC_API ISC_STATUS ISC_HMAC(int algorithm_id,
		 uint8 *key,
		 int keyLen,
		 const uint8 *data,
		 int dataLen,
		 uint8 *digest,
		 int *digestLen);

/*!
* \brief
* HMAC의 이름을 리턴하는 함수
* \param algo_id
* 해쉬 알고리즘 ID
* \returns
* -# HMAC 이름의 포인터 : Success
* -# NULL : Fail
*/
ISC_API char* ISC_Get_HMAC_Name(int algo_id);

/*!
* \brief
* ISC_HMAC_UNIT 생성 함수
* \param isproven 암호화 검증 모듈 제한 여부
* \returns
* 생성된 ISC_HMAC_UNIT의 포인터
*/
ISC_INTERNAL ISC_HMAC_UNIT *isc_New_HMAC_Unit_Ex(uint8 isproven);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_HMAC_UNIT*, ISC_New_HMAC_Unit, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_HMAC_Unit, (ISC_HMAC_UNIT *unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_HMAC_Unit, (ISC_HMAC_UNIT *unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_HMAC, (ISC_HMAC_UNIT *unit, int digest_id, uint8 *key, int keyLen), (unit, digest_id, key, keyLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Update_HMAC, (ISC_HMAC_UNIT *unit, const uint8 *data, int len), (unit, data, len), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Final_HMAC, (ISC_HMAC_UNIT *unit, uint8 *digest, int *len), (unit, digest, len), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_HMAC, (int algorithm_id, uint8 *key, int keyLen, const uint8 *data, int dataLen, uint8 *digest, int *digestLen), (algorithm_id, key, keyLen, data, dataLen, digest, digestLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(char*, ISC_Get_HMAC_Name, (int algo_id), (algo_id), NULL );

#endif

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_HMAC_H */


