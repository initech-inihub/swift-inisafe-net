/*!
* \file digest.h
* \brief ISC_DIGEST 알고리즘의 인터페이스 헤더파일
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_DIGEST_H
#define HEADER_DIGEST_H

#include "foundation.h"
#include "mem.h"

#ifndef ISC_NO_SHA
#include "sha.h"
#include "sha3.h"
#endif
#ifndef ISC_NO_HAS160
#include "has160.h"
#endif
#ifndef ISC_NO_MD5
#include "md5.h"
#endif
#if !defined (ISC_NO_MDC2) && !defined(ISC_NO_DES)
#include "mdc2.h"
#endif
#ifndef ISC_NO_LSH
#include "lsh.h"
#endif

/*!
Flag Definition
|---------------------------------------------------------------|
|------------Algorithm Identification-----------|-------|-------|
| 4bits | 4bits | 4bits | 4bits | 4bits | 4bits | 4bits | 4bits |
|---------------------------------------------------------------|
---------------------------------------------------------------------------------
*/
/*SHA Alias					0x05000000 ------------------------------------------------*/
#define ISC_SHA1			0x05000100												   /*!< ISC_SHA1 알고리즘 ID*/
#define ISC_SHA224			0x05000200												   /*!< ISC_SHA224 알고리즘 ID*/	
#define ISC_SHA256			0x05000300												   /*!< ISC_SHA256 알고리즘 ID*/	
#define ISC_SHA384			0x05000400												   /*!< ISC_SHA384 알고리즘 ID*/
#define ISC_SHA512			0x05000500                                                 /*!< ISC_SHA512 알고리즘 ID*/

#define ISC_SHA3_224		0x05000600												   /*!< ISC_SHA3_224 알고리즘 ID*/	
#define ISC_SHA3_256		0x05000700												   /*!< ISC_SHA3_256 알고리즘 ID*/	
#define ISC_SHA3_384		0x05000800												   /*!< ISC_SHA3_384 알고리즘 ID*/
#define ISC_SHA3_512		0x05000900                                                 /*!< ISC_SHA3_512 알고리즘 ID*/

/*MD Alias					0x06000000 ------------------------------------------------*/
#define ISC_MD5				0x06000100                                                 /*!< ISC_MD5 알고리즘 ID*/

/*HAS Alias					0x07000000 ------------------------------------------------*/
#define ISC_HAS160			0x07000100                                                 /*!< ISC_HAS160 알고리즘 ID*/

/*ISC_DES-Based Alias		0x08000000 ------------------------------------------------*/
#define ISC_MDC2			0x08000100                                                 /*!< ISC_MDC2 알고리즘 ID*/

/*LSH Alias					0x09000000 ------------------------------------------------*/
#define ISC_LSH256_224		0x09000100												   /*!< ISC_LSH256_224 알고리즘 ID*/
#define ISC_LSH256_256		0x09000200												   /*!< ISC_LSH256_256 알고리즘 ID*/

#define ISC_LSH512_224		0x09001100												   /*!< ISC_LSH512_224 알고리즘 ID*/
#define ISC_LSH512_256		0x09001200												   /*!< ISC_LSH512_256 알고리즘 ID*/
#define ISC_LSH512_384		0x09001300												   /*!< ISC_LSH512_384 알고리즘 ID*/
#define ISC_LSH512_512		0x09001400												   /*!< ISC_LSH512_512 알고리즘 ID*/

#define ISC_LSH224			ISC_LSH256_224
#define ISC_LSH256			ISC_LSH256_256
#define ISC_LSH384			ISC_LSH512_384
#define ISC_LSH512			ISC_LSH512_512


/*---------------------------------------------------------------------------------*/
#define ISC_MD5_PROVEN_MODE  1    /*!<  0: 비검증 모드, 1: 검증모드 */
/*---------------------------------------------------------------------------------*/


#define ISC_DEFINE_DIGEST(algo);\
	unit->md_size = algo##_DIGEST_LENGTH;\
	unit->block_size = algo##_BLOCK_SIZE;\
	unit->state_size = algo##_STATE_SIZE;\
	unit->init = (int(*)(void*))algo##_INIT;\
	unit->update = (int(*)(void*, const uint8*, uint32))algo##_UPDATE;\
	unit->final = (int(*)(void*, uint8*))algo##_FINAL;\
	unit->state = NULL;

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* 해쉬에서 쓰이는 정보를 담고 있는 구조체
*/
struct isc_digest_unit_st
{
	uint32 algorithm;												/*!< 해쉬 알고리즘 ID*/
	int block_size;												/*!< 해쉬 알고리즘의 Block Size*/
	int md_size;												/*!< 해쉬 결과 값의 길이*/
	void* state;												/*!< 해쉬의 STATE 구조체 포인터*/
	int state_size;												/*!< 해쉬의 STATE 크기*/
	int (*init)(void* state);									/*!< 해쉬의 init 콜백 함수 포인터*/
	int (*update)(void* state, const uint8 *data, uint32 count);  /*!< 해쉬의 update 콜백 함수 포인터*/
	int (*final)(void* state, uint8 *md);						/*!< 해쉬의 final 콜백 함수 포인터*/
	int unit_status;	
	uint8 isproven;												/*!< 암호화 검증에 사용된 알고리즘만 제한 여부 */
};

#define ISC_DIGESET_SIZE(unit)	((unit)->md_size)

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_DIGEST_UNIT 생성 함수
* \returns
* 생성된 ISC_DIGEST_UNIT의 포인터
*/
ISC_API ISC_DIGEST_UNIT *ISC_New_DIGEST_Unit(void);

/*!
* \brief
* ISC_DIGEST_UNIT 초기화 함수
* \param unit
* ISC_DIGEST_UNIT의 포인터
*/
ISC_API void ISC_Clean_DIGEST_Unit(ISC_DIGEST_UNIT *unit);

/*!
* \brief
* ISC_DIGEST_UNIT 삭제 함수
* \param unit
* ISC_DIGEST_UNIT의 포인터
*/
ISC_API void ISC_Free_DIGEST_Unit(ISC_DIGEST_UNIT *unit);


/*!
* \brief
* 해쉬 초기화 함수
* \param unit
* ISC_DIGEST_UNIT의 포인터
* \param alg_id
* 해쉬 알고리즘 ID
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드 
* -# ISC_L_DIGEST^ISC_F_INIT_DIGEST^ISC_ERR_INIT_FAILURE : NULL 입력값 입력
* -# ISC_L_DIGEST^ISC_F_INIT_DIGEST^ISC_ERR_SUB_OPERATION_FAILURE : 내부함수 연산(isc_Init_DIGEST_Alg) 실패
* -# ISC_L_DIGEST^ISC_F_INIT_DIGEST^ISC_ERR_INIT_DIGEST_FAIL : 알고리즘 인터페이스 INIT DIGEST 실패
*/
ISC_API ISC_STATUS ISC_Init_DIGEST(ISC_DIGEST_UNIT *unit, int alg_id);

/*!
* \brief
* 해쉬 업데이트 함수
* \param unit
* ISC_DIGEST_UNIT의 포인터
* \param message
* 해쉬를 할 메시지의 포인터
* \param messageLen
* 해쉬를 할 메시지의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_DIGEST^ISC_F_UPDATE_DIGEST^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_DIGEST^ISC_F_UPDATE_DIGEST^ISC_ERR_INVALID_INPUT : 0보다 작은 메시지 길이 입력
* -# ISC_L_DIGEST^ISC_F_UPDATE_DIGEST^ISC_ERR_UPDATE_DIGEST_FAIL : 알고리즘 인터페이스 UPDATE DIGEST 실패
*/
ISC_API ISC_STATUS ISC_Update_DIGEST(ISC_DIGEST_UNIT *unit, const uint8 *message, int messageLen);

/*!
* \brief
* 해쉬 파이널 함수
* \param unit
* ISC_DIGEST_UNIT의 포인터
* \param digest
* 해쉬 결과를 저장할 버퍼의 포인터
* \param digestLen
* 해쉬 결과의 길이를 저장할 변수의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_DIGEST^ISC_F_FINAL_DIGEST^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_DIGEST^ISC_F_FINAL_DIGEST^ISC_ERR_FINAL_DIGEST_FAIL : 알고리즘 인터페이스 FINAL DIGEST 실패
*/
ISC_API ISC_STATUS ISC_Final_DIGEST(ISC_DIGEST_UNIT *unit, uint8 *digest, int *digestLen);

/*!
* \brief
* ISC_Init_DIGEST(), ISC_Update_DIGEST(), ISC_Final_DIGEST()를 한 번에 하는 함수
* \param alg_id
* 해쉬 알고리즘 ID
* \param message
* 해쉬 할 메시지의 포인터
* \param messageLen
* 해쉬 할 메시지의 길이
* \param digest
* 해쉬 결과를 저장할 버퍼의 포인터
* \param digestLen
* 해쉬 결과의 길이를 저장할 변수의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_DIGEST^ISC_F_DIGEST^ISC_ERR_NULL_INPUT : NULL 입력값 입력
* -# ISC_L_DIGEST^ISC_F_DIGEST^ISC_ERR_MALLOC : 동적 메모리 할당 실패
* -# ISC_L_DIGEST^ISC_F_DIGEST^ISC_ERR_INIT_DIGEST_FAIL : ISC_Init_DIGEST() 함수 실패
* -# ISC_L_DIGEST^ISC_F_DIGEST^ISC_ERR_UPDATE_DIGEST_FAIL : ISC_Update_DIGEST() 함수 실패
* -# ISC_L_DIGEST^ISC_F_DIGEST^ISC_ERR_FINAL_DIGEST_FAIL : ISC_Final_DIGEST() 함수 실패
*/
ISC_API ISC_STATUS ISC_DIGEST(int alg_id, uint8 *message, int messageLen, uint8 *digest, int *digestLen);

/*!
* \brief
* 해쉬 알고리즘의 ID를 리턴하는 함수
* \param unit
* ISC_DIGEST_UNIT의 포인터
* \returns
* -# 해쉬 알고리즘의 ID : Success
* -# 0 : 해시 알고리즘 ID 가져오기 실패
*/
ISC_API int ISC_Get_DIGEST_Alg_ID(ISC_DIGEST_UNIT *unit);

/*!
* \brief
* 해쉬 알고리즘의 이름을 리턴하는 함수
* \param algorithm_id
* 해쉬 알고리즘 ID
* \returns
* -# 해쉬 알고리즘의 이름 : Success
* -# ISC_NULL_STRING : 해시 알고리즘 가져오기 실패
*/
ISC_API char *ISC_Get_DIGEST_Alg_Name(int algorithm_id);

/*!
* \brief
* 해쉬 알고리즘의 아이디를 리턴하는 함수
* \param algorithm_name
* 해쉬 알고리즘 이름
* \returns
* -# 해쉬 알고리즘의 아이디 : Success
* -# TEST_FAIL : 자가 시험에 실패
* -# 0 : 해시 알고리즘 ID 가져오기 실패
*/
ISC_API int ISC_Get_DIGEST_Alg_ID_By_Name(const char *algorithm_name);

/*!
* \brief
* 해쉬 알고리즘 결과의 길이를 리턴하는 함수
* \param algorithm_id
* 해쉬 알고리즘 ID
* \returns
* -# 해쉬 알고리즘 결과의 길이 : Success
* -# ISC_INVALID_SIZE : 해시 결과값 길이 가져오기 실패
*/
ISC_API int ISC_Get_DIGEST_Length(int algorithm_id);

/*!
* \brief
* 해쉬 알고리즘 초기화 함수
* \param unit
* ISC_DIGEST_UNIT의 포인터
* \param hash_id
* 해쉬 알고리즘 ID
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()함수 에러코드
* -# ISC_L_DIGEST^ISC_F_INIT_DIGEST_ALG^ISC_ERR_NOT_PROVEN_ALGORITHM : 검증모드에서 비검증 알고리즘 사용
* -# ISC_L_DIGEST^ISC_F_INIT_DIGEST_ALG^ISC_ERR_INVALID_ALGORITHM_ID : 잘못된 알고리즘 ID 입력
*/
ISC_INTERNAL ISC_STATUS isc_Init_DIGEST_Alg(ISC_DIGEST_UNIT *unit, int hash_id);

/*!
* \brief
* ISC_DIGEST_UNIT 생성 함수
* \param isproven 암호화 검증 모듈 제한 여부
* \returns
* 생성된 ISC_DIGEST_UNIT의 포인터
*/
ISC_INTERNAL ISC_DIGEST_UNIT *isc_New_DIGEST_Unit_Ex(uint8 isproven);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_DIGEST_UNIT*, ISC_New_DIGEST_Unit, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_DIGEST_Unit, (ISC_DIGEST_UNIT *unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_DIGEST_Unit, (ISC_DIGEST_UNIT *unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_DIGEST, (ISC_DIGEST_UNIT *unit, int alg_id), (unit, alg_id), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Update_DIGEST, (ISC_DIGEST_UNIT *unit, const uint8 *message, int messageLen), (unit, message, messageLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Final_DIGEST, (ISC_DIGEST_UNIT *unit, uint8 *digest, int *digestLen), (unit, digest, digestLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_DIGEST, (int alg_id, uint8 *message, int messageLen, uint8 *digest, int *digestLen), (alg_id, message, messageLen, digest, digestLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, isc_Init_DIGEST_Alg, (ISC_DIGEST_UNIT *unit, int hash_id), (unit, hash_id), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(int, ISC_Get_DIGEST_Alg_ID, (ISC_DIGEST_UNIT *unit), (unit), 0 );
ISC_RET_LOADLIB_CRYPTO(char*, ISC_Get_DIGEST_Alg_Name, (int algorithm_id), (algorithm_id), NULL );
ISC_RET_LOADLIB_CRYPTO(int, ISC_Get_DIGEST_Alg_ID_By_Name, (const char *algorithm_name), (algorithm_name), 0 );
ISC_RET_LOADLIB_CRYPTO(int, ISC_Get_DIGEST_Length, (int algorithm_id), (algorithm_id), 0 );

#endif

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_DIGEST_H */

