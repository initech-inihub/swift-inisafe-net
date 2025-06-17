/*!
* \file rc4.h
* \brief ISC_RC4 알고리즘
* \remarks
* ISC_RC4 는 스트림 암호로서 정해진 블럭 길이가 없음 (draft-kaukonen-cipher-arcfour-03.txt 기준)
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_RC4_H
#define HEADER_RC4_H

#include "foundation.h"
#include "mem.h"

#ifdef NO_RC4
#error ISC_RC4 is disabled.
#endif

#define ISC_RC4_ENCRYPT	1			/*!< ISC_RC4의 암호화*/
#define ISC_RC4_DECRYPT	0			/*!< ISC_RC4의 복호화*/

/*---------------------------------------------------------------------------------*/
/*ISC_RC4 Alias				0x07000000 ------------------------------------------------*/
#define ISC_RC4				0x07000100					/*!< ISC_RC4 알고리즘 ID*/
#define ISC_RC4_NAME		"ISC_RC4"
/*---------------------------------------------------------------------------------*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
 * \brief
 * ISC_RC4의 키에 쓰이는 정보를 다룰 구조체 
 */
typedef struct isc_rc4_key_st
{
	uint32 x,y;
	uint32 state[256];
}ISC_RC4_UNIT;

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_RC4_UNIT 구조체의 초기화 함수
* \returns
* 생성된 ISC_RC4_UNIT 구조체
*/
ISC_API ISC_RC4_UNIT* ISC_New_RC4_Unit();


/*!
* \brief
* ISC_RC4_UNIT 구조체를 리셋 (제로화)
* \param rc4
* 리셋할 ISC_RC4_UNIT 구조체
*/
ISC_API void ISC_Clean_RC4_Unit(ISC_RC4_UNIT* rc4);

/*!
* \brief
* ISC_RC4_UNIT 구조체를 메모리 할당 해제
* \param rc4
* 제거할 구조체
* \remarks
* 구조체를 제거(free)
*/
ISC_API void ISC_Free_RC4_Unit(ISC_RC4_UNIT* rc4);


/*!
* \brief
* ISC_RC4에서 쓰이는 키를 만드는 함수
* \param key
* 키의 정보를 담고 있는 구조체 변수
* \param raw_key
* 초기 Raw Key
* \param length
* 입력된 키의 길이
* \brief
* ISC_RC4는 고정된 키의 길이가 없음
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_RC4_INTERFACE^ISC_ERR_INVALID_INPUT : 잘못된 입력값 입력
*/
ISC_API ISC_STATUS ISC_Init_RC4(ISC_RC4_UNIT *key, const uint8 *raw_key, int length);

/*!
* \brief
* ISC_RC4 Encryption / Decryption 함수
* \param rc4
* ISC_RC4 Unit 구조체
* \param in
* 입력의 포인터
* \param inLen
* 입력된 값의 길이
* \param out
* 출력 포인터
* \brief
* out은 inLen의 크기 만큼 메모리가 할당 되어 있어야 함
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_RC4_INTERFACE^ISC_ERR_INVALID_INPUT : 잘못된 입력값 입력
*/
ISC_API ISC_STATUS ISC_Do_RC4(ISC_RC4_UNIT *rc4, const uint8 *in, uint32 inLen,  uint8 *out);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_RC4_UNIT*, ISC_New_RC4_Unit, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_RC4_Unit, (ISC_RC4_UNIT* rc4), (rc4) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_RC4_Unit, (ISC_RC4_UNIT* rc4), (rc4) );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_RC4, (ISC_RC4_UNIT *key, const uint8 *raw_key, int length), (key, raw_key, length), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Do_RC4, (ISC_RC4_UNIT *rc4, const uint8 *in, uint32 inLen,  uint8 *out), (rc4, in, inLen, out), ISC_ERR_GET_ADRESS_LOADLIBRARY );

#endif

#ifdef  __cplusplus
}
#endif
#endif /* HEADER_RC4_H */

