/*!
* \file rc4.h
* \brief ISC_RC4 �˰���
* \remarks
* ISC_RC4 �� ��Ʈ�� ��ȣ�μ� ������ �� ���̰� ���� (draft-kaukonen-cipher-arcfour-03.txt ����)
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

#define ISC_RC4_ENCRYPT	1			/*!< ISC_RC4�� ��ȣȭ*/
#define ISC_RC4_DECRYPT	0			/*!< ISC_RC4�� ��ȣȭ*/

/*---------------------------------------------------------------------------------*/
/*ISC_RC4 Alias				0x07000000 ------------------------------------------------*/
#define ISC_RC4				0x07000100					/*!< ISC_RC4 �˰��� ID*/
#define ISC_RC4_NAME		"ISC_RC4"
/*---------------------------------------------------------------------------------*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
 * \brief
 * ISC_RC4�� Ű�� ���̴� ������ �ٷ� ����ü 
 */
typedef struct isc_rc4_key_st
{
	uint32 x,y;
	uint32 state[256];
}ISC_RC4_UNIT;

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_RC4_UNIT ����ü�� �ʱ�ȭ �Լ�
* \returns
* ������ ISC_RC4_UNIT ����ü
*/
ISC_API ISC_RC4_UNIT* ISC_New_RC4_Unit();


/*!
* \brief
* ISC_RC4_UNIT ����ü�� ���� (����ȭ)
* \param rc4
* ������ ISC_RC4_UNIT ����ü
*/
ISC_API void ISC_Clean_RC4_Unit(ISC_RC4_UNIT* rc4);

/*!
* \brief
* ISC_RC4_UNIT ����ü�� �޸� �Ҵ� ����
* \param rc4
* ������ ����ü
* \remarks
* ����ü�� ����(free)
*/
ISC_API void ISC_Free_RC4_Unit(ISC_RC4_UNIT* rc4);


/*!
* \brief
* ISC_RC4���� ���̴� Ű�� ����� �Լ�
* \param key
* Ű�� ������ ��� �ִ� ����ü ����
* \param raw_key
* �ʱ� Raw Key
* \param length
* �Էµ� Ű�� ����
* \brief
* ISC_RC4�� ������ Ű�� ���̰� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_RC4_INTERFACE^ISC_ERR_INVALID_INPUT : �߸��� �Է°� �Է�
*/
ISC_API ISC_STATUS ISC_Init_RC4(ISC_RC4_UNIT *key, const uint8 *raw_key, int length);

/*!
* \brief
* ISC_RC4 Encryption / Decryption �Լ�
* \param rc4
* ISC_RC4 Unit ����ü
* \param in
* �Է��� ������
* \param inLen
* �Էµ� ���� ����
* \param out
* ��� ������
* \brief
* out�� inLen�� ũ�� ��ŭ �޸𸮰� �Ҵ� �Ǿ� �־�� ��
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_RC4_INTERFACE^ISC_ERR_INVALID_INPUT : �߸��� �Է°� �Է�
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

