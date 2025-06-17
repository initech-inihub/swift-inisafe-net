/*!
* \file base64.h
* \brief base64 ���ڵ� / ���ڵ�
* \remarks
* \author sungwook.jang@initech.com
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_BASE64_H
#define HEADER_BASE64_H

#include <inicrypto/foundation.h>
#include <inicrypto/mem.h>

#define SINGLE_LINE_MODE		0x00	/*!< New Line�� ���� Single Line Mode*/
#define MULTI_LINE_MODE			0x01	/*!< New Line�� �ִ� Multi Line Mode*/

#define MAX_BYTES_OF_LINE		64		/*!< �� �ٴ� �ִ� ����Ʈ ��*/

#ifdef  __cplusplus
extern "C" {
#endif


#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* Base64�������� ���ڵ��ϴ� �Լ�
* \param data
* ���ڵ��� ���̳ʸ� �������� ������
* \param dataLen
* ���̳ʸ� �������� ����
* \param base64
* ���ڵ� ����� ������ ������ ���� ������
* \param mode
* ���ڵ��� ��� Ex)SINGLE_LINE_MODE
* \returns
* Base64�� ���ڵ��� ���̳ʸ��� ����(Byte)
*/
ISC_API int encode_Base64(const uint8 *data, int dataLen, uint8 **base64, int mode);

/*!
* \brief
* Base64�������� ���ڵ��ϴ� �Լ�
* \param data
* ���ڵ��� ���̳ʸ� �������� ������
* \param dataLen
* ���̳ʸ� �������� ����
* \param base64
* ���ڵ� ����� ������ ������ ���� ������
* \param byteOfLine
* ���ٴ� ����Ʈ ������
* \returns
* Base64�� ���ڵ��� ���̳ʸ��� ����(Byte)
*/
ISC_API int encode_Base64_Line(const uint8 *data, int dataLen, uint8 **base64, int byteOfLine);

/*!
* \brief
* Base64�������� ���ڵ� �� �����͸� ���ڵ��ϴ� �Լ�
* \param base64
* Base64�� ���ڵ��� ���̳ʸ� �������� ������
* \param base64Len
* Base64�� ���ڵ��� ���̳ʸ��� ����
* \param output
* ���ڵ� ����� ������ ������ ���� ������
* \returns
* ���ڵ��� ���̳ʸ��� ����(Byte)
*/
ISC_API int decode_Base64(const uint8 *base64, int base64Len, uint8 **output);

#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(int, encode_Base64, (const uint8 *data, int dataLen, uint8 **base64, int mode), (data,dataLen,base64,mode), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, encode_Base64_Line, (const uint8 *data, int dataLen, uint8 **base64, int byteOfLine), (data,dataLen,base64,byteOfLine), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, decode_Base64, (const uint8 *base64, int base64Len, uint8 **output), (base64,base64Len,output), ISC_FAIL);

#endif

#ifdef  __cplusplus
}
#endif
#endif /* HEADER_BASE64_H */
