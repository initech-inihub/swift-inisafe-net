/*!
* \file base64.h
* \brief base64 인코딩 / 디코딩
* \remarks
* \author sungwook.jang@initech.com
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_BASE64_H
#define HEADER_BASE64_H

#include <inicrypto/foundation.h>
#include <inicrypto/mem.h>

#define SINGLE_LINE_MODE		0x00	/*!< New Line이 없는 Single Line Mode*/
#define MULTI_LINE_MODE			0x01	/*!< New Line이 있는 Multi Line Mode*/

#define MAX_BYTES_OF_LINE		64		/*!< 한 줄당 최대 바이트 수*/

#ifdef  __cplusplus
extern "C" {
#endif


#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* Base64형식으로 인코딩하는 함수
* \param data
* 인코딩할 바이너리 데이터의 포인터
* \param dataLen
* 바이너리 데이터의 길이
* \param base64
* 인코딩 결과를 저장할 버퍼의 이중 포인터
* \param mode
* 인코딩할 모드 Ex)SINGLE_LINE_MODE
* \returns
* Base64로 인코딩된 바이너리의 길이(Byte)
*/
ISC_API int encode_Base64(const uint8 *data, int dataLen, uint8 **base64, int mode);

/*!
* \brief
* Base64형식으로 인코딩하는 함수
* \param data
* 인코딩할 바이너리 데이터의 포인터
* \param dataLen
* 바이너리 데이터의 길이
* \param base64
* 인코딩 결과를 저장할 버퍼의 이중 포인터
* \param byteOfLine
* 한줄당 바이트 사이즈
* \returns
* Base64로 인코딩된 바이너리의 길이(Byte)
*/
ISC_API int encode_Base64_Line(const uint8 *data, int dataLen, uint8 **base64, int byteOfLine);

/*!
* \brief
* Base64형식으로 인코딩 된 데이터를 디코딩하는 함수
* \param base64
* Base64로 인코딩된 바이너리 데이터의 포인터
* \param base64Len
* Base64로 인코딩된 바이너리의 길이
* \param output
* 디코딩 결과를 저장할 버퍼의 이중 포인터
* \returns
* 디코딩된 바이너리의 길이(Byte)
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
