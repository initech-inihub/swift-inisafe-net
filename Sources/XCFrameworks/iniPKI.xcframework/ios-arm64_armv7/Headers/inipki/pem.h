/*!
* \file pem.h
* \brief pem 인코딩 / 디코딩
* \remarks
* \author sungwook.jang@initech.com
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_PEM_H
#define HEADER_PEM_H

#include <inicrypto/foundation.h>
#include <inicrypto/mem.h>

/* -----BEGIN (PEM_STRING)-----\n */
#define PEM_HEADER_LENGTH			17		/*!< PEM Header의 길이(개행문자 포함)*/
/* \n-----END (PEM_STRING)----- */
#define PEM_FOOTER_LENGTH			15		/*!< PEM Footer의 길이*/

/* 인코딩 될 때 쓰이는 PEM STRING */
#define PEM_STRING					"PRIVACY-ENHANCED MESSAGE" /*!< */
#define X509_OLD_PEM_STRING			"X509 CERTIFICATE" /*!< */
#define X509_PEM_STRING				"CERTIFICATE" /*!< */
#define X509_PAIR_PEM_STRING		"CERTIFICATE PAIR" /*!< */
#define X509_TRUSTED_PEM_STRING		"TRUSTED CERTIFICATE" /*!< */
#define X509_REQ_OLD_PEM_STRING		"NEW CERTIFICATE REQUEST" /*!< */
#define X509_REQ_PEM_STRING			"CERTIFICATE REQUEST" /*!< */
#define X509_CRL_PEM_STRING			"X509 CRL" /*!< */
#define PUBLIC_PEM_STRING			"PUBLIC KEY" /*!< */
#define RSA_PEM_STRING				"RSA PRIVATE KEY" /*!< */
#define RSA_PUBLIC_PEM_STRING		"RSA PUBLIC KEY" /*!< */
#define PKCS7_PEM_STRING			"PKCS7" /*!< */
#define PKCS8_PEM_STRING			"ENCRYPTED PRIVATE KEY" /*!< */
#define PKCS8INF_PEM_STRING			"PRIVATE KEY" /*!< */
#define KCDSA_PEM_STRING			"KCDSA PRIVATE KEY" /*!< */
#define KCDSAPARAMS_PEM_STRING		"KCDSA PARAMETERS" /*!< */
#define EC_PEM_STRING               "EC PRIVATE KEY" /*!< */
#define EC_PARAMS_PEM_STRING        "EC PARAMETERS" /*!< */

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* PEM형식으로 인코딩하는 함수
* \param data
* 인코딩할 바이너리 데이터의 포인터
* \param dataLen
* 바이너리 데이터의 길이
* \param pemString
* PEM String Ex)"X509 CERTIFICATE"
* \param pemStringLen
* PEM String의 길이
* \param pem
* 인코딩 결과를 저장할 버퍼의 이중 포인터
* \param mode
* 인코딩할 모드 Ex)SINGLE_LINE_MODE
* \returns
* PEM으로 인코딩된 바이너리의 길이(Byte)
*/
ISC_API int encode_PEM(const uint8 *data, int dataLen, const char *pemString, int pemStringLen, uint8 **pem, int mode);

/*!
* \brief
* Base64로 인코딩 된 데이터를 PEM형식으로 인코딩하는 함수
* \param base64
* Base64로 인코딩 된 데이터의 포인터
* \param base64Len
* Base64로 인코딩 된 데이터의 길이
* \param pemString
* PEM String Ex)"X509 CERTIFICATE"
* \param pemStringLen
* PEM String의 길이
* \param pem
* 인코딩 결과를 저장할 버퍼의 이중 포인터
* \returns
* PEM으로 인코딩된 바이너리의 길이(Byte)
*/
ISC_API int base64ToPEM(const uint8 *base64, int base64Len, const char *pemString, int pemStringLen, uint8 **pem);

/*!
* \brief
* PEM형식으로 인코딩 된 데이터를 디코딩하는 함수
* \param pem
* PEM으로 인코딩된 바이너리 데이터의 포인터
* \param pemLen
* PEM으로 인코딩된 바이너리의 길이
* \param output
* 디코딩 결과를 저장할 버퍼의 이중 포인터
* \returns
* 디코딩된 바이너리의 길이(Byte)
*/
ISC_API int decode_PEM(const uint8 *pem, int pemLen, uint8 **output);

#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(int, encode_PEM, (const uint8 *data, int dataLen, const char *pemString, int pemStringLen, uint8 **pem, int mode), (data,dataLen,pemString,pemStringLen,pem,mode), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, base64ToPEM, (const uint8 *base64, int base64Len, const char *pemString, int pemStringLen, uint8 **pem), (base64,base64Len,pemString,pemStringLen,pem), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, decode_PEM, (const uint8 *pem, int pemLen, uint8 **output), (pem,pemLen,output), ISC_FAIL);

#endif

#ifdef  __cplusplus
}
#endif
#endif /* HEADER_PEM_H */
