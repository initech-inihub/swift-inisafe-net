/*!
* \file pem.h
* \brief pem ���ڵ� / ���ڵ�
* \remarks
* \author sungwook.jang@initech.com
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_PEM_H
#define HEADER_PEM_H

#include <inicrypto/foundation.h>
#include <inicrypto/mem.h>

/* -----BEGIN (PEM_STRING)-----\n */
#define PEM_HEADER_LENGTH			17		/*!< PEM Header�� ����(���๮�� ����)*/
/* \n-----END (PEM_STRING)----- */
#define PEM_FOOTER_LENGTH			15		/*!< PEM Footer�� ����*/

/* ���ڵ� �� �� ���̴� PEM STRING */
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
* PEM�������� ���ڵ��ϴ� �Լ�
* \param data
* ���ڵ��� ���̳ʸ� �������� ������
* \param dataLen
* ���̳ʸ� �������� ����
* \param pemString
* PEM String Ex)"X509 CERTIFICATE"
* \param pemStringLen
* PEM String�� ����
* \param pem
* ���ڵ� ����� ������ ������ ���� ������
* \param mode
* ���ڵ��� ��� Ex)SINGLE_LINE_MODE
* \returns
* PEM���� ���ڵ��� ���̳ʸ��� ����(Byte)
*/
ISC_API int encode_PEM(const uint8 *data, int dataLen, const char *pemString, int pemStringLen, uint8 **pem, int mode);

/*!
* \brief
* Base64�� ���ڵ� �� �����͸� PEM�������� ���ڵ��ϴ� �Լ�
* \param base64
* Base64�� ���ڵ� �� �������� ������
* \param base64Len
* Base64�� ���ڵ� �� �������� ����
* \param pemString
* PEM String Ex)"X509 CERTIFICATE"
* \param pemStringLen
* PEM String�� ����
* \param pem
* ���ڵ� ����� ������ ������ ���� ������
* \returns
* PEM���� ���ڵ��� ���̳ʸ��� ����(Byte)
*/
ISC_API int base64ToPEM(const uint8 *base64, int base64Len, const char *pemString, int pemStringLen, uint8 **pem);

/*!
* \brief
* PEM�������� ���ڵ� �� �����͸� ���ڵ��ϴ� �Լ�
* \param pem
* PEM���� ���ڵ��� ���̳ʸ� �������� ������
* \param pemLen
* PEM���� ���ڵ��� ���̳ʸ��� ����
* \param output
* ���ڵ� ����� ������ ������ ���� ������
* \returns
* ���ڵ��� ���̳ʸ��� ����(Byte)
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
