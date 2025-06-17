/*!
* \file generalized_time.h
* \brief ISSUER_AND_SERIAL_NUMBER
* \remarks
* RFC2630, Network Working Group
* \author
* Copyright (c) 2008 by \<INITECH\> / Developed by Seon Jong. Kim.
*/

#ifndef __GENERALIZED_TIME_H__
#define __GENERALIZED_TIME_H__

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/foundation.h>

#include "asn1_objects.h"
#include "x509.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* ISSUER AND SERIAL NUMBER�� ������ �����ϴ� ����ü
*/
typedef struct ISSUER_AND_SERIAL_NUMBER_st {
	X509_NAME	*issuer;		/*!< �߱��� ����*/
	INTEGER		*serialNumber;	/*!< �ø��� �ѹ�*/
} ISSUER_AND_SERIAL_NUMBER;


/*------------------------- �Լ� ���� -------------------------------------------*/

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* ISSUER_AND_SERIAL_NUMBER ����ü�� �ʱ�ȭ �Լ�
* \returns
* ISSUER_AND_SERIAL_NUMBER ����ü ������
*/
ISC_API ISSUER_AND_SERIAL_NUMBER *new_ISSUER_AND_SERIAL_NUMBER(void);

/*!
* \brief
* ISSUER_AND_SERIAL_NUMBER ����ü�� �޸� �Ҵ� ����
* \param ias
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_ISSUER_AND_SERIAL_NUMBER(ISSUER_AND_SERIAL_NUMBER *ias);


/*!
* \brief
* �������� ISSUER_AND_SERIAL_NUMBER�� ��
* \param x509
* ������
* \param ias
* ISSUER_AND_SERIAL_NUMBER ����ü ������
* \return
* -# 0 : ����
* -# ISC_FAIL : ����
* -# -1 : �ٸ�
*/
ISC_API int cmp_ISSUER_AND_SERIAL_NUMBER(X509_CERT *x509, ISSUER_AND_SERIAL_NUMBER *ias);


/*!
* \brief
* �������߿��� ISSUER_AND_SERIAL_NUMBER�� ������ ã��
* \param certs
* X509 ��������
* \param ias
* ISSUER_AND_SERIAL_NUMBER ����ü ������
* \return
* -# 0 : ����
* -# ISC_FAIL : ����
* -# -1 : �ٸ�
*/
ISC_API X509_CERT *find_X509_CERT_by_IssuerAndSerialNumber(X509_CERTS *certs, ISSUER_AND_SERIAL_NUMBER *ias);

/*!
* \brief
* ISSUER_AND_SERIAL_NUMBER ����ü�� Sequence�� Encode �Լ�
* \param ias
* ISSUER_AND_SERIAL_NUMBER ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_IS_AND_SN_TO_SEQ^ISC_ERR_NULL_INPUT : �Է� �Ķ���Ͱ� NULL��
* -# LOCATION^F_IS_AND_SN_TO_SEQ^ERR_ASN1_ENCODING : ASN1 ����
* -# X509_NAME_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS ISSUER_AND_SERIAL_NUMBER_to_Seq(ISSUER_AND_SERIAL_NUMBER *ias, SEQUENCE **seq);

/*!
* \brief
* Sequence�� ISSUER_AND_SERIAL_NUMBER ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param ias
* ISSUER_AND_SERIAL_NUMBER ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_IS_AND_SN^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_IS_AND_SN^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_IS_AND_SN^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_NAME()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_ISSUER_AND_SERIAL_NUMBER(SEQUENCE *seq, ISSUER_AND_SERIAL_NUMBER **ias);

#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(ISSUER_AND_SERIAL_NUMBER*, new_ISSUER_AND_SERIAL_NUMBER, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_ISSUER_AND_SERIAL_NUMBER, (ISSUER_AND_SERIAL_NUMBER *ias), (ias) );
INI_RET_LOADLIB_PKI(int, cmp_ISSUER_AND_SERIAL_NUMBER, (X509_CERT *x509, ISSUER_AND_SERIAL_NUMBER *ias), (x509,ias), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_CERT*, find_X509_CERT_by_IssuerAndSerialNumber, (X509_CERTS *certs, ISSUER_AND_SERIAL_NUMBER *ias), (certs,ias), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, ISSUER_AND_SERIAL_NUMBER_to_Seq, (ISSUER_AND_SERIAL_NUMBER *ias, SEQUENCE **seq), (ias,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_ISSUER_AND_SERIAL_NUMBER, (SEQUENCE *seq, ISSUER_AND_SERIAL_NUMBER **ias), (seq,ias), ISC_FAIL);

#endif

#ifdef  __cplusplus
}
#endif 

#endif /* __GENERALIZED_TIME_H__ */
