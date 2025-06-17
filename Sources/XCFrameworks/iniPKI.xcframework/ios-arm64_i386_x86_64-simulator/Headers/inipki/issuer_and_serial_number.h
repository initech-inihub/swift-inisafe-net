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
* ISSUER AND SERIAL NUMBER의 정보를 저장하는 구조체
*/
typedef struct ISSUER_AND_SERIAL_NUMBER_st {
	X509_NAME	*issuer;		/*!< 발급자 정보*/
	INTEGER		*serialNumber;	/*!< 시리얼 넘버*/
} ISSUER_AND_SERIAL_NUMBER;


/*------------------------- 함수 시작 -------------------------------------------*/

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* ISSUER_AND_SERIAL_NUMBER 구조체의 초기화 함수
* \returns
* ISSUER_AND_SERIAL_NUMBER 구조체 포인터
*/
ISC_API ISSUER_AND_SERIAL_NUMBER *new_ISSUER_AND_SERIAL_NUMBER(void);

/*!
* \brief
* ISSUER_AND_SERIAL_NUMBER 구조체를 메모리 할당 해제
* \param ias
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_ISSUER_AND_SERIAL_NUMBER(ISSUER_AND_SERIAL_NUMBER *ias);


/*!
* \brief
* 인증서와 ISSUER_AND_SERIAL_NUMBER을 비교
* \param x509
* 인증서
* \param ias
* ISSUER_AND_SERIAL_NUMBER 구조체 포인터
* \return
* -# 0 : 같음
* -# ISC_FAIL : 실패
* -# -1 : 다름
*/
ISC_API int cmp_ISSUER_AND_SERIAL_NUMBER(X509_CERT *x509, ISSUER_AND_SERIAL_NUMBER *ias);


/*!
* \brief
* 인증서중에서 ISSUER_AND_SERIAL_NUMBER인 인증서 찾기
* \param certs
* X509 인증서들
* \param ias
* ISSUER_AND_SERIAL_NUMBER 구조체 포인터
* \return
* -# 0 : 같음
* -# ISC_FAIL : 실패
* -# -1 : 다름
*/
ISC_API X509_CERT *find_X509_CERT_by_IssuerAndSerialNumber(X509_CERTS *certs, ISSUER_AND_SERIAL_NUMBER *ias);

/*!
* \brief
* ISSUER_AND_SERIAL_NUMBER 구조체를 Sequence로 Encode 함수
* \param ias
* ISSUER_AND_SERIAL_NUMBER 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_IS_AND_SN_TO_SEQ^ISC_ERR_NULL_INPUT : 입력 파라미터가 NULL임
* -# LOCATION^F_IS_AND_SN_TO_SEQ^ERR_ASN1_ENCODING : ASN1 에러
* -# X509_NAME_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS ISSUER_AND_SERIAL_NUMBER_to_Seq(ISSUER_AND_SERIAL_NUMBER *ias, SEQUENCE **seq);

/*!
* \brief
* Sequence를 ISSUER_AND_SERIAL_NUMBER 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param ias
* ISSUER_AND_SERIAL_NUMBER 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_IS_AND_SN^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_IS_AND_SN^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_IS_AND_SN^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_NAME()의 에러 코드\n
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
