/*!
* \file ctl.h
* \brief CTL
* Certificate Trust List
* \remarks
* \author
* Copyright (c) 2008 by \<INITECH\>
*/
#ifndef __CTL_H__
#define __CTL_H__

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include "asn1_objects.h"
#include "x509.h"
#include "x509v3.h"
#include "x509_crl.h"
#include "error.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define new_TRUSTED_CERTIFICATE_STK() new_STK(TRUSTED_CERTIFICATE)
#define free_TRUSTED_CERTIFICATE_STK(st) free_STK(TRUSTED_CERTIFICATE, (st))
#define get_TRUSTED_CERTIFICATE_STK_count(st) get_STK_count(TRUSTED_CERTIFICATE, (st))
#define get_TRUSTED_CERTIFICATE_STK_value(st, i) get_STK_value(TRUSTED_CERTIFICATE, (st), (i))
#define push_TRUSTED_CERTIFICATE_STK(st, val) push_STK_value(TRUSTED_CERTIFICATE, (st), (val))
#define find_TRUSTED_CERTIFICATE_STK(st, val) find_STK_value(TRUSTED_CERTIFICATE, (st), (val))
#define remove_TRUSTED_CERTIFICATE_STK(st, i) remove_STK_value(TRUSTED_CERTIFICATE, (st), (i))
#define insert_TRUSTED_CERTIFICATE_STK(st, val, i) insert_STK_value(TRUSTED_CERTIFICATE, (st), (val), (i))
#define dup_TRUSTED_CERTIFICATE_STK(st) dup_STK(TRUSTED_CERTIFICATE, st)
#define free_TRUSTED_CERTIFICATE_STK_values(st, free_func) free_STK_values(TRUSTED_CERTIFICATE, (st), (free_func))
#define pop_TRUSTED_CERTIFICATE_STK(st) pop_STK_value(TRUSTED_CERTIFICATE, (st))
#define sort_TRUSTED_CERTIFICATE_STK(st) sort_STK(TRUSTED_CERTIFICATE, (st))
#define is_TRUSTED_CERTIFICATE_STK_sorted(st) is_STK_sorted(TRUSTED_CERTIFICATE, (st))

/*!
* \brief
* OBJECT_IDENTIFIER의 스택 구조체
*/
typedef STK(OBJECT_IDENTIFIER) OBJECT_IDENTIFIERS;

/*!
* \brief
* trusted Subjects
* TrustedSubjects ::= SEQUENCE OF TrustedCertificate
* TrustedCertificate ::= SEQUENCE {
*				trustedCertificateHash HashValue,
*				trustedCertificateAttributes TrustedCertificateAttributes OPTIONAL }
*
* HashValue ::= OCTET STRING
* TrustedCertificateAttributes ::= SEQUENCE OF AttributeTypeAndValue
*/
typedef struct TRUSTED_CERTIFICATE_st {
	OCTET_STRING			*trustedCertificateHash;					/*!< */
	X509_ATTRIBUTES			*trustedCertificateAttributes;				/*!< */
} TRUSTED_CERTIFICATE;

typedef STK(TRUSTED_CERTIFICATE) TRUSTED_SUBJECTS;

/*!
* \brief
* certificate trust list
* CertificateTrustList ::= SEQUENCE {
*				version Version DEFAULT v1,
*				subjectUsage SubjectUsage,
*				listIdentifier ListIdentifier OPTIONAL,
*				sequenceNumber INTEGER,
*				thisUpdate Time,
*				nextUpdate Time,
*				subjectAlgorithm AlgorithmIdentifier,
*				trustedSubjects TrustedSubjects,
*				extensions Extensions OPTIONAL }
*/
typedef struct CERT_TRUST_LIST_st {
	INTEGER					*version;									/*!< 버젼 정보 */
	OBJECT_IDENTIFIERS		*subjectUsage;								/*!< 주체사용 */
	OCTET_STRING	 		*listIdentifier;							/*!< 식별자 나열 */
	INTEGER					*sequenceNumber;							/*!< 일련번호 */
	X509_TIME 				*thisUpdate;								/*!< 발급일자 */
	X509_TIME 				*nextUpdate;								/*!< 다음 발그일자 */
	X509_ALGO_IDENTIFIER 	*subjectAlgorithm;							/*!< 주체 알고리즘 */
	TRUSTED_SUBJECTS		*trustedSubjects;							/*!< 신뢰 주체들 */
	X509_EXTENSIONS			*extensions;								/*!< 인증서 신뢰목록 확장필드 */
} CERT_TRUST_LIST;

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* OBJECT_IDENTIFIERS 구조체의 초기화 함수
* \returns
* OBJECT_IDENTIFIERS 구조체 포인터
*/
ISC_API OBJECT_IDENTIFIERS *new_OBJECT_IDENTIFIERS(void);

/*!
* \brief
* OBJECT_IDENTIFIERS 구조체를 메모리 할당 해제하는 함수
* \param oids
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_OBJECT_IDENTIFIERS(OBJECT_IDENTIFIERS *oids);

/*!
* \brief
* OBJECT_IDENTIFIERS 스택에 OBJECT_IDENTIFIER를 추가
* \param oids
* OBJECT_IDENTIFIERS 스택 포인터
* \param oid
* 추가될 OBJECT_IDENTIFIER 구조체 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_OBJECT_IDENTIFIERS(OBJECT_IDENTIFIERS *oids, OBJECT_IDENTIFIER *oid);

/*!
* \brief
* OBJECT_IDENTIFIERS 스택에서 OBJECT_IDENTIFIER와 일치하는 인덱스를 검색
* \param oids
* OBJECT_IDENTIFIERS 스택 포인터
* \param oid
* OBJECT_IDENTIFIER 구조체 포인터
* \return
* -# oid와 일치하는 인덱스
* -# oid와 일치하는 인덱스가 없을경우 -1
*/
ISC_API int get_OBJECT_IDENTIFIERS_index_by_OBJECT_IDENTIFIER(OBJECT_IDENTIFIERS *oids, OBJECT_IDENTIFIER *oid);

/*!
* \brief
* TRUSTED_CERTIFICATE 구조체의 초기화 함수
* \returns
* TRUSTED_CERTIFICATE 구조체 포인터
*/
ISC_API TRUSTED_CERTIFICATE *new_TRUSTED_CERTIFICATE(void);

/*!
* \brief
* TRUSTED_CERTIFICATE 구조체를 메모리 할당 해제
* \param TRUSTED_CERTIFICATE
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_TRUSTED_CERTIFICATE(TRUSTED_CERTIFICATE *unit);

/*!
* \brief
* TRUSTED_CERTIFICATE 구조체를 Sequence로 Encode 함수
* \param tc
* TRUSTED_CERTIFICATE 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_TRUSTED_CERTIFICATE_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_TRUSTED_CERTIFICATE_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# TRUSTED_CERTIFICATE_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS TRUSTED_CERTIFICATE_to_Seq (TRUSTED_CERTIFICATE *tc, SEQUENCE **seq);

/*!
* \brief
* Sequence를 TRUSTED_CERTIFICATE 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param tc
* TRUSTED_CERTIFICATE 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_TRUSTED_CERTIFICATE^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_SEQ_TO_TRUSTED_CERTIFICATE^ERR_ASN1_ENCODING : ASN1 Err
* -# Seq_to_TRUSTED_CERTIFICATE()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_TRUSTED_CERTIFICATE (SEQUENCE *seq, TRUSTED_CERTIFICATE** tc);


/*!
* \brief
* TRUSTED_SUBJECTS 구조체의 초기화 함수
* \returns
* TRUSTED_SUBJECTS 구조체 포인터
*/
ISC_API TRUSTED_SUBJECTS *new_TRUSTED_SUBJECTS(void);

/*!
* \brief
* TRUSTED_SUBJECTS 구조체를 메모리 할당 해제
* \param TRUSTED_SUBJECTS
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_TRUSTED_SUBJECTS(TRUSTED_SUBJECTS *unit);

/*!
* \brief
* TRUSTED_SUBJECTS 구조체를 Sequence로 Encode 함수
* \param ts
* TRUSTED_SUBJECTS 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_TRUSTED_SUBJECTS_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_TRUSTED_SUBJECTS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# TRUSTED_SUBJECTS_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS TRUSTED_SUBJECTS_to_Seq (TRUSTED_SUBJECTS *ts, SEQUENCE **seq);

/*!
* \brief
* Sequence를 TRUSTED_SUBJECTS 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param ts
* TRUSTED_SUBJECTS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_TRUSTED_SUBJECTS^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_SEQ_TO_TRUSTED_SUBJECTS^ERR_ASN1_ENCODING : ASN1 Err
* -# Seq_to_TRUSTED_SUBJECTS()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_TRUSTED_SUBJECTS (SEQUENCE *seq, TRUSTED_SUBJECTS** ts);

/*!
* \brief
* CERT_TRUST_LIST 구조체의 초기화 함수
* \returns
* CERT_TRUST_LIST 구조체 포인터
*/
ISC_API CERT_TRUST_LIST *new_CERT_TRUST_LIST(void);

/*!
* \brief
* CERT_TRUST_LIST 구조체를 메모리 할당 해제
* \param CERT_TRUST_LIST
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_CERT_TRUST_LIST(CERT_TRUST_LIST *unit);

/*!
* \brief
* CERT_TRUST_LIST 구조체를 리셋
* \param unit
* 리셋할 구조체
*/
ISC_API void clean_CERT_TRUST_LIST(CERT_TRUST_LIST *unit);

/*!
* \brief
* CERT_TRUST_LIST 구조체를 Sequence로 Encode 함수
* \param ta
* CERT_TRUST_LIST 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_CERT_TRUST_LIST_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_CERT_TRUST_LIST_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# CERT_TRUST_LIST_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS CERT_TRUST_LIST_to_Seq (CERT_TRUST_LIST *ta, SEQUENCE **seq);

/*!
* \brief
* Sequence를 CERT_TRUST_LIST 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param ctl
* CERT_TRUST_LIST 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_CERT_TRUST_LIST^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_SEQ_TO_CERT_TRUST_LIST^ERR_ASN1_ENCODING : ASN1 Err
* -# Seq_to_CERT_TRUST_LIST()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_CERT_TRUST_LIST (SEQUENCE *seq, CERT_TRUST_LIST** ctl);

/*!
* \brief
* Sequence를 CERT_TRUST_LIST 의 유효기간을 체크하는 함수
* \param ctl
* CERT_TRUST_LIST 구조체 
* \param x509time
* 기준시간
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS verify_CTL_validity(CERT_TRUST_LIST *ctl, X509_TIME *time);

#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(OBJECT_IDENTIFIERS*, new_OBJECT_IDENTIFIERS, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_OBJECT_IDENTIFIERS, (OBJECT_IDENTIFIERS *oids), (oids) );
INI_RET_LOADLIB_PKI(ISC_STATUS, add_OBJECT_IDENTIFIERS, (OBJECT_IDENTIFIERS *oids, OBJECT_IDENTIFIER *oid), (oids,oid), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_OBJECT_IDENTIFIERS_index_by_OBJECT_IDENTIFIER, (OBJECT_IDENTIFIERS *oids, OBJECT_IDENTIFIER *oid), (oids,oid), ISC_FAIL);
INI_RET_LOADLIB_PKI(TRUSTED_CERTIFICATE*, new_TRUSTED_CERTIFICATE, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_TRUSTED_CERTIFICATE, (TRUSTED_CERTIFICATE *unit), (unit) );
INI_RET_LOADLIB_PKI(ISC_STATUS, TRUSTED_CERTIFICATE_to_Seq, (TRUSTED_CERTIFICATE *tc, SEQUENCE **seq), (tc,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_TRUSTED_CERTIFICATE, (SEQUENCE *seq, TRUSTED_CERTIFICATE** tc), (seq,tc), ISC_FAIL);
INI_RET_LOADLIB_PKI(TRUSTED_SUBJECTS*, new_TRUSTED_SUBJECTS, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_TRUSTED_SUBJECTS, (TRUSTED_SUBJECTS *unit), (unit) );
INI_RET_LOADLIB_PKI(ISC_STATUS, TRUSTED_SUBJECTS_to_Seq, (TRUSTED_SUBJECTS *ts, SEQUENCE **seq), (ts,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_TRUSTED_SUBJECTS, (SEQUENCE *seq, TRUSTED_SUBJECTS** ts), (seq,ts), ISC_FAIL);
INI_RET_LOADLIB_PKI(CERT_TRUST_LIST*, new_CERT_TRUST_LIST, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_CERT_TRUST_LIST, (CERT_TRUST_LIST *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_CERT_TRUST_LIST, (CERT_TRUST_LIST *unit), (unit) );
INI_RET_LOADLIB_PKI(ISC_STATUS, CERT_TRUST_LIST_to_Seq, (CERT_TRUST_LIST *ta, SEQUENCE **seq), (ta,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_CERT_TRUST_LIST, (SEQUENCE *seq, CERT_TRUST_LIST** ctl), (seq,ctl), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, verify_CTL_validity, (CERT_TRUST_LIST *ctl, X509_TIME *time),(ctl, time), ISC_FAIL);


#endif

#define add_USER_POLICIES	add_OBJECT_IDENTIFIERS
#define new_USER_POLICIES	new_OBJECT_IDENTIFIERS

#ifdef  __cplusplus
}
#endif
#endif /* __CTL_H__ */

