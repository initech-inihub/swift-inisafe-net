/*!
* \file x509v3.h
* \brief X509_V3 Extension
* \remarks
* X509의 확장필드의 구조체 및 관련 함수/매크로 헤더
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_X509v3_H
#define HEADER_X509v3_H

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/foundation.h>

#include "asn1.h"
#include "x509.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* GENERAL NAME OPTION */
#define G_N_OTHERNAME	0		/*!< */
#define G_N_EMAIL		1		/*!< */
#define G_N_DNS			2		/*!< */
#define G_N_X400		3		/*!< */
#define G_N_DIRNAME		4		/*!< */
#define G_N_EDIPARTY	5		/*!< */
#define G_N_URI			6		/*!< */
#define G_N_IPADD		7		/*!< */
#define G_N_RID			8		/*!< */

#define K_USAGE_DIGITAL_SIGNATURE	0x0080	/*!< */
#define K_USAGE_NON_REPUDIATION		0x0040	/*!< */
#define K_USAGE_KEY_ENCIPHERMENT	0x0020	/*!< */
#define K_USAGE_DATA_ENCIPHERMENT	0x0010	/*!< */
#define K_USAGE_KEY_AGREEMENT		0x0008	/*!< */
#define K_USAGE_KEY_CERT_SIGN		0x0004	/*!< */
#define K_USAGE_CRL_SIGN			0x0002	/*!< */
#define K_USAGE_ENCIPHER_ONLY		0x0001	/*!< */
#define K_USAGE_DECIPHER_ONLY		0x8000	/*!< */

#define unused					0	/*!< */
#define keyCompromise           1	/*!< */
#define cACompromise            2	/*!< */
#define affiliationChanged      3	/*!< */
#define superseded              4	/*!< */
#define cessationOfOperation    5	/*!< */
#define certificateHold         6	/*!< */
#define privilegeWithdrawn      7	/*!< */  /*removeFromCRL*/
#define aACompromise            8	/*!< */

/*!
* \brief
* X509 기본 제한 확장필드 구조체
*/
typedef struct BASIC_CONSTRAINTS_st {
	int ca;					/*!< */
	INTEGER *pathlen;		/*!< */
} BASIC_CONSTRAINTS;


/*!
* \brief
* X509 키 사용기간 확장필드 구조체
*/
typedef struct PKEY_USAGE_PERIOD_st {
	UTC_TIME *notBefore; /*!< */
	UTC_TIME *notAfter; /*!< */
} PKEY_USAGE_PERIOD;

/*!
* \brief
* X509 General Name 확장필드의 OTHERNAME 구조체
*/
typedef struct otherName_st {
	OBJECT_IDENTIFIER *type_id; /*!< */
	ASN1_STRING *value; /*!< */
} OTHERNAME;

/*!
* \brief
* X509 General Name 확장필드의 EDIPARTYNAME 구조체
*/
typedef struct EDIPartyName_st {
	ASN1_STRING *nameAssigner; /*!< */
	ASN1_STRING *partyName; /*!< */
} EDIPARTYNAME;

/*!
* \brief
* X509 General Name 확장필드 구조체
*/
typedef struct GENERAL_NAME_st {
	int type; /*!< */
	union {
		char *ptr; /*!< */
		OTHERNAME *otherName; /*!< */
		IA5_STRING *rfc822Name; /*!< */
		IA5_STRING *dNSName; /*!< */
		ASN1_STRING *x400Address; /*!< */
		X509_NAME *directoryName; /*!< */
		EDIPARTYNAME *ediPartyName; /*!< */
		IA5_STRING *uniformResourceIdentifier; /*!< */
		OCTET_STRING *iPAddress; /*!< */
		OBJECT_IDENTIFIER *registeredID; /*!< */
	} d; /*!< */
} GENERAL_NAME;

/*!
* \brief
* X509 General Name 확장필드의 스택 구조체
*/
typedef STK(GENERAL_NAME) GENERAL_NAMES; 

/*!
* \brief
* X509 Access_Description 확장필드의 구조체
*/
typedef struct ACCESS_DESCRIPTION_st {
	OBJECT_IDENTIFIER *method; /*!< */
	GENERAL_NAME *location; /*!< */
} ACCESS_DESCRIPTION;

/*!
* \brief
* X509 Access_Description 확장필드의 스택 구조체
*/
typedef STK(ACCESS_DESCRIPTION) AUTHORITY_INFO_ACCESS;

/*!
* \brief
* X509 Access_Description 확장필드의 스택 구조체
*/
typedef STK(ACCESS_DESCRIPTION) SUBJECT_INFO_ACCESS;

/*!
* \brief
* X509 OBJECT_IDENTIFIER의 스택 구조체
*/
typedef STK(OBJECT_IDENTIFIER) EXTENDED_KEY_USAGE;

/*!
* \brief
* X509 DIST_POINT 확장필드의 DIST_POINT_NAME 구조체
*/
typedef struct DIST_POINT_NAME_st {
	int type;
	union {
		GENERAL_NAMES *fullname; /*!< */
		X509_NAME *relativename; /*!< */
	} name;
} DIST_POINT_NAME;

/*!
* \brief
* X509 DIST_POINT 확장필드의 구조체
*/
typedef struct DIST_POINT_st {
	DIST_POINT_NAME	*distpoint; /*!< */
	BIT_STRING *reasons; /*!< */
	GENERAL_NAMES *CRLissuer; /*!< */
} DIST_POINT;

/*!
* \brief
* X509 DIST_POINT 확장필드의 스택 구조체
*/
typedef STK(DIST_POINT) CRL_DIST_POINTS;

/*!
* \brief
* X509 AUTHORITY_KEYID 확장필드의 구조체
*/
typedef struct AUTHORITY_KEYID_st {
	OCTET_STRING *keyid;   /*!< */ /*cs0*/
	GENERAL_NAMES *issuer; /*!< */ /*cs1*/
	INTEGER *serial;	   /*!< */ /*cs2*/
} AUTHORITY_KEYID;

/*!
* \brief
* X509 INTEGER형의 스택 구조체
*/
typedef STK(INTEGER) NOTICE_NUMBERS;

/*!
* \brief
* X509 POLICY_INFO 확장필드의 NOTICE_REFERENCE 구조체
*/
typedef struct NOTICEREF_st {
	ASN1_STRING *organization; /*!< */
	NOTICE_NUMBERS *noticeNumbers; /*!< */
} NOTICE_REFERENCE;
/*!
* \brief
* X509 POLICY_INFO 확장필드의 USER_NOTICE 구조체
*/
typedef struct USERNOTICE_st {
	NOTICE_REFERENCE *noticeref; /*!< */
	ASN1_STRING *exptext; /*!< */
} USER_NOTICE;
/*!
* \brief
* X509 POLICY_INFO 확장필드의 POLICY_QUALIFIER_INFO 구조체
*/
typedef struct POLICYQUALINFO_st {
	OBJECT_IDENTIFIER *pqualid; /*!< */
	union {
		IA5_STRING *cpsuri; /*!< */
		USER_NOTICE *usernotice; /*!< */
	} d; /*!< */
} POLICY_QUALIFIER_INFO;

/*!
* \brief
* X509 POLICY_QUALIFIER_INFO의 스택 구조체
*/
typedef STK(POLICY_QUALIFIER_INFO) POLICY_QUALIFIERS;

/*!
* \brief
* X509 POLICY_INFO 확장필드의 구조체
*/
typedef struct POLICYINFO_st {
	OBJECT_IDENTIFIER *policyid; /*!< */
	POLICY_QUALIFIERS *qualifiers; /*!< */
} POLICY_INFO;
/*!
* \brief
* X509 POLICY_INFO의 스택 구조체
*/
typedef STK(POLICY_INFO) CERTIFICATE_POLICIES;

/*!
* \brief
* X509 POLICY_MAPPING 확장필드의 구조체
*/
typedef struct POLICY_MAPPING_st {
	OBJECT_IDENTIFIER *issuerDomainPolicy; /*!< */
	OBJECT_IDENTIFIER *subjectDomainPolicy; /*!< */
} POLICY_MAPPING;
/*!
* \brief
* X509 POLICY_MAPPING의 스택 구조체
*/
typedef STK(POLICY_MAPPING) POLICY_MAPPINGS;

/*!
* \brief
* X509 GENERAL_SUBTREE 확장필드의 구조체
*/
typedef struct GENERAL_SUBTREE_st {
	GENERAL_NAME *base; /*!< */
	INTEGER *minimum; /*!< */
	INTEGER *maximum; /*!< */
} GENERAL_SUBTREE;
/*!
* \brief
* X509 GENERAL_SUBTREE 확장필드의 스택 구조체
*/
typedef STK(GENERAL_SUBTREE) GENERAL_SUBTREES;

/*!
* \brief
* X509 NAME_CONSTRAINTS 확장필드의 구조체
*/
typedef struct NAME_CONSTRAINTS_st {
	GENERAL_SUBTREES *permittedSubtrees; /*!< */
	GENERAL_SUBTREES *excludedSubtrees; /*!< */
} NAME_CONSTRAINTS;

/*!
* \brief
* X509 POLICY_CONSTRAINTS 확장필드의 구조체
*/
typedef struct POLICY_CONSTRAINTS_st {
	INTEGER *requireExplicitPolicy; /*!< */
	INTEGER *inhibitPolicyMapping; /*!< */
} POLICY_CONSTRAINTS;

/*!
* \brief
* X509 Subject/Issuer Altname 확장필드의 구조체
*/
typedef struct ALT_NAME_st {
	GENERAL_NAMES *names;
} ALT_NAME;

/*!
* \brief
* X509 VID 확장필드의 구조체
*/
typedef struct VID_st {
	OBJECT_IDENTIFIER * hashAlgo; /*!< */
	OCTET_STRING * vid; /*!< */
}VID;

/*!
* \brief
* X509 KISA_IDENTIFY_DATA 확장필드의 구조체
*/
typedef struct KISA_ID_DATA_st
{
	UTF8_STRING *realName; /*!< */
	OBJECT_IDENTIFIER * userInfo; /*!< */
	VID* vid; /*!< */
}KISA_IDENTIFY_DATA;

/*!
* \brief
* X509 ISSUING_DIST_POINT 확장필드의 구조체
*/
typedef struct issuingDIST_POINT_st {
	DIST_POINT_NAME* distpoint; /*!< */
	BOOLEAN* onlyContainUserCerts; /*!< */
	BOOLEAN* onlyContainCACerts; /*!< */
	BIT_STRING *reasons; /*!< */
	BOOLEAN* indirectCRL; /*!< */
} ISSUING_DIST_POINT;
/*!
* \brief
* X509 ISSUING_DIST_POINT 확장필드의 스택 구조체
*/
typedef STK(ISSUING_DIST_POINT) ISSUING_DIST_POINTS;

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* VID 구조체의 초기화 함수
* \returns
* VID 구조체 포인터
*/
ISC_API VID* new_VID();

/*!
* \brief
* GENERAL_NAME 구조체의 초기화 함수
* \returns
* GENERAL_NAME 구조체 포인터
*/
ISC_API GENERAL_NAME* new_GENERAL_NAME();
/*!
* \brief
* GENERAL_NAME 구조체를 메모리 할당 해제
* \param gn
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_GENERAL_NAME(GENERAL_NAME* gn);
/*!
* \brief
* GENERAL_NAME 구조체를 복사하는 함수
* \param src
* 복사 원본의 GENERAL_NAME 구조체
* \returns
* 복사된 GENERAL_NAME 구조체
*/
ISC_API GENERAL_NAME* dup_GENERAL_NAME(GENERAL_NAME* src);

/*!
* \brief
* GENERAL_NAME 구조체 값을 세팅하는 함수
* \param dst 
* 값을 설정할 GENERAL_NAME 구조체
* \param type 
* 설정할 GENERAL_NAME type
* \param name 
* 설정할 GENERAL_NAME 값
* \returns
* 복사된 GENERAL_NAME 구조체
*/
ISC_API ISC_STATUS set_GENERAL_NAME(GENERAL_NAME* dst, int type, void *name, int namelen);


/*!
* \brief
* GENERAL_NAMES 구조체의 초기화 함수
* \returns
* GENERAL_NAMES 구조체 포인터
*/
ISC_API GENERAL_NAMES* new_GENERAL_NAMES();

/*!
* \brief
* GENERAL_NAMES 구조체를 메모리 할당 해제
* \param gns
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_GENERAL_NAMES(GENERAL_NAMES* gns);

/*!
* \brief
* GENERAL_NAMES 구조체를 복사하는 함수
* \param gns
* 복사 원본의 GENERAL_NAMES 구조체
* \returns
* 복사된 GENERAL_NAMES 구조체
*/
ISC_API GENERAL_NAMES* dup_GENERAL_NAMES(GENERAL_NAMES* gns);

/*!
* \brief
* ALT_NAME 구조체의 초기화 함수
* \returns
* ALT_NAME 구조체 포인터
*/
ISC_API ALT_NAME* new_ALT_NAME();

/*!
* \brief
* ALT_NAME 구조체를 메모리 할당 해제
* \param alt_name 
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_ALT_NAME(ALT_NAME* alt_name);

/*!
* \brief
* Sequence를 ALT_NAME 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param an 
*  ALT_NAME 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_GENERAL_NAME^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_GENERAL_NAME^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_NAME()의 에러 코드\n
* -# Seq_to_EDIPARTYNAME()의 에러 코드\n
* -# 현재 기준 ALT_NAME은 GENERAL_NAME 만으로 구성되어있으므로 오류코드는 GENERAL_NAME과 동일\n
*/
ISC_API ISC_STATUS Seq_to_ALT_NAME(SEQUENCE *seq, ALT_NAME **an);

/*!
* \brief
* ALT_NAME 구조체를 Sequence로 Encode 함수
* \param an 
* ALT_NAME 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_GENERAL_NAME_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_GENERAL_NAME_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# OTHERNAME_to_Seq()의 에러 코드\n
* -# EDIPARTYNAME_to_Seq()의 에러 코드\n
* -# X509_NAME_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS ALT_NAME_to_Seq(ALT_NAME *an, SEQUENCE **seq);

/*!
* \brief
* BASIC_CONSTRAINTS 구조체의 초기화 함수
* \returns
* BASIC_CONSTRAINTS 구조체 포인터
*/
ISC_API BASIC_CONSTRAINTS* new_BASIC_CONSTRAINTS();
/*!
* \brief
* BASIC_CONSTRAINTS 구조체를 메모리 할당 해제
* \param bs
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS* bs);
/*!
* \brief
* BASIC_CONSTRAINTS 구조체를 복사하는 함수
* \param src
* 복사 원본의 BASIC_CONSTRAINTS 구조체
* \returns
* 복사된 BASIC_CONSTRAINTS 구조체
*/
ISC_API BASIC_CONSTRAINTS *dup_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS* src);

/*!
* \brief
* OTHERNAME 구조체의 초기화 함수
* \returns
* OTHERNAME 구조체 포인터
*/
ISC_API OTHERNAME* new_OTHERNAME();
/*!
* \brief
* OTHERNAME 구조체를 메모리 할당 해제
* \param on
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_OTHERNAME(OTHERNAME* on);
/*!
* \brief
* OTHERNAME 구조체를 복사하는 함수
* \param src
* 복사 원본의 OTHERNAME 구조체
* \returns
* 복사된 OTHERNAME 구조체
*/
ISC_API OTHERNAME *dup_OTHERNAME(OTHERNAME* src);

/*!
* \brief
* EDIPARTYNAME 구조체의 초기화 함수
* \returns
* EDIPARTYNAME 구조체 포인터
*/
ISC_API EDIPARTYNAME* new_EDIPARTYNAME();
/*!
* \brief
* EDIPARTYNAME 구조체를 메모리 할당 해제
* \param e
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_EDIPARTYNAME(EDIPARTYNAME* e);
/*!
* \brief
* EDIPARTYNAME 구조체를 복사하는 함수
* \param src
* 복사 원본의 EDIPARTYNAME 구조체
* \returns
* 복사된 EDIPARTYNAME 구조체
*/
ISC_API EDIPARTYNAME *dup_EDIPARTYNAME(EDIPARTYNAME* src);

/*!
* \brief
* POLICY_CONSTRAINTS 구조체의 초기화 함수
* \returns
* POLICY_CONSTRAINTS 구조체 포인터
*/
ISC_API POLICY_CONSTRAINTS* new_POLICY_CONSTRAINTS();
/*!
* \brief
* POLICY_CONSTRAINTS 구조체를 메모리 할당 해제
* \param e
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_POLICY_CONSTRAINTS(POLICY_CONSTRAINTS* pc);
/*!
* \brief
* POLICY_CONSTRAINTS 구조체를 복사하는 함수
* \param src
* 복사 원본의 POLICY_CONSTRAINTS 구조체
* \returns
* 복사된 POLICY_CONSTRAINTS 구조체
*/
ISC_API POLICY_CONSTRAINTS *dup_POLICY_CONSTRAINTS(POLICY_CONSTRAINTS* src);

/*!
* \brief
* NOTICE_REFERENCE 구조체의 초기화 함수
* \returns
* NOTICE_REFERENCE 구조체 포인터
*/
ISC_API NOTICE_REFERENCE* new_NOTICE_REFERENCE();
/*!
* \brief
* NOTICE_REFERENCE 구조체를 메모리 할당 해제
* \param n
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_NOTICE_REFERENCE(NOTICE_REFERENCE* n);
/*!
* \brief
* NOTICE_REFERENCE 구조체를 복사하는 함수
* \param src
* 복사 원본의 NOTICE_REFERENCE 구조체
* \returns
* 복사된 NOTICE_REFERENCE 구조체
*/
ISC_API NOTICE_REFERENCE* dup_NOTICE_REFERENCE(NOTICE_REFERENCE* src);

/*!
* \brief
* USER_NOTICE 구조체의 초기화 함수
* \returns
* USER_NOTICE 구조체 포인터
*/
ISC_API USER_NOTICE* new_USER_NOTICE();
/*!
* \brief
* USER_NOTICE 구조체를 메모리 할당 해제
* \param n
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_USER_NOTICE(USER_NOTICE* n);
/*!
* \brief
* USER_NOTICE 구조체를 복사하는 함수
* \param src
* 복사 원본의 USER_NOTICE 구조체
* \returns
* 복사된 USER_NOTICE 구조체
*/
ISC_API USER_NOTICE* dup_USER_NOTICE(USER_NOTICE* src);

/*!
* \brief
* POLICY_QUALIFIER_INFO 구조체의 초기화 함수
* \returns
* POLICY_QUALIFIER_INFO 구조체 포인터
*/
ISC_API POLICY_QUALIFIER_INFO* new_POLICY_QUALIFIER_INFO();
/*!
* \brief
* POLICY_QUALIFIER_INFO 구조체를 메모리 할당 해제
* \param i
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_POLICY_QUALIFIER_INFO(POLICY_QUALIFIER_INFO *i);
/*!
* \brief
* POLICY_QUALIFIER_INFO 구조체를 복사하는 함수
* \param src
* 복사 원본의 POLICY_QUALIFIER_INFO 구조체
* \returns
* 복사된 POLICY_QUALIFIER_INFO 구조체
*/
ISC_API POLICY_QUALIFIER_INFO* dup_POLICY_QUALIFIER_INFO(POLICY_QUALIFIER_INFO *src);

/*!
* \brief
* POLICY_INFO 구조체의 초기화 함수
* \returns
* POLICY_INFO 구조체 포인터
*/
ISC_API POLICY_INFO* new_POLICY_INFO();
/*!
* \brief
* POLICY_INFO 구조체를 메모리 할당 해제
* \param i
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_POLICY_INFO(POLICY_INFO* i);
/*!
* \brief
* POLICY_INFO 구조체를 복사하는 함수
* \param src
* 복사 원본의 POLICY_INFO 구조체
* \returns
* 복사된 POLICY_INFO 구조체
*/
ISC_API POLICY_INFO* dup_POLICY_INFO(POLICY_INFO* src);

/*!
* \brief
* CERTIFICATE_POLICIES 구조체의 초기화 함수
* \returns
* CERTIFICATE_POLICIES 구조체 포인터
*/
ISC_API CERTIFICATE_POLICIES* new_CERTIFICATE_POLICIES();
/*!
* \brief
* CERTIFICATE_POLICIES 구조체를 메모리 할당 해제
* \param c
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_CERTIFICATE_POLICIES(CERTIFICATE_POLICIES* c);
/*!
* \brief
* CERTIFICATE_POLICIES 구조체를 복사하는 함수
* \param src
* 복사 원본의 CERTIFICATE_POLICIES 구조체
* \returns
* 복사된 CERTIFICATE_POLICIES 구조체
*/
ISC_API CERTIFICATE_POLICIES *dup_CERTIFICATE_POLICIES(CERTIFICATE_POLICIES* src);

/*!
* \brief
* POLICY_QUALIFIERS 구조체의 초기화 함수
* \returns
* POLICY_QUALIFIERS 구조체 포인터
*/
ISC_API POLICY_QUALIFIERS *new_POLICY_QUALIFIERS();
/*!
* \brief
* POLICY_QUALIFIERS 구조체를 메모리 할당 해제
* \param pqs
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_POLICY_QUALIFIERS(POLICY_QUALIFIERS *pqs);
/*!
* \brief
* POLICY_QUALIFIERS 구조체를 복사하는 함수
* \param pqs
* 복사 원본의 POLICY_QUALIFIERS 구조체
* \returns
* 복사된 POLICY_QUALIFIERS 구조체
*/
ISC_API POLICY_QUALIFIERS *dup_POLICY_QUALIFIERS(POLICY_QUALIFIERS *pqs);

/*!
* \brief
* POLICY_MAPPING 구조체의 초기화 함수
* \returns
* POLICY_MAPPING 구조체 포인터
*/
ISC_API POLICY_MAPPING* new_POLICY_MAPPING();
/*!
* \brief
* POLICY_MAPPING 구조체를 메모리 할당 해제
* \param pm
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_POLICY_MAPPING(POLICY_MAPPING* pm);
/*!
* \brief
* POLICY_MAPPING 구조체를 복사하는 함수
* \param src
* 복사 원본의 POLICY_MAPPING 구조체
* \returns
* 복사된 POLICY_MAPPING 구조체
*/
ISC_API POLICY_MAPPING* dup_POLICY_MAPPING(POLICY_MAPPING* src);

/*!
* \brief
* POLICY_MAPPINGS 구조체의 초기화 함수
* \returns
* POLICY_MAPPINGS 구조체 포인터
*/
ISC_API POLICY_MAPPINGS* new_POLICY_MAPPINGS();
/*!
* \brief
* POLICY_MAPPINGS 구조체를 메모리 할당 해제
* \param c
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_POLICY_MAPPINGS(POLICY_MAPPINGS* c);
/*!
* \brief
* POLICY_MAPPINGS 구조체를 복사하는 함수
* \param src
* 복사 원본의 POLICY_MAPPINGS 구조체
* \returns
* 복사된 POLICY_MAPPINGS 구조체
*/
ISC_API POLICY_MAPPINGS *dup_POLICY_MAPPINGS(POLICY_MAPPINGS* src);

/*!
* \brief
* ACCESS_DESCRIPTION 구조체의 초기화 함수
* \returns
* ACCESS_DESCRIPTION 구조체 포인터
*/
ISC_API ACCESS_DESCRIPTION* new_ACCESS_DESCRIPTION();
/*!
* \brief
* ACCESS_DESCRIPTION 구조체를 메모리 할당 해제
* \param ad
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_ACCESS_DESCRIPTION(ACCESS_DESCRIPTION* ad);
/*!
* \brief
* ACCESS_DESCRIPTION 구조체를 복사하는 함수
* \param src
* 복사 원본의 ACCESS_DESCRIPTION 구조체
* \returns
* 복사된 ACCESS_DESCRIPTION 구조체
*/
ISC_API ACCESS_DESCRIPTION *dup_ACCESS_DESCRIPTION(ACCESS_DESCRIPTION* src);

/*!
* \brief
* AUTHORITY_INFO_ACCESS 구조체의 초기화 함수
* \returns
* AUTHORITY_INFO_ACCESS 구조체 포인터
*/
ISC_API AUTHORITY_INFO_ACCESS* new_AUTHORITY_INFO_ACCESS();
/*!
* \brief
* AUTHORITY_INFO_ACCESS 구조체를 메모리 할당 해제
* \param aia
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_AUTHORITY_INFO_ACCESS(AUTHORITY_INFO_ACCESS* aia);

/*!
* \brief
* SUBJECT_INFO_ACCESS 구조체의 초기화 함수
* \returns
* SUBJECT_INFO_ACCESS 구조체 포인터
*/
ISC_API SUBJECT_INFO_ACCESS* new_SUBJECT_INFO_ACCESS();
/*!
* \brief
* SUBJECT_INFO_ACCESS 구조체를 메모리 할당 해제
* \param aia
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_SUBJECT_INFO_ACCESS(SUBJECT_INFO_ACCESS* sia);

/*!
* \brief
* EXTENDED_KEY_USAGE 구조체의 초기화 함수
* \returns
* EXTENDED_KEY_USAGE 구조체 포인터
*/
ISC_API EXTENDED_KEY_USAGE* new_EXTENDED_KEY_USAGE();
/*!
* \brief
* EXTENDED_KEY_USAGE 구조체를 메모리 할당 해제
* \param eku
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_EXTENDED_KEY_USAGE(EXTENDED_KEY_USAGE* eku);


/*!
* \brief
* DIST_POINT_NAME 구조체의 초기화 함수
* \returns
* DIST_POINT_NAME 구조체 포인터
*/
ISC_API DIST_POINT_NAME* new_DIST_POINT_NAME();
/*!
* \brief
* DIST_POINT_NAME 구조체를 메모리 할당 해제
* \param dpn
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_DIST_POINT_NAME(DIST_POINT_NAME* dpn);
/*!
* \brief
* DIST_POINT_NAME 구조체를 복사하는 함수
* \param src
* 복사 원본의 DIST_POINT_NAME 구조체
* \returns
* 복사된 DIST_POINT_NAME 구조체
*/
ISC_API DIST_POINT_NAME* dup_DIST_POINT_NAME(DIST_POINT_NAME* src);


/*!
* \brief
* DIST_POINT 구조체의 초기화 함수
* \returns
* DIST_POINT 구조체 포인터
*/
ISC_API DIST_POINT* new_DIST_POINT();
/*!
* \brief
* DIST_POINT 구조체를 메모리 할당 해제
* \param dp
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_DIST_POINT(DIST_POINT* dp);
/*!
* \brief
* DIST_POINT 구조체를 복사하는 함수
* \param src
* 복사 원본의 DIST_POINT 구조체
* \returns
* 복사된 DIST_POINT 구조체
*/
ISC_API DIST_POINT *dup_DIST_POINT(DIST_POINT* src);

/*!
* \brief
* CRL_DIST_POINTS 구조체의 초기화 함수
* \returns
* CRL_DIST_POINTS 구조체 포인터
*/
ISC_API CRL_DIST_POINTS* new_CRL_DIST_POINTS();
/*!
* \brief
* CRL_DIST_POINTS 구조체를 메모리 할당 해제
* \param cdp
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_CRL_DIST_POINTS(CRL_DIST_POINTS* cdp);
/*!
* \brief
* CRL_DIST_POINTS 구조체를 복사하는 함수
* \param src
* 복사 원본의 CRL_DIST_POINTS 구조체
* \returns
* 복사된 CRL_DIST_POINTS 구조체
*/
ISC_API CRL_DIST_POINTS* dup_CRL_DIST_POINTS(CRL_DIST_POINTS* src);

/*!
* \brief
* AUTHORITY_KEYID 구조체의 초기화 함수
* \returns
* AUTHORITY_KEYID 구조체 포인터
*/
ISC_API AUTHORITY_KEYID* new_AUTHORITY_KEYID();
/*!
* \brief
* AUTHORITY_KEYID 구조체를 메모리 할당 해제
* \param ak
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_AUTHORITY_KEYID(AUTHORITY_KEYID* ak);
/*!
* \brief
* AUTHORITY_KEYID 구조체를 복사하는 함수
* \param src
* 복사 원본의 AUTHORITY_KEYID 구조체
* \returns
* 복사된 AUTHORITY_KEYID 구조체
*/
ISC_API AUTHORITY_KEYID *dup_AUTHORITY_KEYID(AUTHORITY_KEYID* src);

/*!
* \brief
* GENERAL_SUBTREE 구조체의 초기화 함수
* \returns
* GENERAL_SUBTREE 구조체 포인터
*/
ISC_API GENERAL_SUBTREE* new_GENERAL_SUBTREE();
/*!
* \brief
* GENERAL_SUBTREE 구조체를 메모리 할당 해제
* \param gs
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_GENERAL_SUBTREE(GENERAL_SUBTREE* gs);
/*!
* \brief
* GENERAL_SUBTREE 구조체를 복사하는 함수
* \param src
* 복사 원본의 GENERAL_SUBTREE 구조체
* \returns
* 복사된 GENERAL_SUBTREE 구조체
*/
ISC_API GENERAL_SUBTREE *dup_GENERAL_SUBTREE(GENERAL_SUBTREE* src);

/*!
* \brief
* GENERAL_SUBTREES 구조체의 초기화 함수
* \returns
* GENERAL_SUBTREES 구조체 포인터
*/
ISC_API GENERAL_SUBTREES* new_GENERAL_SUBTREES();
/*!
* \brief
* GENERAL_SUBTREES 구조체를 메모리 할당 해제
* \param gs
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_GENERAL_SUBTREES(GENERAL_SUBTREES* gs);
/*!
* \brief
* GENERAL_SUBTREES 구조체를 복사하는 함수
* \param gs
* 복사 원본의 GENERAL_SUBTREES 구조체
* \returns
* 복사된 GENERAL_SUBTREES 구조체
*/
ISC_API GENERAL_SUBTREES* dup_GENERAL_SUBTREES(GENERAL_SUBTREES* gs);

/*!
* \brief
* NAME_CONSTRAINTS 구조체의 초기화 함수
* \returns
* NAME_CONSTRAINTS 구조체 포인터
*/
ISC_API NAME_CONSTRAINTS* new_NAME_CONSTRAINTS();
/*!
* \brief
* NAME_CONSTRAINTS 구조체를 메모리 할당 해제
* \param nc
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_NAME_CONSTRAINTS(NAME_CONSTRAINTS* nc);
/*!
* \brief
* NAME_CONSTRAINTS 구조체를 복사하는 함수
* \param src
* 복사 원본의 NAME_CONSTRAINTS 구조체
* \returns
* 복사된 NAME_CONSTRAINTS 구조체
*/
ISC_API NAME_CONSTRAINTS *dup_NAME_CONSTRAINTS(NAME_CONSTRAINTS* src);

/*!
* \brief
* POLICY_CONSTRAINTS 구조체의 초기화 함수
* \returns
* POLICY_CONSTRAINTS 구조체 포인터
*/
ISC_API POLICY_CONSTRAINTS* new_POLICY_CONSTRAINTS();
/*!
* \brief
* POLICY_CONSTRAINTS 구조체를 메모리 할당 해제
* \param pc
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_POLICY_CONSTRAINTS(POLICY_CONSTRAINTS* pc);
/*!
* \brief
* POLICY_CONSTRAINTS 구조체를 복사하는 함수
* \param src
* 복사 원본의 POLICY_CONSTRAINTS 구조체
* \returns
* 복사된 POLICY_CONSTRAINTS 구조체
*/
ISC_API POLICY_CONSTRAINTS *dup_POLICY_CONSTRAINTS(POLICY_CONSTRAINTS* src);

/*!
* \brief
* Sequence를 GENERAL_NAME 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param gn
* GENERAL_NAME 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_GENERAL_NAME^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_GENERAL_NAME^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_NAME()의 에러 코드\n
* -# Seq_to_EDIPARTYNAME()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_GENERAL_NAME(SEQUENCE *seq, GENERAL_NAME **gn);
/*!
* \brief
* GENERAL_NAME 구조체를 Sequence로 Encode 함수
* \param gn
* GENERAL_NAME 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_GENERAL_NAME_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_GENERAL_NAME_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# OTHERNAME_to_Seq()의 에러 코드\n
* -# EDIPARTYNAME_to_Seq()의 에러 코드\n
* -# X509_NAME_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS GENERAL_NAME_to_Seq(GENERAL_NAME *gn, SEQUENCE **seq);

/*!
* \brief
* Sequence를 GENERAL_NAMES 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param gns
* GENERAL_NAMES 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_GENERAL_NAMES^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_GENERAL_NAMES^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_GENERAL_NAMES^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_GENERAL_NAME()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_GENERAL_NAMES(SEQUENCE *seq, GENERAL_NAMES **gns);
/*!
* \brief
* GENERAL_NAME 구조체를 Sequence로 Encode 함수
* \param gns
* GENERAL_NAME 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_GENERAL_NAMES_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_GENERAL_NAMES_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_GENERAL_NAMES_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# GENERAL_NAME_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS GENERAL_NAMES_to_Seq(GENERAL_NAMES *gns, SEQUENCE **seq);

/*!
* \brief
* AUTHORITY_KEYID 구조체를 Sequence로 Encode 함수
* \param id
* AUTHORITY_KEYID 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_AUTHORITY_KEYID_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_AUTHORITY_KEYID_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# GENERAL_NAMES_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS AUTHORITY_KEYID_to_Seq(AUTHORITY_KEYID* id, SEQUENCE **seq);
/*!
* \brief
* Sequence를 P8_PRIV_KEY_INFO 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param id
* P8_PRIV_KEY_INFO 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_AUTHORITY_KEYID^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_AUTHORITY_KEYID^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_AUTHORITY_KEYID^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_GENERAL_NAMES()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_AUTHORITY_KEYID(SEQUENCE *seq, AUTHORITY_KEYID **id);

/*!
* \brief
* Sequence를 OTHERNAME 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param oth
* OTHERNAME 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_OTHERNAME^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_OTHERNAME^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_OTHERNAME^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_OTHERNAME(SEQUENCE* seq, OTHERNAME **oth);
/*!
* \brief
* OTHERNAME 구조체를 Sequence로 Encode 함수
* \param oth
* OTHERNAME 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_OTHERNAME_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_OTHERNAME_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_OTHERNAME_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS OTHERNAME_to_Seq(OTHERNAME* oth, SEQUENCE **seq);

/*!
* \brief
* Sequence를 EDIPARTYNAME 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param e
* EDIPARTYNAME 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_EDIPARTYNAME^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_EDIPARTYNAME^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_EDIPARTYNAME^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_EDIPARTYNAME(SEQUENCE* seq, EDIPARTYNAME **e);
/*!
* \brief
* EDIPARTYNAME 구조체를 Sequence로 Encode 함수
* \param e
* EDIPARTYNAME 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_EDIPARTYNAME_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_EDIPARTYNAME_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_EDIPARTYNAME_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS EDIPARTYNAME_to_Seq(EDIPARTYNAME* e, SEQUENCE **seq);

/*!
* \brief
* Sequence를 POLICY_CONSTRAINTS 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param e
* POLICY_CONSTRAINTS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_POLICY_CONSTRAINTS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_POLICY_CONSTRAINTS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_POLICY_CONSTRAINTS^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_POLICY_CONSTRAINTS(SEQUENCE* seq, POLICY_CONSTRAINTS **pc);
/*!
* \brief
* POLICY_CONSTRAINTS 구조체를 Sequence로 Encode 함수
* \param e
* POLICY_CONSTRAINTS 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_POLICY_CONSTRAINTS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_POLICY_CONSTRAINTS_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_POLICY_CONSTRAINTS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS POLICY_CONSTRAINTS_to_Seq(POLICY_CONSTRAINTS* pc, SEQUENCE **seq);

/*!
* \brief
* VID 구조체를 Sequence로 Encode 함수
* \param vid
* VID 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_VID_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_VID_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS VID_to_Seq(VID *vid, SEQUENCE **seq);
/*!
* \brief
* Sequence를 VID 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param vid
* VID 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_VID^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_VID^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_CRL_INFO()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_VID(SEQUENCE *seq, VID **vid);


ISC_API KISA_IDENTIFY_DATA *new_KISA_IDENTIFY_DATA(void);

ISC_API void free_KISA_IDENTIFY_DATA(KISA_IDENTIFY_DATA *v);

/*!
* \brief
* Sequence를 KISA_IDENTIFY_DATA 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param id
* KISA_IDENTIFY_DATA 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_KISA_IDENTIFY_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_KISA_IDENTIFY_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_VID()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_KISA_IDENTIFY_DATA(SEQUENCE *seq, KISA_IDENTIFY_DATA **id);
/*!
* \brief
* KISA_IDENTIFY_DATA 구조체를 Sequence로 Encode 함수
* \param id
* KISA_IDENTIFY_DATA 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_KISA_IDENTIFY_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_VID_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# VID_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS KISA_IDENTIFY_DATA_to_Seq(KISA_IDENTIFY_DATA *id, SEQUENCE **seq);

/*!
* \brief
* ISSUING_DIST_POINT 구조체의 초기화 함수
* \returns
* ISSUING_DIST_POINT 구조체 포인터
*/
ISC_API ISSUING_DIST_POINT* new_ISSUING_DIST_POINT();
/*!
* \brief
* ISSUING_DIST_POINT 구조체를 메모리 할당 해제
* \param idp
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_ISSUING_DIST_POINT(ISSUING_DIST_POINT* idp);

/*!
* \brief
* ISSUING_DIST_POINTS 구조체의 초기화 함수
* \returns
* ISSUING_DIST_POINTS 구조체 포인터
*/
ISC_API ISSUING_DIST_POINTS* new_ISSUING_DIST_POINTS();
/*!
* \brief
* ISSUING_DIST_POINTS 구조체를 메모리 할당 해제
* \param cdp
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_ISSUING_DIST_POINTS(ISSUING_DIST_POINTS* cdp);
/*!
* \brief
* ISSUING_DIST_POINTS 구조체를 복사하는 함수
* \param src
* 복사 원본의 ISSUING_DIST_POINTS 구조체
* \returns
* 복사된 ISSUING_DIST_POINTS 구조체
*/
ISC_API ISSUING_DIST_POINTS* dup_ISSUING_DIST_POINTS(ISSUING_DIST_POINTS* src);

/*!
* \brief
* Sequence를 DIST_POINT 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param dp
* DIST_POINT 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_DIST_POINT^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_DIST_POINT^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_GENERAL_NAMES()의 에러 코드\n
* -# Seq_to_X509_NAME()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_DIST_POINT(SEQUENCE *seq, DIST_POINT **dp);
/*!
* \brief
* DIST_POINT 구조체를 Sequence로 Encode 함수
* \param dp
* DIST_POINT 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_DIST_POINT_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_DIST_POINT_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# GENERAL_NAMES_to_Seq()의 에러 코드\n
* -# X509_NAME_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS DIST_POINT_to_Seq(DIST_POINT *dp, SEQUENCE **seq);

/*!
* \brief
* Sequence를 CRL_DIST_POINTS 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param cdp
* CRL_DIST_POINTS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_CRL_DIST_POINTS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CRL_DIST_POINTS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CRL_DIST_POINTS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_DIST_POINT()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_CRL_DIST_POINTS(SEQUENCE *seq, CRL_DIST_POINTS **cdp);
/*!
* \brief
* CRL_DIST_POINTS 구조체를 Sequence로 Encode 함수
* \param cdp
* CRL_DIST_POINTS 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_CRL_DIST_POINTS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CRL_DIST_POINTS_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_CRL_DIST_POINTS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# DIST_POINT_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS CRL_DIST_POINTS_to_Seq(CRL_DIST_POINTS *cdp, SEQUENCE **seq);

/*!
* \brief
* ISSUING_DIST_POINT 구조체를 Sequence로 Encode 함수
* \param idp
* ISSUING_DIST_POINT 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ISSUING_DIST_POINT_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_ISSUING_DIST_POINT_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# GENERAL_NAMES_to_Seq()의 에러 코드\n
* -# X509_NAME_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS issuing_DIST_POINT_to_Seq(ISSUING_DIST_POINT *idp, SEQUENCE **seq);
/*!
* \brief
* Sequence를 ISSUING_DIST_POINT 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param idp
* ISSUING_DIST_POINT 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_ISSUING_DIST_POINT^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_ISSUING_DIST_POINT^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_GENERAL_NAMES()의 에러 코드\n
* -# Seq_to_X509_NAME()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_issuing_DIST_POINT(SEQUENCE *seq, ISSUING_DIST_POINT **idp);
/*!
* \brief
* ISSUING_DIST_POINTS 구조체를 Sequence로 Encode 함수
* \param cdp
* ISSUING_DIST_POINTS 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ISSUING_DIST_POINTS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_ISSUING_DIST_POINTS_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_ISSUING_DIST_POINTS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# issuing_DIST_POINT_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS issuing_DIST_POINTS_to_Seq(ISSUING_DIST_POINTS *cdp, SEQUENCE **seq);
/*!
* \brief
* Sequence를 ISSUING_DIST_POINTS 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param cdp
* ISSUING_DIST_POINTS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_ISSUING_DIST_POINTS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_ISSUING_DIST_POINTS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_ISSUING_DIST_POINTS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_issuing_DIST_POINT()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_issuing_DIST_POINTS(SEQUENCE *seq, ISSUING_DIST_POINTS **cdp);

/*!
* \brief
* POLICY_MAPPING 구조체를 Sequence로 Encode 함수
* \param pm
* POLICY_MAPPING 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_POLICY_MAPPING_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_POLICY_MAPPING_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS POLICY_MAPPING_to_Seq(POLICY_MAPPING *pm, SEQUENCE **seq);
/*!
* \brief
* Sequence를 POLICY_MAPPING 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param pm
* POLICY_MAPPING 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_POLICY_MAPPING^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_POLICY_MAPPING^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_POLICY_MAPPING(SEQUENCE *seq, POLICY_MAPPING **pm);

/*!
* \brief
* POLICY_MAPPINGS 구조체를 Sequence로 Encode 함수
* \param pms
* POLICY_MAPPINGS 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_POLICY_MAPPINGS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_POLICY_MAPPINGS_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_POLICY_MAPPINGS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# POLICY_MAPPING_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS POLICY_MAPPINGS_to_Seq(POLICY_MAPPINGS *pms, SEQUENCE **seq);
/*!
* \brief
* Sequence를 POLICY_MAPPINGS 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param pms
* POLICY_MAPPINGS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_POLICY_MAPPINGS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_POLICY_MAPPINGS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_POLICY_MAPPING()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_POLICY_MAPPINGS(SEQUENCE *seq, POLICY_MAPPINGS **pms);

/*!
* \brief
* BASIC_CONSTRAINTS 구조체를 Sequence로 Encode 함수
* \param bc
* BASIC_CONSTRAINTS 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_BASIC_CONSTRAINTS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_BASIC_CONSTRAINTS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS BASIC_CONSTRAINTS_to_Seq(BASIC_CONSTRAINTS *bc, SEQUENCE **seq);
/*!
* \brief
* Sequence를 BASIC_CONSTRAINTS 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param bc
* BASIC_CONSTRAINTS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_BASIC_CONSTRAINTS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_BASIC_CONSTRAINTS^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_BASIC_CONSTRAINTS(SEQUENCE *seq, BASIC_CONSTRAINTS **bc);

/*!
* \brief
* Sequence를 POLICY_CONSTRAINTS 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param pc
* POLICY_CONSTRAINTS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_POLICY_CONSTRAINTS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_POLICY_CONSTRAINTS^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_POLICY_CONSTRAINTS(SEQUENCE *seq, POLICY_CONSTRAINTS **pc);
/*!
* \brief
* POLICY_CONSTRAINTS 구조체를 Sequence로 Encode 함수
* \param pc
* POLICY_CONSTRAINTS 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_POLICY_CONSTRAINTS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_POLICY_CONSTRAINTS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS POLICY_CONSTRAINTS_to_Seq(POLICY_CONSTRAINTS *pc, SEQUENCE **seq);

/*!
* \brief
* Sequence를 ACCESS_DESCRIPTION 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param ad
* ACCESS_DESCRIPTION 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_ACCESS_DESCRIPTION^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_ACCESS_DESCRIPTION^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_GENERAL_NAME()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_ACCESS_DESCRIPTION(SEQUENCE *seq, ACCESS_DESCRIPTION **ad);
/*!
* \brief
* ACCESS_DESCRIPTION 구조체를 Sequence로 Encode 함수
* \param ad
* ACCESS_DESCRIPTION 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ACCESS_DESCRIPTION_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_ACCESS_DESCRIPTION_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# GENERAL_NAME_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS ACCESS_DESCRIPTION_to_Seq(ACCESS_DESCRIPTION *ad, SEQUENCE **seq);

/*!
* \brief
* Sequence를 AUTHORITY_INFO_ACCESS 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param aia
* AUTHORITY_INFO_ACCESS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_AUTHORITY_INFO_ACCESS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_AUTHORITY_INFO_ACCESS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_AUTHORITY_INFO_ACCESS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_ACCESS_DESCRIPTION()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_AUTHORITY_INFO_ACCESS(SEQUENCE *seq, AUTHORITY_INFO_ACCESS **aia);
/*!
* \brief
* AUTHORITY_INFO_ACCESS 구조체를 Sequence로 Encode 함수
* \param aia
* AUTHORITY_INFO_ACCESS 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_AUTHORITY_INFO_ACCESS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_AUTHORITY_INFO_ACCESS_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_AUTHORITY_INFO_ACCESS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# ACCESS_DESCRIPTION_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS AUTHORITY_INFO_ACCESS_to_Seq(AUTHORITY_INFO_ACCESS *aia, SEQUENCE **seq);

/*!
* \brief
* Sequence를 SUBJECT_INFO_ACCESS 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param aia
* SUBJECT_INFO_ACCESS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_SUBJECT_INFO_ACCESS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_SUBJECT_INFO_ACCESS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_SUBJECT_INFO_ACCESS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_ACCESS_DESCRIPTION()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_SUBJECT_INFO_ACCESS(SEQUENCE *seq, SUBJECT_INFO_ACCESS **aia);
/*!
* \brief
* SUBJECT_INFO_ACCESS 구조체를 Sequence로 Encode 함수
* \param aia
* SUBJECT_INFO_ACCESS 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SUBJECT_INFO_ACCESS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SUBJECT_INFO_ACCESS_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SUBJECT_INFO_ACCESS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# ACCESS_DESCRIPTION_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS SUBJECT_INFO_ACCESS_to_Seq(SUBJECT_INFO_ACCESS *aia, SEQUENCE **seq);

/*!
* \brief
* CERTIFICATE_POLICIES 구조체를 Sequence로 Encode 함수
* \param cps
* CERTIFICATE_POLICIES 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_CERTIFICATE_POLICIES_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CERTIFICATE_POLICIES_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_CERTIFICATE_POLICIES_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# POLICY_INFO_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS CERTIFICATE_POLICIES_to_Seq(CERTIFICATE_POLICIES *cps, SEQUENCE **seq);
/*!
* \brief
* Sequence를 CERTIFICATE_POLICIES 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param cps
* CERTIFICATE_POLICIES 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_CERTIFICATE_POLICIES^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CERTIFICATE_POLICIES^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CERTIFICATE_POLICIES^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_POLICY_INFO()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_CERTIFICATE_POLICIES(SEQUENCE *seq, CERTIFICATE_POLICIES **cps);

/*!
* \brief
* POLICY_INFO 구조체를 Sequence로 Encode 함수
* \param policyInfo
* POLICY_INFO 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_POLICY_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_POLICY_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# POLICY_QUALIFIERS_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS POLICY_INFO_to_Seq(POLICY_INFO *policyInfo, SEQUENCE **seq);
/*!
* \brief
* Sequence를 POLICY_INFO 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param policyInfo
* POLICY_INFO 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_POLICY_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_POLICY_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_POLICY_QUALIFIERS()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_POLICY_INFO(SEQUENCE *seq, POLICY_INFO **policyInfo);

/*!
* \brief
* POLICY_QUALIFIERS 구조체를 Sequence로 Encode 함수
* \param policyQualifiers
* POLICY_QUALIFIERS 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_POLICY_QUALIFIERS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_POLICY_QUALIFIERS_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_POLICY_QUALIFIERS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# POLICY_QUALIFIER_INFO_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS POLICY_QUALIFIERS_to_Seq(POLICY_QUALIFIERS *policyQualifiers, SEQUENCE **seq);
/*!
* \brief
* Sequence를 POLICY_QUALIFIERS 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param policyQualifiers
* POLICY_QUALIFIERS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_POLICY_QUALIFIERS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_POLICY_QUALIFIERS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_POLICY_QUALIFIERS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_POLICY_QUALIFIER_INFO()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_POLICY_QUALIFIERS(SEQUENCE *seq, POLICY_QUALIFIERS **policyQualifiers);

/*!
* \brief
* POLICY_QUALIFIER_INFO 구조체를 Sequence로 Encode 함수
* \param pqInfo
* POLICY_QUALIFIER_INFO 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_POLICY_QUALIFIER_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_POLICY_QUALIFIER_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# USER_NOTICE_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS POLICY_QUALIFIER_INFO_to_Seq(POLICY_QUALIFIER_INFO *pqInfo, SEQUENCE **seq);
/*!
* \brief
* Sequence를 POLICY_QUALIFIER_INFO 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param pqInfo
* POLICY_QUALIFIER_INFO 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_POLICY_QUALIFIER_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_POLICY_QUALIFIER_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_POLICY_QUALIFIER_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_USER_NOTICE()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_POLICY_QUALIFIER_INFO(SEQUENCE *seq, POLICY_QUALIFIER_INFO **pqInfo);

/*!
* \brief
* USER_NOTICE 구조체를 Sequence로 Encode 함수
* \param userNotice
* USER_NOTICE 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_USER_NOTICE_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_USER_NOTICE_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# NOTICE_REFERENCE_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS USER_NOTICE_to_Seq(USER_NOTICE *userNotice, SEQUENCE **seq);
/*!
* \brief
* Sequence를 USER_NOTICE 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param userNotice
* USER_NOTICE 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_USER_NOTICE^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_USER_NOTICE^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_USER_NOTICE^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_NOTICE_REFERENCE()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_USER_NOTICE(SEQUENCE *seq, USER_NOTICE **userNotice);

/*!
* \brief
* NOTICE_REFERENCE 구조체를 Sequence로 Encode 함수
* \param noticeRef
* NOTICE_REFERENCE 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_NOTICE_REFERENCE_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_NOTICE_REFERENCE_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# NOTICE_NUMBERS_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS NOTICE_REFERENCE_to_Seq(NOTICE_REFERENCE *noticeRef, SEQUENCE **seq);
/*!
* \brief
* Sequence를 NOTICE_REFERENCE 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param noticeRef
* NOTICE_REFERENCE 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_NOTICE_REFERENCE^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_NOTICE_REFERENCE^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_NOTICE_REFERENCE^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_NOTICE_NUMBERS()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_NOTICE_REFERENCE(SEQUENCE *seq, NOTICE_REFERENCE **noticeRef);

/*!
* \brief
* NOTICE_NUMBERS 구조체를 Sequence로 Encode 함수
* \param noticeNumbers
* NOTICE_NUMBERS 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_NOTICE_NUMBERS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_NOTICE_NUMBERS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS NOTICE_NUMBERS_to_Seq(NOTICE_NUMBERS *noticeNumbers, SEQUENCE_OF **seq);
/*!
* \brief
* Sequence를 NOTICE_NUMBERS 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param noticeNumbers
* NOTICE_NUMBERS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_NOTICE_NUMBERS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_NOTICE_NUMBERS^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_NOTICE_NUMBERS(SEQUENCE_OF *seq, NOTICE_NUMBERS **noticeNumbers);

/*!
* \brief
* Sequence를 GENERAL_SUBTREE 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param gs
* GENERAL_SUBTREE 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_GENERAL_SUBTREE^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_GENERAL_SUBTREE^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_GENERAL_NAME()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_GENERAL_SUBTREE(SEQUENCE *seq, GENERAL_SUBTREE **gs);
/*!
* \brief
* GENERAL_SUBTREE 구조체를 Sequence로 Encode 함수
* \param gs
* GENERAL_SUBTREE 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_GENERAL_SUBTREE_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_GENERAL_SUBTREE_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# GENERAL_NAME_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS GENERAL_SUBTREE_to_Seq(GENERAL_SUBTREE *gs, SEQUENCE **seq);

/*!
* \brief
* Sequence를 GENERAL_SUBTREES 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param gss
* GENERAL_SUBTREES 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_GENERAL_SUBTREES^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_GENERAL_SUBTREES^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_GENERAL_SUBTREES^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_GENERAL_SUBTREE()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_GENERAL_SUBTREES(SEQUENCE *seq, GENERAL_SUBTREES **gss);
/*!
* \brief
* GENERAL_SUBTREES 구조체를 Sequence로 Encode 함수
* \param gss
* GENERAL_SUBTREES 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_GENERAL_SUBTREES_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_GENERAL_SUBTREES_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_GENERAL_SUBTREES_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# GENERAL_SUBTREE_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS GENERAL_SUBTREES_to_Seq(GENERAL_SUBTREES *gss, SEQUENCE **seq);

/*!
* \brief
* Sequence를 NAME_CONSTRAINTS 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param nc
* NAME_CONSTRAINTS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_NAME_CONSTRAINTS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_NAME_CONSTRAINTS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_NAME_CONSTRAINTS^ERR_ASN1_DECODING : ASN1 Err
* -# GENERAL_SUBTREES_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_NAME_CONSTRAINTS(SEQUENCE *seq, NAME_CONSTRAINTS **nc);

/*!
* \brief
* NAME_CONSTRAINTS 구조체를 Sequence로 Encode 함수
* \param nc
* NAME_CONSTRAINTS 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_NAME_CONSTRAINTS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_NAME_CONSTRAINTS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_NAME_CONSTRAINTS^ERR_ASN1_ENCODING : ASN1 Err
* -# Seq_to_GENERAL_SUBTREES()의 에러 코드\n
*/
ISC_API ISC_STATUS NAME_CONSTRAINTS_to_Seq(NAME_CONSTRAINTS *nc, SEQUENCE **seq);


/*!
* \brief
* 국내 KISA 공인인증서의 VID를 이용한 본인 확인 함수
* \param cert
* 공인인증서
* \param rand
* 개인키에 포함된 random 값
* \param randlen
* rand길이
* \param idnum
* 주민등록번호 또는 사업자번호 ('-'없이)
* \param idnumlen
* idnumlen길이
* \returns
* -# TRUE : 본인확인 성공
* -# FALSE : 본인확인 실패
*/
ISC_API ISC_STATUS check_VID(const X509_CERT *cert, const uint8 *rand, int randlen, const char *idnum, int idnumlen);


/*!
* \brief
* Sequence를 X509_SIGN 구조체로 Decode 함수
* \param sign
* X509_SIGN 구조체
* \param seq
* Decoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^X509_SIGN_to_Seq^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^X509_SIGN_to_Seq^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^X509_SIGN_to_Seq^ERR_ASN1_DECODING : ASN1 Err
* -# GENERAL_SUBTREES_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS X509_SIGN_to_Seq(X509_SIGN* sign, SEQUENCE **seq);

/*!
* \brief
* X509_SIGN 구조체를 Sequence로 Encode 함수
* \param seq
* Encoding Sequence 구조체
* \param sign
* X509_SIGN 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_X509_SIGN^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_X509_SIGN^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_X509_SIGN^ERR_ASN1_ENCODING : ASN1 Err
* -# Seq_to_GENERAL_SUBTREES()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_X509_SIGN(SEQUENCE* seq, X509_SIGN **sign);

/*!
* \brief
* X509_CERT 인증서의 확장정보를 출력
* \param cert
* X509_CERT 구조체
*/
ISC_API void print_X509_Extension(X509_CERT *cert);

#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(VID*, new_VID, (), (), NULL);
INI_RET_LOADLIB_PKI(GENERAL_NAME*, new_GENERAL_NAME, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_GENERAL_NAME, (GENERAL_NAME* gn), (gn) );
INI_RET_LOADLIB_PKI(GENERAL_NAME*, dup_GENERAL_NAME, (GENERAL_NAME* src), (src), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_GENERAL_NAME, (GENERAL_NAME* dst, int type, void* name, int namelen), (dst, type, name, namelen), ISC_FAIL);
INI_RET_LOADLIB_PKI(GENERAL_NAMES*, new_GENERAL_NAMES, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_GENERAL_NAMES, (GENERAL_NAMES* gns), (gns) );
INI_RET_LOADLIB_PKI(GENERAL_NAMES*, dup_GENERAL_NAMES, (GENERAL_NAMES* gns), (gns), NULL);
INI_RET_LOADLIB_PKI(BASIC_CONSTRAINTS*, new_BASIC_CONSTRAINTS, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_BASIC_CONSTRAINTS, (BASIC_CONSTRAINTS* bs), (bs) );
INI_RET_LOADLIB_PKI(BASIC_CONSTRAINTS*, dup_BASIC_CONSTRAINTS, (BASIC_CONSTRAINTS* src), (src), NULL);
INI_RET_LOADLIB_PKI(OTHERNAME*, new_OTHERNAME, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_OTHERNAME, (OTHERNAME* on), (on) );
INI_RET_LOADLIB_PKI(OTHERNAME*, dup_OTHERNAME, (OTHERNAME* src), (src), NULL);
INI_RET_LOADLIB_PKI(EDIPARTYNAME*, new_EDIPARTYNAME, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_EDIPARTYNAME, (EDIPARTYNAME* e), (e) );
INI_RET_LOADLIB_PKI(EDIPARTYNAME*, dup_EDIPARTYNAME, (EDIPARTYNAME* src), (src), NULL);
INI_RET_LOADLIB_PKI(NOTICE_REFERENCE*, new_NOTICE_REFERENCE, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_NOTICE_REFERENCE, (NOTICE_REFERENCE* n), (n) );
INI_RET_LOADLIB_PKI(NOTICE_REFERENCE*, dup_NOTICE_REFERENCE, (NOTICE_REFERENCE* src), (src), NULL);
INI_RET_LOADLIB_PKI(USER_NOTICE*, new_USER_NOTICE, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_USER_NOTICE, (USER_NOTICE* n), (n) );
INI_RET_LOADLIB_PKI(USER_NOTICE*, dup_USER_NOTICE, (USER_NOTICE* src), (src), NULL);
INI_RET_LOADLIB_PKI(POLICY_QUALIFIER_INFO*, new_POLICY_QUALIFIER_INFO, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_POLICY_QUALIFIER_INFO, (POLICY_QUALIFIER_INFO *i), (i) );
INI_RET_LOADLIB_PKI(POLICY_QUALIFIER_INFO*, dup_POLICY_QUALIFIER_INFO, (POLICY_QUALIFIER_INFO *src), (src), NULL);
INI_RET_LOADLIB_PKI(POLICY_INFO*, new_POLICY_INFO, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_POLICY_INFO, (POLICY_INFO* i), (i) );
INI_RET_LOADLIB_PKI(POLICY_INFO*, dup_POLICY_INFO, (POLICY_INFO* src), (src), NULL);
INI_RET_LOADLIB_PKI(CERTIFICATE_POLICIES*, new_CERTIFICATE_POLICIES, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_CERTIFICATE_POLICIES, (CERTIFICATE_POLICIES* c), (c) );
INI_RET_LOADLIB_PKI(CERTIFICATE_POLICIES*, dup_CERTIFICATE_POLICIES, (CERTIFICATE_POLICIES* src), (src), NULL);
INI_RET_LOADLIB_PKI(POLICY_QUALIFIERS*, new_POLICY_QUALIFIERS, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_POLICY_QUALIFIERS, (POLICY_QUALIFIERS *pqs), (pqs) );
INI_RET_LOADLIB_PKI(POLICY_QUALIFIERS*, dup_POLICY_QUALIFIERS, (POLICY_QUALIFIERS *pqs), (pqs), NULL);
INI_RET_LOADLIB_PKI(POLICY_MAPPING*, new_POLICY_MAPPING, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_POLICY_MAPPING, (POLICY_MAPPING* pm), (pm) );
INI_RET_LOADLIB_PKI(POLICY_MAPPING*, dup_POLICY_MAPPING, (POLICY_MAPPING* src), (src), NULL);
INI_RET_LOADLIB_PKI(POLICY_MAPPINGS*, new_POLICY_MAPPINGS, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_POLICY_MAPPINGS, (POLICY_MAPPINGS* c), (c) );
INI_RET_LOADLIB_PKI(POLICY_MAPPINGS*, dup_POLICY_MAPPINGS, (POLICY_MAPPINGS* src), (src), NULL);
INI_RET_LOADLIB_PKI(ACCESS_DESCRIPTION*, new_ACCESS_DESCRIPTION, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_ACCESS_DESCRIPTION, (ACCESS_DESCRIPTION* ad), (ad) );
INI_RET_LOADLIB_PKI(ACCESS_DESCRIPTION*, dup_ACCESS_DESCRIPTION, (ACCESS_DESCRIPTION* src), (src), NULL);
INI_RET_LOADLIB_PKI(AUTHORITY_INFO_ACCESS*, new_AUTHORITY_INFO_ACCESS, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_AUTHORITY_INFO_ACCESS, (AUTHORITY_INFO_ACCESS* aia), (aia) );
INI_RET_LOADLIB_PKI(SUBJECT_INFO_ACCESS*, new_SUBJECT_INFO_ACCESS, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_SUBJECT_INFO_ACCESS, (SUBJECT_INFO_ACCESS* aia), (aia) );
INI_RET_LOADLIB_PKI(EXTENDED_KEY_USAGE*, new_EXTENDED_KEY_USAGE, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_EXTENDED_KEY_USAGE, (EXTENDED_KEY_USAGE* eku), (eku) );
INI_RET_LOADLIB_PKI(DIST_POINT_NAME*, new_DIST_POINT_NAME, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_DIST_POINT_NAME, (DIST_POINT_NAME* dpn), (dpn) );
INI_RET_LOADLIB_PKI(DIST_POINT_NAME*, dup_DIST_POINT_NAME, (DIST_POINT_NAME* src), (src), NULL);
INI_RET_LOADLIB_PKI(DIST_POINT*, new_DIST_POINT, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_DIST_POINT, (DIST_POINT* dp), (dp) );
INI_RET_LOADLIB_PKI(DIST_POINT*, dup_DIST_POINT, (DIST_POINT* src), (src), NULL);
INI_RET_LOADLIB_PKI(CRL_DIST_POINTS*, new_CRL_DIST_POINTS, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_CRL_DIST_POINTS, (CRL_DIST_POINTS* cdp), (cdp) );
INI_RET_LOADLIB_PKI(CRL_DIST_POINTS*, dup_CRL_DIST_POINTS, (CRL_DIST_POINTS* src), (src), NULL);
INI_RET_LOADLIB_PKI(AUTHORITY_KEYID*, new_AUTHORITY_KEYID, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_AUTHORITY_KEYID, (AUTHORITY_KEYID* ak), (ak) );
INI_RET_LOADLIB_PKI(AUTHORITY_KEYID*, dup_AUTHORITY_KEYID, (AUTHORITY_KEYID* src), (src), NULL);
INI_RET_LOADLIB_PKI(GENERAL_SUBTREE*, new_GENERAL_SUBTREE, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_GENERAL_SUBTREE, (GENERAL_SUBTREE* gs), (gs) );
INI_RET_LOADLIB_PKI(GENERAL_SUBTREE*, dup_GENERAL_SUBTREE, (GENERAL_SUBTREE* src), (src), NULL);
INI_RET_LOADLIB_PKI(GENERAL_SUBTREES*, new_GENERAL_SUBTREES, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_GENERAL_SUBTREES, (GENERAL_SUBTREES* gs), (gs) );
INI_RET_LOADLIB_PKI(GENERAL_SUBTREES*, dup_GENERAL_SUBTREES, (GENERAL_SUBTREES* gs), (gs), NULL);
INI_RET_LOADLIB_PKI(NAME_CONSTRAINTS*, new_NAME_CONSTRAINTS, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_NAME_CONSTRAINTS, (NAME_CONSTRAINTS* nc), (nc) );
INI_RET_LOADLIB_PKI(NAME_CONSTRAINTS*, dup_NAME_CONSTRAINTS, (NAME_CONSTRAINTS* src), (src), NULL);
INI_RET_LOADLIB_PKI(POLICY_CONSTRAINTS*, new_POLICY_CONSTRAINTS, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_POLICY_CONSTRAINTS, (POLICY_CONSTRAINTS* pc), (pc) );
INI_RET_LOADLIB_PKI(POLICY_CONSTRAINTS*, dup_POLICY_CONSTRAINTS, (POLICY_CONSTRAINTS* src), (src), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_GENERAL_NAME, (SEQUENCE *seq, GENERAL_NAME **gn), (seq,gn), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, GENERAL_NAME_to_Seq, (GENERAL_NAME *gn, SEQUENCE **seq), (gn,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_GENERAL_NAMES, (SEQUENCE *seq, GENERAL_NAMES **gns), (seq,gns), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, GENERAL_NAMES_to_Seq, (GENERAL_NAMES *gns, SEQUENCE **seq), (gns,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, AUTHORITY_KEYID_to_Seq, (AUTHORITY_KEYID* id, SEQUENCE **seq), (id,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_AUTHORITY_KEYID, (SEQUENCE *seq, AUTHORITY_KEYID **id), (seq,id), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_OTHERNAME, (SEQUENCE* seq, OTHERNAME **oth), (seq,oth), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, OTHERNAME_to_Seq, (OTHERNAME* oth, SEQUENCE **seq), (oth,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_EDIPARTYNAME, (SEQUENCE* seq, EDIPARTYNAME **e), (seq,e), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, EDIPARTYNAME_to_Seq, (EDIPARTYNAME* e, SEQUENCE **seq), (e,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_POLICY_CONSTRAINTS, (SEQUENCE* seq, POLICY_CONSTRAINTS **pc), (seq,pc), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, POLICY_CONSTRAINTS_to_Seq, (POLICY_CONSTRAINTS* pc, SEQUENCE **seq), (pc,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, VID_to_Seq, (VID *vid, SEQUENCE **seq), (vid,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_VID, (SEQUENCE *seq, VID **vid), (seq,vid), ISC_FAIL);
INI_RET_LOADLIB_PKI(KISA_IDENTIFY_DATA*, new_KISA_IDENTIFY_DATA, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_KISA_IDENTIFY_DATA, (KISA_IDENTIFY_DATA *v), (v) );
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_KISA_IDENTIFY_DATA, (SEQUENCE *seq, KISA_IDENTIFY_DATA **id), (seq,id), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, KISA_IDENTIFY_DATA_to_Seq, (KISA_IDENTIFY_DATA *id, SEQUENCE **seq), (id,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISSUING_DIST_POINT*, new_ISSUING_DIST_POINT, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_ISSUING_DIST_POINT, (ISSUING_DIST_POINT* idp), (idp) );
INI_RET_LOADLIB_PKI(ISSUING_DIST_POINTS*, new_ISSUING_DIST_POINTS, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_ISSUING_DIST_POINTS, (ISSUING_DIST_POINTS* cdp), (cdp) );
INI_RET_LOADLIB_PKI(ISSUING_DIST_POINTS*, dup_ISSUING_DIST_POINTS, (ISSUING_DIST_POINTS* src), (src), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_DIST_POINT, (SEQUENCE *seq, DIST_POINT **dp), (seq,dp), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, DIST_POINT_to_Seq, (DIST_POINT *dp, SEQUENCE **seq), (dp,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_CRL_DIST_POINTS, (SEQUENCE *seq, CRL_DIST_POINTS **cdp), (seq,cdp), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, CRL_DIST_POINTS_to_Seq, (CRL_DIST_POINTS *cdp, SEQUENCE **seq), (cdp,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, issuing_DIST_POINT_to_Seq, (ISSUING_DIST_POINT *idp, SEQUENCE **seq), (idp,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_issuing_DIST_POINT, (SEQUENCE *seq, ISSUING_DIST_POINT **idp), (seq,idp), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, issuing_DIST_POINTS_to_Seq, (ISSUING_DIST_POINTS *cdp, SEQUENCE **seq), (cdp,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_issuing_DIST_POINTS, (SEQUENCE *seq, ISSUING_DIST_POINTS **cdp), (seq,cdp), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, POLICY_MAPPING_to_Seq, (POLICY_MAPPING *pm, SEQUENCE **seq), (pm,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_POLICY_MAPPING, (SEQUENCE *seq, POLICY_MAPPING **pm), (seq,pm), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, POLICY_MAPPINGS_to_Seq, (POLICY_MAPPINGS *pms, SEQUENCE **seq), (pms,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_POLICY_MAPPINGS, (SEQUENCE *seq, POLICY_MAPPINGS **pms), (seq,pms), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, BASIC_CONSTRAINTS_to_Seq, (BASIC_CONSTRAINTS *bc, SEQUENCE **seq), (bc,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_BASIC_CONSTRAINTS, (SEQUENCE *seq, BASIC_CONSTRAINTS **bc), (seq,bc), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_POLICY_CONSTRAINTS, (SEQUENCE *seq, POLICY_CONSTRAINTS **pc), (seq,pc), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, POLICY_CONSTRAINTS_to_Seq, (POLICY_CONSTRAINTS *pc, SEQUENCE **seq), (pc,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_ACCESS_DESCRIPTION, (SEQUENCE *seq, ACCESS_DESCRIPTION **ad), (seq,ad), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, ACCESS_DESCRIPTION_to_Seq, (ACCESS_DESCRIPTION *ad, SEQUENCE **seq), (ad,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_AUTHORITY_INFO_ACCESS, (SEQUENCE *seq, AUTHORITY_INFO_ACCESS **aia), (seq,aia), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, AUTHORITY_INFO_ACCESS_to_Seq, (AUTHORITY_INFO_ACCESS *aia, SEQUENCE **seq), (aia,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_SUBJECT_INFO_ACCESS, (SEQUENCE *seq, SUBJECT_INFO_ACCESS **aia), (seq,aia), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, SUBJECT_INFO_ACCESS_to_Seq, (SUBJECT_INFO_ACCESS *aia, SEQUENCE **seq), (aia,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, CERTIFICATE_POLICIES_to_Seq, (CERTIFICATE_POLICIES *cps, SEQUENCE **seq), (cps,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_CERTIFICATE_POLICIES, (SEQUENCE *seq, CERTIFICATE_POLICIES **cps), (seq,cps), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, POLICY_INFO_to_Seq, (POLICY_INFO *policyInfo, SEQUENCE **seq), (policyInfo,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_POLICY_INFO, (SEQUENCE *seq, POLICY_INFO **policyInfo), (seq,policyInfo), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, POLICY_QUALIFIERS_to_Seq, (POLICY_QUALIFIERS *policyQualifiers, SEQUENCE **seq), (policyQualifiers,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_POLICY_QUALIFIERS, (SEQUENCE *seq, POLICY_QUALIFIERS **policyQualifiers), (seq,policyQualifiers), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, POLICY_QUALIFIER_INFO_to_Seq, (POLICY_QUALIFIER_INFO *pqInfo, SEQUENCE **seq), (pqInfo,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_POLICY_QUALIFIER_INFO, (SEQUENCE *seq, POLICY_QUALIFIER_INFO **pqInfo), (seq,pqInfo), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, USER_NOTICE_to_Seq, (USER_NOTICE *userNotice, SEQUENCE **seq), (userNotice,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_USER_NOTICE, (SEQUENCE *seq, USER_NOTICE **userNotice), (seq,userNotice), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, NOTICE_REFERENCE_to_Seq, (NOTICE_REFERENCE *noticeRef, SEQUENCE **seq), (noticeRef,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_NOTICE_REFERENCE, (SEQUENCE *seq, NOTICE_REFERENCE **noticeRef), (seq,noticeRef), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, NOTICE_NUMBERS_to_Seq, (NOTICE_NUMBERS *noticeNumbers, SEQUENCE_OF **seq), (noticeNumbers,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_NOTICE_NUMBERS, (SEQUENCE_OF *seq, NOTICE_NUMBERS **noticeNumbers), (seq,noticeNumbers), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_GENERAL_SUBTREE, (SEQUENCE *seq, GENERAL_SUBTREE **gs), (seq,gs), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, GENERAL_SUBTREE_to_Seq, (GENERAL_SUBTREE *gs, SEQUENCE **seq), (gs,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_GENERAL_SUBTREES, (SEQUENCE *seq, GENERAL_SUBTREES **gss), (seq,gss), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, GENERAL_SUBTREES_to_Seq, (GENERAL_SUBTREES *gss, SEQUENCE **seq), (gss,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_NAME_CONSTRAINTS, (SEQUENCE *seq, NAME_CONSTRAINTS **nc), (seq,nc), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, NAME_CONSTRAINTS_to_Seq, (NAME_CONSTRAINTS *nc, SEQUENCE **seq), (nc,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, check_VID, (const X509_CERT *cert, const uint8 *rand, int randlen, const char *idnum, int idnumlen), (cert,rand,randlen,idnum,idnumlen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, X509_SIGN_to_Seq, (X509_SIGN* sign, SEQUENCE **seq), (sign,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_X509_SIGN, (SEQUENCE* seq, X509_SIGN **sign), (seq,sign), ISC_FAIL);
INI_VOID_LOADLIB_PKI(void, print_X509_Extension, (X509_CERT *cert), (cert) );


#endif

#ifdef  __cplusplus
}
#endif

#endif
