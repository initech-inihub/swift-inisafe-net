/*!
* \file x509v3.h
* \brief X509_V3 Extension
* \remarks
* X509�� Ȯ���ʵ��� ����ü �� ���� �Լ�/��ũ�� ���
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
* X509 �⺻ ���� Ȯ���ʵ� ����ü
*/
typedef struct BASIC_CONSTRAINTS_st {
	int ca;					/*!< */
	INTEGER *pathlen;		/*!< */
} BASIC_CONSTRAINTS;


/*!
* \brief
* X509 Ű ���Ⱓ Ȯ���ʵ� ����ü
*/
typedef struct PKEY_USAGE_PERIOD_st {
	UTC_TIME *notBefore; /*!< */
	UTC_TIME *notAfter; /*!< */
} PKEY_USAGE_PERIOD;

/*!
* \brief
* X509 General Name Ȯ���ʵ��� OTHERNAME ����ü
*/
typedef struct otherName_st {
	OBJECT_IDENTIFIER *type_id; /*!< */
	ASN1_STRING *value; /*!< */
} OTHERNAME;

/*!
* \brief
* X509 General Name Ȯ���ʵ��� EDIPARTYNAME ����ü
*/
typedef struct EDIPartyName_st {
	ASN1_STRING *nameAssigner; /*!< */
	ASN1_STRING *partyName; /*!< */
} EDIPARTYNAME;

/*!
* \brief
* X509 General Name Ȯ���ʵ� ����ü
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
* X509 General Name Ȯ���ʵ��� ���� ����ü
*/
typedef STK(GENERAL_NAME) GENERAL_NAMES; 

/*!
* \brief
* X509 Access_Description Ȯ���ʵ��� ����ü
*/
typedef struct ACCESS_DESCRIPTION_st {
	OBJECT_IDENTIFIER *method; /*!< */
	GENERAL_NAME *location; /*!< */
} ACCESS_DESCRIPTION;

/*!
* \brief
* X509 Access_Description Ȯ���ʵ��� ���� ����ü
*/
typedef STK(ACCESS_DESCRIPTION) AUTHORITY_INFO_ACCESS;

/*!
* \brief
* X509 Access_Description Ȯ���ʵ��� ���� ����ü
*/
typedef STK(ACCESS_DESCRIPTION) SUBJECT_INFO_ACCESS;

/*!
* \brief
* X509 OBJECT_IDENTIFIER�� ���� ����ü
*/
typedef STK(OBJECT_IDENTIFIER) EXTENDED_KEY_USAGE;

/*!
* \brief
* X509 DIST_POINT Ȯ���ʵ��� DIST_POINT_NAME ����ü
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
* X509 DIST_POINT Ȯ���ʵ��� ����ü
*/
typedef struct DIST_POINT_st {
	DIST_POINT_NAME	*distpoint; /*!< */
	BIT_STRING *reasons; /*!< */
	GENERAL_NAMES *CRLissuer; /*!< */
} DIST_POINT;

/*!
* \brief
* X509 DIST_POINT Ȯ���ʵ��� ���� ����ü
*/
typedef STK(DIST_POINT) CRL_DIST_POINTS;

/*!
* \brief
* X509 AUTHORITY_KEYID Ȯ���ʵ��� ����ü
*/
typedef struct AUTHORITY_KEYID_st {
	OCTET_STRING *keyid;   /*!< */ /*cs0*/
	GENERAL_NAMES *issuer; /*!< */ /*cs1*/
	INTEGER *serial;	   /*!< */ /*cs2*/
} AUTHORITY_KEYID;

/*!
* \brief
* X509 INTEGER���� ���� ����ü
*/
typedef STK(INTEGER) NOTICE_NUMBERS;

/*!
* \brief
* X509 POLICY_INFO Ȯ���ʵ��� NOTICE_REFERENCE ����ü
*/
typedef struct NOTICEREF_st {
	ASN1_STRING *organization; /*!< */
	NOTICE_NUMBERS *noticeNumbers; /*!< */
} NOTICE_REFERENCE;
/*!
* \brief
* X509 POLICY_INFO Ȯ���ʵ��� USER_NOTICE ����ü
*/
typedef struct USERNOTICE_st {
	NOTICE_REFERENCE *noticeref; /*!< */
	ASN1_STRING *exptext; /*!< */
} USER_NOTICE;
/*!
* \brief
* X509 POLICY_INFO Ȯ���ʵ��� POLICY_QUALIFIER_INFO ����ü
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
* X509 POLICY_QUALIFIER_INFO�� ���� ����ü
*/
typedef STK(POLICY_QUALIFIER_INFO) POLICY_QUALIFIERS;

/*!
* \brief
* X509 POLICY_INFO Ȯ���ʵ��� ����ü
*/
typedef struct POLICYINFO_st {
	OBJECT_IDENTIFIER *policyid; /*!< */
	POLICY_QUALIFIERS *qualifiers; /*!< */
} POLICY_INFO;
/*!
* \brief
* X509 POLICY_INFO�� ���� ����ü
*/
typedef STK(POLICY_INFO) CERTIFICATE_POLICIES;

/*!
* \brief
* X509 POLICY_MAPPING Ȯ���ʵ��� ����ü
*/
typedef struct POLICY_MAPPING_st {
	OBJECT_IDENTIFIER *issuerDomainPolicy; /*!< */
	OBJECT_IDENTIFIER *subjectDomainPolicy; /*!< */
} POLICY_MAPPING;
/*!
* \brief
* X509 POLICY_MAPPING�� ���� ����ü
*/
typedef STK(POLICY_MAPPING) POLICY_MAPPINGS;

/*!
* \brief
* X509 GENERAL_SUBTREE Ȯ���ʵ��� ����ü
*/
typedef struct GENERAL_SUBTREE_st {
	GENERAL_NAME *base; /*!< */
	INTEGER *minimum; /*!< */
	INTEGER *maximum; /*!< */
} GENERAL_SUBTREE;
/*!
* \brief
* X509 GENERAL_SUBTREE Ȯ���ʵ��� ���� ����ü
*/
typedef STK(GENERAL_SUBTREE) GENERAL_SUBTREES;

/*!
* \brief
* X509 NAME_CONSTRAINTS Ȯ���ʵ��� ����ü
*/
typedef struct NAME_CONSTRAINTS_st {
	GENERAL_SUBTREES *permittedSubtrees; /*!< */
	GENERAL_SUBTREES *excludedSubtrees; /*!< */
} NAME_CONSTRAINTS;

/*!
* \brief
* X509 POLICY_CONSTRAINTS Ȯ���ʵ��� ����ü
*/
typedef struct POLICY_CONSTRAINTS_st {
	INTEGER *requireExplicitPolicy; /*!< */
	INTEGER *inhibitPolicyMapping; /*!< */
} POLICY_CONSTRAINTS;

/*!
* \brief
* X509 Subject/Issuer Altname Ȯ���ʵ��� ����ü
*/
typedef struct ALT_NAME_st {
	GENERAL_NAMES *names;
} ALT_NAME;

/*!
* \brief
* X509 VID Ȯ���ʵ��� ����ü
*/
typedef struct VID_st {
	OBJECT_IDENTIFIER * hashAlgo; /*!< */
	OCTET_STRING * vid; /*!< */
}VID;

/*!
* \brief
* X509 KISA_IDENTIFY_DATA Ȯ���ʵ��� ����ü
*/
typedef struct KISA_ID_DATA_st
{
	UTF8_STRING *realName; /*!< */
	OBJECT_IDENTIFIER * userInfo; /*!< */
	VID* vid; /*!< */
}KISA_IDENTIFY_DATA;

/*!
* \brief
* X509 ISSUING_DIST_POINT Ȯ���ʵ��� ����ü
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
* X509 ISSUING_DIST_POINT Ȯ���ʵ��� ���� ����ü
*/
typedef STK(ISSUING_DIST_POINT) ISSUING_DIST_POINTS;

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* VID ����ü�� �ʱ�ȭ �Լ�
* \returns
* VID ����ü ������
*/
ISC_API VID* new_VID();

/*!
* \brief
* GENERAL_NAME ����ü�� �ʱ�ȭ �Լ�
* \returns
* GENERAL_NAME ����ü ������
*/
ISC_API GENERAL_NAME* new_GENERAL_NAME();
/*!
* \brief
* GENERAL_NAME ����ü�� �޸� �Ҵ� ����
* \param gn
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_GENERAL_NAME(GENERAL_NAME* gn);
/*!
* \brief
* GENERAL_NAME ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ GENERAL_NAME ����ü
* \returns
* ����� GENERAL_NAME ����ü
*/
ISC_API GENERAL_NAME* dup_GENERAL_NAME(GENERAL_NAME* src);

/*!
* \brief
* GENERAL_NAME ����ü ���� �����ϴ� �Լ�
* \param dst 
* ���� ������ GENERAL_NAME ����ü
* \param type 
* ������ GENERAL_NAME type
* \param name 
* ������ GENERAL_NAME ��
* \returns
* ����� GENERAL_NAME ����ü
*/
ISC_API ISC_STATUS set_GENERAL_NAME(GENERAL_NAME* dst, int type, void *name, int namelen);


/*!
* \brief
* GENERAL_NAMES ����ü�� �ʱ�ȭ �Լ�
* \returns
* GENERAL_NAMES ����ü ������
*/
ISC_API GENERAL_NAMES* new_GENERAL_NAMES();

/*!
* \brief
* GENERAL_NAMES ����ü�� �޸� �Ҵ� ����
* \param gns
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_GENERAL_NAMES(GENERAL_NAMES* gns);

/*!
* \brief
* GENERAL_NAMES ����ü�� �����ϴ� �Լ�
* \param gns
* ���� ������ GENERAL_NAMES ����ü
* \returns
* ����� GENERAL_NAMES ����ü
*/
ISC_API GENERAL_NAMES* dup_GENERAL_NAMES(GENERAL_NAMES* gns);

/*!
* \brief
* ALT_NAME ����ü�� �ʱ�ȭ �Լ�
* \returns
* ALT_NAME ����ü ������
*/
ISC_API ALT_NAME* new_ALT_NAME();

/*!
* \brief
* ALT_NAME ����ü�� �޸� �Ҵ� ����
* \param alt_name 
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_ALT_NAME(ALT_NAME* alt_name);

/*!
* \brief
* Sequence�� ALT_NAME ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param an 
*  ALT_NAME ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_GENERAL_NAME^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_GENERAL_NAME^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_NAME()�� ���� �ڵ�\n
* -# Seq_to_EDIPARTYNAME()�� ���� �ڵ�\n
* -# ���� ���� ALT_NAME�� GENERAL_NAME ������ �����Ǿ������Ƿ� �����ڵ�� GENERAL_NAME�� ����\n
*/
ISC_API ISC_STATUS Seq_to_ALT_NAME(SEQUENCE *seq, ALT_NAME **an);

/*!
* \brief
* ALT_NAME ����ü�� Sequence�� Encode �Լ�
* \param an 
* ALT_NAME ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_GENERAL_NAME_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_GENERAL_NAME_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# OTHERNAME_to_Seq()�� ���� �ڵ�\n
* -# EDIPARTYNAME_to_Seq()�� ���� �ڵ�\n
* -# X509_NAME_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS ALT_NAME_to_Seq(ALT_NAME *an, SEQUENCE **seq);

/*!
* \brief
* BASIC_CONSTRAINTS ����ü�� �ʱ�ȭ �Լ�
* \returns
* BASIC_CONSTRAINTS ����ü ������
*/
ISC_API BASIC_CONSTRAINTS* new_BASIC_CONSTRAINTS();
/*!
* \brief
* BASIC_CONSTRAINTS ����ü�� �޸� �Ҵ� ����
* \param bs
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS* bs);
/*!
* \brief
* BASIC_CONSTRAINTS ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ BASIC_CONSTRAINTS ����ü
* \returns
* ����� BASIC_CONSTRAINTS ����ü
*/
ISC_API BASIC_CONSTRAINTS *dup_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS* src);

/*!
* \brief
* OTHERNAME ����ü�� �ʱ�ȭ �Լ�
* \returns
* OTHERNAME ����ü ������
*/
ISC_API OTHERNAME* new_OTHERNAME();
/*!
* \brief
* OTHERNAME ����ü�� �޸� �Ҵ� ����
* \param on
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_OTHERNAME(OTHERNAME* on);
/*!
* \brief
* OTHERNAME ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ OTHERNAME ����ü
* \returns
* ����� OTHERNAME ����ü
*/
ISC_API OTHERNAME *dup_OTHERNAME(OTHERNAME* src);

/*!
* \brief
* EDIPARTYNAME ����ü�� �ʱ�ȭ �Լ�
* \returns
* EDIPARTYNAME ����ü ������
*/
ISC_API EDIPARTYNAME* new_EDIPARTYNAME();
/*!
* \brief
* EDIPARTYNAME ����ü�� �޸� �Ҵ� ����
* \param e
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_EDIPARTYNAME(EDIPARTYNAME* e);
/*!
* \brief
* EDIPARTYNAME ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ EDIPARTYNAME ����ü
* \returns
* ����� EDIPARTYNAME ����ü
*/
ISC_API EDIPARTYNAME *dup_EDIPARTYNAME(EDIPARTYNAME* src);

/*!
* \brief
* POLICY_CONSTRAINTS ����ü�� �ʱ�ȭ �Լ�
* \returns
* POLICY_CONSTRAINTS ����ü ������
*/
ISC_API POLICY_CONSTRAINTS* new_POLICY_CONSTRAINTS();
/*!
* \brief
* POLICY_CONSTRAINTS ����ü�� �޸� �Ҵ� ����
* \param e
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_POLICY_CONSTRAINTS(POLICY_CONSTRAINTS* pc);
/*!
* \brief
* POLICY_CONSTRAINTS ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ POLICY_CONSTRAINTS ����ü
* \returns
* ����� POLICY_CONSTRAINTS ����ü
*/
ISC_API POLICY_CONSTRAINTS *dup_POLICY_CONSTRAINTS(POLICY_CONSTRAINTS* src);

/*!
* \brief
* NOTICE_REFERENCE ����ü�� �ʱ�ȭ �Լ�
* \returns
* NOTICE_REFERENCE ����ü ������
*/
ISC_API NOTICE_REFERENCE* new_NOTICE_REFERENCE();
/*!
* \brief
* NOTICE_REFERENCE ����ü�� �޸� �Ҵ� ����
* \param n
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_NOTICE_REFERENCE(NOTICE_REFERENCE* n);
/*!
* \brief
* NOTICE_REFERENCE ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ NOTICE_REFERENCE ����ü
* \returns
* ����� NOTICE_REFERENCE ����ü
*/
ISC_API NOTICE_REFERENCE* dup_NOTICE_REFERENCE(NOTICE_REFERENCE* src);

/*!
* \brief
* USER_NOTICE ����ü�� �ʱ�ȭ �Լ�
* \returns
* USER_NOTICE ����ü ������
*/
ISC_API USER_NOTICE* new_USER_NOTICE();
/*!
* \brief
* USER_NOTICE ����ü�� �޸� �Ҵ� ����
* \param n
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_USER_NOTICE(USER_NOTICE* n);
/*!
* \brief
* USER_NOTICE ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ USER_NOTICE ����ü
* \returns
* ����� USER_NOTICE ����ü
*/
ISC_API USER_NOTICE* dup_USER_NOTICE(USER_NOTICE* src);

/*!
* \brief
* POLICY_QUALIFIER_INFO ����ü�� �ʱ�ȭ �Լ�
* \returns
* POLICY_QUALIFIER_INFO ����ü ������
*/
ISC_API POLICY_QUALIFIER_INFO* new_POLICY_QUALIFIER_INFO();
/*!
* \brief
* POLICY_QUALIFIER_INFO ����ü�� �޸� �Ҵ� ����
* \param i
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_POLICY_QUALIFIER_INFO(POLICY_QUALIFIER_INFO *i);
/*!
* \brief
* POLICY_QUALIFIER_INFO ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ POLICY_QUALIFIER_INFO ����ü
* \returns
* ����� POLICY_QUALIFIER_INFO ����ü
*/
ISC_API POLICY_QUALIFIER_INFO* dup_POLICY_QUALIFIER_INFO(POLICY_QUALIFIER_INFO *src);

/*!
* \brief
* POLICY_INFO ����ü�� �ʱ�ȭ �Լ�
* \returns
* POLICY_INFO ����ü ������
*/
ISC_API POLICY_INFO* new_POLICY_INFO();
/*!
* \brief
* POLICY_INFO ����ü�� �޸� �Ҵ� ����
* \param i
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_POLICY_INFO(POLICY_INFO* i);
/*!
* \brief
* POLICY_INFO ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ POLICY_INFO ����ü
* \returns
* ����� POLICY_INFO ����ü
*/
ISC_API POLICY_INFO* dup_POLICY_INFO(POLICY_INFO* src);

/*!
* \brief
* CERTIFICATE_POLICIES ����ü�� �ʱ�ȭ �Լ�
* \returns
* CERTIFICATE_POLICIES ����ü ������
*/
ISC_API CERTIFICATE_POLICIES* new_CERTIFICATE_POLICIES();
/*!
* \brief
* CERTIFICATE_POLICIES ����ü�� �޸� �Ҵ� ����
* \param c
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_CERTIFICATE_POLICIES(CERTIFICATE_POLICIES* c);
/*!
* \brief
* CERTIFICATE_POLICIES ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ CERTIFICATE_POLICIES ����ü
* \returns
* ����� CERTIFICATE_POLICIES ����ü
*/
ISC_API CERTIFICATE_POLICIES *dup_CERTIFICATE_POLICIES(CERTIFICATE_POLICIES* src);

/*!
* \brief
* POLICY_QUALIFIERS ����ü�� �ʱ�ȭ �Լ�
* \returns
* POLICY_QUALIFIERS ����ü ������
*/
ISC_API POLICY_QUALIFIERS *new_POLICY_QUALIFIERS();
/*!
* \brief
* POLICY_QUALIFIERS ����ü�� �޸� �Ҵ� ����
* \param pqs
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_POLICY_QUALIFIERS(POLICY_QUALIFIERS *pqs);
/*!
* \brief
* POLICY_QUALIFIERS ����ü�� �����ϴ� �Լ�
* \param pqs
* ���� ������ POLICY_QUALIFIERS ����ü
* \returns
* ����� POLICY_QUALIFIERS ����ü
*/
ISC_API POLICY_QUALIFIERS *dup_POLICY_QUALIFIERS(POLICY_QUALIFIERS *pqs);

/*!
* \brief
* POLICY_MAPPING ����ü�� �ʱ�ȭ �Լ�
* \returns
* POLICY_MAPPING ����ü ������
*/
ISC_API POLICY_MAPPING* new_POLICY_MAPPING();
/*!
* \brief
* POLICY_MAPPING ����ü�� �޸� �Ҵ� ����
* \param pm
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_POLICY_MAPPING(POLICY_MAPPING* pm);
/*!
* \brief
* POLICY_MAPPING ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ POLICY_MAPPING ����ü
* \returns
* ����� POLICY_MAPPING ����ü
*/
ISC_API POLICY_MAPPING* dup_POLICY_MAPPING(POLICY_MAPPING* src);

/*!
* \brief
* POLICY_MAPPINGS ����ü�� �ʱ�ȭ �Լ�
* \returns
* POLICY_MAPPINGS ����ü ������
*/
ISC_API POLICY_MAPPINGS* new_POLICY_MAPPINGS();
/*!
* \brief
* POLICY_MAPPINGS ����ü�� �޸� �Ҵ� ����
* \param c
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_POLICY_MAPPINGS(POLICY_MAPPINGS* c);
/*!
* \brief
* POLICY_MAPPINGS ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ POLICY_MAPPINGS ����ü
* \returns
* ����� POLICY_MAPPINGS ����ü
*/
ISC_API POLICY_MAPPINGS *dup_POLICY_MAPPINGS(POLICY_MAPPINGS* src);

/*!
* \brief
* ACCESS_DESCRIPTION ����ü�� �ʱ�ȭ �Լ�
* \returns
* ACCESS_DESCRIPTION ����ü ������
*/
ISC_API ACCESS_DESCRIPTION* new_ACCESS_DESCRIPTION();
/*!
* \brief
* ACCESS_DESCRIPTION ����ü�� �޸� �Ҵ� ����
* \param ad
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_ACCESS_DESCRIPTION(ACCESS_DESCRIPTION* ad);
/*!
* \brief
* ACCESS_DESCRIPTION ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ ACCESS_DESCRIPTION ����ü
* \returns
* ����� ACCESS_DESCRIPTION ����ü
*/
ISC_API ACCESS_DESCRIPTION *dup_ACCESS_DESCRIPTION(ACCESS_DESCRIPTION* src);

/*!
* \brief
* AUTHORITY_INFO_ACCESS ����ü�� �ʱ�ȭ �Լ�
* \returns
* AUTHORITY_INFO_ACCESS ����ü ������
*/
ISC_API AUTHORITY_INFO_ACCESS* new_AUTHORITY_INFO_ACCESS();
/*!
* \brief
* AUTHORITY_INFO_ACCESS ����ü�� �޸� �Ҵ� ����
* \param aia
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_AUTHORITY_INFO_ACCESS(AUTHORITY_INFO_ACCESS* aia);

/*!
* \brief
* SUBJECT_INFO_ACCESS ����ü�� �ʱ�ȭ �Լ�
* \returns
* SUBJECT_INFO_ACCESS ����ü ������
*/
ISC_API SUBJECT_INFO_ACCESS* new_SUBJECT_INFO_ACCESS();
/*!
* \brief
* SUBJECT_INFO_ACCESS ����ü�� �޸� �Ҵ� ����
* \param aia
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_SUBJECT_INFO_ACCESS(SUBJECT_INFO_ACCESS* sia);

/*!
* \brief
* EXTENDED_KEY_USAGE ����ü�� �ʱ�ȭ �Լ�
* \returns
* EXTENDED_KEY_USAGE ����ü ������
*/
ISC_API EXTENDED_KEY_USAGE* new_EXTENDED_KEY_USAGE();
/*!
* \brief
* EXTENDED_KEY_USAGE ����ü�� �޸� �Ҵ� ����
* \param eku
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_EXTENDED_KEY_USAGE(EXTENDED_KEY_USAGE* eku);


/*!
* \brief
* DIST_POINT_NAME ����ü�� �ʱ�ȭ �Լ�
* \returns
* DIST_POINT_NAME ����ü ������
*/
ISC_API DIST_POINT_NAME* new_DIST_POINT_NAME();
/*!
* \brief
* DIST_POINT_NAME ����ü�� �޸� �Ҵ� ����
* \param dpn
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_DIST_POINT_NAME(DIST_POINT_NAME* dpn);
/*!
* \brief
* DIST_POINT_NAME ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ DIST_POINT_NAME ����ü
* \returns
* ����� DIST_POINT_NAME ����ü
*/
ISC_API DIST_POINT_NAME* dup_DIST_POINT_NAME(DIST_POINT_NAME* src);


/*!
* \brief
* DIST_POINT ����ü�� �ʱ�ȭ �Լ�
* \returns
* DIST_POINT ����ü ������
*/
ISC_API DIST_POINT* new_DIST_POINT();
/*!
* \brief
* DIST_POINT ����ü�� �޸� �Ҵ� ����
* \param dp
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_DIST_POINT(DIST_POINT* dp);
/*!
* \brief
* DIST_POINT ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ DIST_POINT ����ü
* \returns
* ����� DIST_POINT ����ü
*/
ISC_API DIST_POINT *dup_DIST_POINT(DIST_POINT* src);

/*!
* \brief
* CRL_DIST_POINTS ����ü�� �ʱ�ȭ �Լ�
* \returns
* CRL_DIST_POINTS ����ü ������
*/
ISC_API CRL_DIST_POINTS* new_CRL_DIST_POINTS();
/*!
* \brief
* CRL_DIST_POINTS ����ü�� �޸� �Ҵ� ����
* \param cdp
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_CRL_DIST_POINTS(CRL_DIST_POINTS* cdp);
/*!
* \brief
* CRL_DIST_POINTS ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ CRL_DIST_POINTS ����ü
* \returns
* ����� CRL_DIST_POINTS ����ü
*/
ISC_API CRL_DIST_POINTS* dup_CRL_DIST_POINTS(CRL_DIST_POINTS* src);

/*!
* \brief
* AUTHORITY_KEYID ����ü�� �ʱ�ȭ �Լ�
* \returns
* AUTHORITY_KEYID ����ü ������
*/
ISC_API AUTHORITY_KEYID* new_AUTHORITY_KEYID();
/*!
* \brief
* AUTHORITY_KEYID ����ü�� �޸� �Ҵ� ����
* \param ak
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_AUTHORITY_KEYID(AUTHORITY_KEYID* ak);
/*!
* \brief
* AUTHORITY_KEYID ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ AUTHORITY_KEYID ����ü
* \returns
* ����� AUTHORITY_KEYID ����ü
*/
ISC_API AUTHORITY_KEYID *dup_AUTHORITY_KEYID(AUTHORITY_KEYID* src);

/*!
* \brief
* GENERAL_SUBTREE ����ü�� �ʱ�ȭ �Լ�
* \returns
* GENERAL_SUBTREE ����ü ������
*/
ISC_API GENERAL_SUBTREE* new_GENERAL_SUBTREE();
/*!
* \brief
* GENERAL_SUBTREE ����ü�� �޸� �Ҵ� ����
* \param gs
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_GENERAL_SUBTREE(GENERAL_SUBTREE* gs);
/*!
* \brief
* GENERAL_SUBTREE ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ GENERAL_SUBTREE ����ü
* \returns
* ����� GENERAL_SUBTREE ����ü
*/
ISC_API GENERAL_SUBTREE *dup_GENERAL_SUBTREE(GENERAL_SUBTREE* src);

/*!
* \brief
* GENERAL_SUBTREES ����ü�� �ʱ�ȭ �Լ�
* \returns
* GENERAL_SUBTREES ����ü ������
*/
ISC_API GENERAL_SUBTREES* new_GENERAL_SUBTREES();
/*!
* \brief
* GENERAL_SUBTREES ����ü�� �޸� �Ҵ� ����
* \param gs
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_GENERAL_SUBTREES(GENERAL_SUBTREES* gs);
/*!
* \brief
* GENERAL_SUBTREES ����ü�� �����ϴ� �Լ�
* \param gs
* ���� ������ GENERAL_SUBTREES ����ü
* \returns
* ����� GENERAL_SUBTREES ����ü
*/
ISC_API GENERAL_SUBTREES* dup_GENERAL_SUBTREES(GENERAL_SUBTREES* gs);

/*!
* \brief
* NAME_CONSTRAINTS ����ü�� �ʱ�ȭ �Լ�
* \returns
* NAME_CONSTRAINTS ����ü ������
*/
ISC_API NAME_CONSTRAINTS* new_NAME_CONSTRAINTS();
/*!
* \brief
* NAME_CONSTRAINTS ����ü�� �޸� �Ҵ� ����
* \param nc
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_NAME_CONSTRAINTS(NAME_CONSTRAINTS* nc);
/*!
* \brief
* NAME_CONSTRAINTS ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ NAME_CONSTRAINTS ����ü
* \returns
* ����� NAME_CONSTRAINTS ����ü
*/
ISC_API NAME_CONSTRAINTS *dup_NAME_CONSTRAINTS(NAME_CONSTRAINTS* src);

/*!
* \brief
* POLICY_CONSTRAINTS ����ü�� �ʱ�ȭ �Լ�
* \returns
* POLICY_CONSTRAINTS ����ü ������
*/
ISC_API POLICY_CONSTRAINTS* new_POLICY_CONSTRAINTS();
/*!
* \brief
* POLICY_CONSTRAINTS ����ü�� �޸� �Ҵ� ����
* \param pc
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_POLICY_CONSTRAINTS(POLICY_CONSTRAINTS* pc);
/*!
* \brief
* POLICY_CONSTRAINTS ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ POLICY_CONSTRAINTS ����ü
* \returns
* ����� POLICY_CONSTRAINTS ����ü
*/
ISC_API POLICY_CONSTRAINTS *dup_POLICY_CONSTRAINTS(POLICY_CONSTRAINTS* src);

/*!
* \brief
* Sequence�� GENERAL_NAME ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param gn
* GENERAL_NAME ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_GENERAL_NAME^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_GENERAL_NAME^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_NAME()�� ���� �ڵ�\n
* -# Seq_to_EDIPARTYNAME()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_GENERAL_NAME(SEQUENCE *seq, GENERAL_NAME **gn);
/*!
* \brief
* GENERAL_NAME ����ü�� Sequence�� Encode �Լ�
* \param gn
* GENERAL_NAME ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_GENERAL_NAME_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_GENERAL_NAME_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# OTHERNAME_to_Seq()�� ���� �ڵ�\n
* -# EDIPARTYNAME_to_Seq()�� ���� �ڵ�\n
* -# X509_NAME_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS GENERAL_NAME_to_Seq(GENERAL_NAME *gn, SEQUENCE **seq);

/*!
* \brief
* Sequence�� GENERAL_NAMES ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param gns
* GENERAL_NAMES ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_GENERAL_NAMES^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_GENERAL_NAMES^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_GENERAL_NAMES^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_GENERAL_NAME()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_GENERAL_NAMES(SEQUENCE *seq, GENERAL_NAMES **gns);
/*!
* \brief
* GENERAL_NAME ����ü�� Sequence�� Encode �Լ�
* \param gns
* GENERAL_NAME ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_GENERAL_NAMES_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_GENERAL_NAMES_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_GENERAL_NAMES_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# GENERAL_NAME_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS GENERAL_NAMES_to_Seq(GENERAL_NAMES *gns, SEQUENCE **seq);

/*!
* \brief
* AUTHORITY_KEYID ����ü�� Sequence�� Encode �Լ�
* \param id
* AUTHORITY_KEYID ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_AUTHORITY_KEYID_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_AUTHORITY_KEYID_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# GENERAL_NAMES_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS AUTHORITY_KEYID_to_Seq(AUTHORITY_KEYID* id, SEQUENCE **seq);
/*!
* \brief
* Sequence�� P8_PRIV_KEY_INFO ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param id
* P8_PRIV_KEY_INFO ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_AUTHORITY_KEYID^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_AUTHORITY_KEYID^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_AUTHORITY_KEYID^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_GENERAL_NAMES()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_AUTHORITY_KEYID(SEQUENCE *seq, AUTHORITY_KEYID **id);

/*!
* \brief
* Sequence�� OTHERNAME ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param oth
* OTHERNAME ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_OTHERNAME^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_OTHERNAME^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_OTHERNAME^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_OTHERNAME(SEQUENCE* seq, OTHERNAME **oth);
/*!
* \brief
* OTHERNAME ����ü�� Sequence�� Encode �Լ�
* \param oth
* OTHERNAME ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_OTHERNAME_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_OTHERNAME_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_OTHERNAME_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS OTHERNAME_to_Seq(OTHERNAME* oth, SEQUENCE **seq);

/*!
* \brief
* Sequence�� EDIPARTYNAME ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param e
* EDIPARTYNAME ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_EDIPARTYNAME^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_EDIPARTYNAME^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_EDIPARTYNAME^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_EDIPARTYNAME(SEQUENCE* seq, EDIPARTYNAME **e);
/*!
* \brief
* EDIPARTYNAME ����ü�� Sequence�� Encode �Լ�
* \param e
* EDIPARTYNAME ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_EDIPARTYNAME_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_EDIPARTYNAME_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_EDIPARTYNAME_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS EDIPARTYNAME_to_Seq(EDIPARTYNAME* e, SEQUENCE **seq);

/*!
* \brief
* Sequence�� POLICY_CONSTRAINTS ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param e
* POLICY_CONSTRAINTS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_POLICY_CONSTRAINTS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_POLICY_CONSTRAINTS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_POLICY_CONSTRAINTS^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_POLICY_CONSTRAINTS(SEQUENCE* seq, POLICY_CONSTRAINTS **pc);
/*!
* \brief
* POLICY_CONSTRAINTS ����ü�� Sequence�� Encode �Լ�
* \param e
* POLICY_CONSTRAINTS ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_POLICY_CONSTRAINTS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_POLICY_CONSTRAINTS_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_POLICY_CONSTRAINTS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS POLICY_CONSTRAINTS_to_Seq(POLICY_CONSTRAINTS* pc, SEQUENCE **seq);

/*!
* \brief
* VID ����ü�� Sequence�� Encode �Լ�
* \param vid
* VID ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_VID_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_VID_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS VID_to_Seq(VID *vid, SEQUENCE **seq);
/*!
* \brief
* Sequence�� VID ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param vid
* VID ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_VID^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_VID^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_CRL_INFO()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_VID(SEQUENCE *seq, VID **vid);


ISC_API KISA_IDENTIFY_DATA *new_KISA_IDENTIFY_DATA(void);

ISC_API void free_KISA_IDENTIFY_DATA(KISA_IDENTIFY_DATA *v);

/*!
* \brief
* Sequence�� KISA_IDENTIFY_DATA ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param id
* KISA_IDENTIFY_DATA ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_KISA_IDENTIFY_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_KISA_IDENTIFY_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_VID()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_KISA_IDENTIFY_DATA(SEQUENCE *seq, KISA_IDENTIFY_DATA **id);
/*!
* \brief
* KISA_IDENTIFY_DATA ����ü�� Sequence�� Encode �Լ�
* \param id
* KISA_IDENTIFY_DATA ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_KISA_IDENTIFY_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_VID_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# VID_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS KISA_IDENTIFY_DATA_to_Seq(KISA_IDENTIFY_DATA *id, SEQUENCE **seq);

/*!
* \brief
* ISSUING_DIST_POINT ����ü�� �ʱ�ȭ �Լ�
* \returns
* ISSUING_DIST_POINT ����ü ������
*/
ISC_API ISSUING_DIST_POINT* new_ISSUING_DIST_POINT();
/*!
* \brief
* ISSUING_DIST_POINT ����ü�� �޸� �Ҵ� ����
* \param idp
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_ISSUING_DIST_POINT(ISSUING_DIST_POINT* idp);

/*!
* \brief
* ISSUING_DIST_POINTS ����ü�� �ʱ�ȭ �Լ�
* \returns
* ISSUING_DIST_POINTS ����ü ������
*/
ISC_API ISSUING_DIST_POINTS* new_ISSUING_DIST_POINTS();
/*!
* \brief
* ISSUING_DIST_POINTS ����ü�� �޸� �Ҵ� ����
* \param cdp
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_ISSUING_DIST_POINTS(ISSUING_DIST_POINTS* cdp);
/*!
* \brief
* ISSUING_DIST_POINTS ����ü�� �����ϴ� �Լ�
* \param src
* ���� ������ ISSUING_DIST_POINTS ����ü
* \returns
* ����� ISSUING_DIST_POINTS ����ü
*/
ISC_API ISSUING_DIST_POINTS* dup_ISSUING_DIST_POINTS(ISSUING_DIST_POINTS* src);

/*!
* \brief
* Sequence�� DIST_POINT ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param dp
* DIST_POINT ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_DIST_POINT^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_DIST_POINT^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_GENERAL_NAMES()�� ���� �ڵ�\n
* -# Seq_to_X509_NAME()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_DIST_POINT(SEQUENCE *seq, DIST_POINT **dp);
/*!
* \brief
* DIST_POINT ����ü�� Sequence�� Encode �Լ�
* \param dp
* DIST_POINT ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_DIST_POINT_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_DIST_POINT_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# GENERAL_NAMES_to_Seq()�� ���� �ڵ�\n
* -# X509_NAME_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS DIST_POINT_to_Seq(DIST_POINT *dp, SEQUENCE **seq);

/*!
* \brief
* Sequence�� CRL_DIST_POINTS ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param cdp
* CRL_DIST_POINTS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_CRL_DIST_POINTS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CRL_DIST_POINTS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CRL_DIST_POINTS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_DIST_POINT()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_CRL_DIST_POINTS(SEQUENCE *seq, CRL_DIST_POINTS **cdp);
/*!
* \brief
* CRL_DIST_POINTS ����ü�� Sequence�� Encode �Լ�
* \param cdp
* CRL_DIST_POINTS ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_CRL_DIST_POINTS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CRL_DIST_POINTS_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_CRL_DIST_POINTS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# DIST_POINT_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS CRL_DIST_POINTS_to_Seq(CRL_DIST_POINTS *cdp, SEQUENCE **seq);

/*!
* \brief
* ISSUING_DIST_POINT ����ü�� Sequence�� Encode �Լ�
* \param idp
* ISSUING_DIST_POINT ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ISSUING_DIST_POINT_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_ISSUING_DIST_POINT_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# GENERAL_NAMES_to_Seq()�� ���� �ڵ�\n
* -# X509_NAME_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS issuing_DIST_POINT_to_Seq(ISSUING_DIST_POINT *idp, SEQUENCE **seq);
/*!
* \brief
* Sequence�� ISSUING_DIST_POINT ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param idp
* ISSUING_DIST_POINT ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_ISSUING_DIST_POINT^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_ISSUING_DIST_POINT^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_GENERAL_NAMES()�� ���� �ڵ�\n
* -# Seq_to_X509_NAME()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_issuing_DIST_POINT(SEQUENCE *seq, ISSUING_DIST_POINT **idp);
/*!
* \brief
* ISSUING_DIST_POINTS ����ü�� Sequence�� Encode �Լ�
* \param cdp
* ISSUING_DIST_POINTS ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ISSUING_DIST_POINTS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_ISSUING_DIST_POINTS_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_ISSUING_DIST_POINTS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# issuing_DIST_POINT_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS issuing_DIST_POINTS_to_Seq(ISSUING_DIST_POINTS *cdp, SEQUENCE **seq);
/*!
* \brief
* Sequence�� ISSUING_DIST_POINTS ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param cdp
* ISSUING_DIST_POINTS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_ISSUING_DIST_POINTS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_ISSUING_DIST_POINTS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_ISSUING_DIST_POINTS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_issuing_DIST_POINT()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_issuing_DIST_POINTS(SEQUENCE *seq, ISSUING_DIST_POINTS **cdp);

/*!
* \brief
* POLICY_MAPPING ����ü�� Sequence�� Encode �Լ�
* \param pm
* POLICY_MAPPING ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_POLICY_MAPPING_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_POLICY_MAPPING_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS POLICY_MAPPING_to_Seq(POLICY_MAPPING *pm, SEQUENCE **seq);
/*!
* \brief
* Sequence�� POLICY_MAPPING ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param pm
* POLICY_MAPPING ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_POLICY_MAPPING^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_POLICY_MAPPING^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_POLICY_MAPPING(SEQUENCE *seq, POLICY_MAPPING **pm);

/*!
* \brief
* POLICY_MAPPINGS ����ü�� Sequence�� Encode �Լ�
* \param pms
* POLICY_MAPPINGS ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_POLICY_MAPPINGS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_POLICY_MAPPINGS_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_POLICY_MAPPINGS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# POLICY_MAPPING_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS POLICY_MAPPINGS_to_Seq(POLICY_MAPPINGS *pms, SEQUENCE **seq);
/*!
* \brief
* Sequence�� POLICY_MAPPINGS ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param pms
* POLICY_MAPPINGS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_POLICY_MAPPINGS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_POLICY_MAPPINGS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_POLICY_MAPPING()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_POLICY_MAPPINGS(SEQUENCE *seq, POLICY_MAPPINGS **pms);

/*!
* \brief
* BASIC_CONSTRAINTS ����ü�� Sequence�� Encode �Լ�
* \param bc
* BASIC_CONSTRAINTS ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_BASIC_CONSTRAINTS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_BASIC_CONSTRAINTS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS BASIC_CONSTRAINTS_to_Seq(BASIC_CONSTRAINTS *bc, SEQUENCE **seq);
/*!
* \brief
* Sequence�� BASIC_CONSTRAINTS ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param bc
* BASIC_CONSTRAINTS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_BASIC_CONSTRAINTS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_BASIC_CONSTRAINTS^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_BASIC_CONSTRAINTS(SEQUENCE *seq, BASIC_CONSTRAINTS **bc);

/*!
* \brief
* Sequence�� POLICY_CONSTRAINTS ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param pc
* POLICY_CONSTRAINTS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_POLICY_CONSTRAINTS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_POLICY_CONSTRAINTS^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_POLICY_CONSTRAINTS(SEQUENCE *seq, POLICY_CONSTRAINTS **pc);
/*!
* \brief
* POLICY_CONSTRAINTS ����ü�� Sequence�� Encode �Լ�
* \param pc
* POLICY_CONSTRAINTS ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_POLICY_CONSTRAINTS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_POLICY_CONSTRAINTS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS POLICY_CONSTRAINTS_to_Seq(POLICY_CONSTRAINTS *pc, SEQUENCE **seq);

/*!
* \brief
* Sequence�� ACCESS_DESCRIPTION ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param ad
* ACCESS_DESCRIPTION ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_ACCESS_DESCRIPTION^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_ACCESS_DESCRIPTION^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_GENERAL_NAME()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_ACCESS_DESCRIPTION(SEQUENCE *seq, ACCESS_DESCRIPTION **ad);
/*!
* \brief
* ACCESS_DESCRIPTION ����ü�� Sequence�� Encode �Լ�
* \param ad
* ACCESS_DESCRIPTION ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ACCESS_DESCRIPTION_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_ACCESS_DESCRIPTION_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# GENERAL_NAME_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS ACCESS_DESCRIPTION_to_Seq(ACCESS_DESCRIPTION *ad, SEQUENCE **seq);

/*!
* \brief
* Sequence�� AUTHORITY_INFO_ACCESS ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param aia
* AUTHORITY_INFO_ACCESS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_AUTHORITY_INFO_ACCESS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_AUTHORITY_INFO_ACCESS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_AUTHORITY_INFO_ACCESS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_ACCESS_DESCRIPTION()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_AUTHORITY_INFO_ACCESS(SEQUENCE *seq, AUTHORITY_INFO_ACCESS **aia);
/*!
* \brief
* AUTHORITY_INFO_ACCESS ����ü�� Sequence�� Encode �Լ�
* \param aia
* AUTHORITY_INFO_ACCESS ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_AUTHORITY_INFO_ACCESS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_AUTHORITY_INFO_ACCESS_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_AUTHORITY_INFO_ACCESS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# ACCESS_DESCRIPTION_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS AUTHORITY_INFO_ACCESS_to_Seq(AUTHORITY_INFO_ACCESS *aia, SEQUENCE **seq);

/*!
* \brief
* Sequence�� SUBJECT_INFO_ACCESS ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param aia
* SUBJECT_INFO_ACCESS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_SUBJECT_INFO_ACCESS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_SUBJECT_INFO_ACCESS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_SUBJECT_INFO_ACCESS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_ACCESS_DESCRIPTION()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_SUBJECT_INFO_ACCESS(SEQUENCE *seq, SUBJECT_INFO_ACCESS **aia);
/*!
* \brief
* SUBJECT_INFO_ACCESS ����ü�� Sequence�� Encode �Լ�
* \param aia
* SUBJECT_INFO_ACCESS ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SUBJECT_INFO_ACCESS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SUBJECT_INFO_ACCESS_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SUBJECT_INFO_ACCESS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# ACCESS_DESCRIPTION_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS SUBJECT_INFO_ACCESS_to_Seq(SUBJECT_INFO_ACCESS *aia, SEQUENCE **seq);

/*!
* \brief
* CERTIFICATE_POLICIES ����ü�� Sequence�� Encode �Լ�
* \param cps
* CERTIFICATE_POLICIES ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_CERTIFICATE_POLICIES_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CERTIFICATE_POLICIES_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_CERTIFICATE_POLICIES_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# POLICY_INFO_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS CERTIFICATE_POLICIES_to_Seq(CERTIFICATE_POLICIES *cps, SEQUENCE **seq);
/*!
* \brief
* Sequence�� CERTIFICATE_POLICIES ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param cps
* CERTIFICATE_POLICIES ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_CERTIFICATE_POLICIES^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CERTIFICATE_POLICIES^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CERTIFICATE_POLICIES^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_POLICY_INFO()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_CERTIFICATE_POLICIES(SEQUENCE *seq, CERTIFICATE_POLICIES **cps);

/*!
* \brief
* POLICY_INFO ����ü�� Sequence�� Encode �Լ�
* \param policyInfo
* POLICY_INFO ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_POLICY_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_POLICY_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# POLICY_QUALIFIERS_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS POLICY_INFO_to_Seq(POLICY_INFO *policyInfo, SEQUENCE **seq);
/*!
* \brief
* Sequence�� POLICY_INFO ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param policyInfo
* POLICY_INFO ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_POLICY_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_POLICY_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_POLICY_QUALIFIERS()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_POLICY_INFO(SEQUENCE *seq, POLICY_INFO **policyInfo);

/*!
* \brief
* POLICY_QUALIFIERS ����ü�� Sequence�� Encode �Լ�
* \param policyQualifiers
* POLICY_QUALIFIERS ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_POLICY_QUALIFIERS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_POLICY_QUALIFIERS_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_POLICY_QUALIFIERS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# POLICY_QUALIFIER_INFO_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS POLICY_QUALIFIERS_to_Seq(POLICY_QUALIFIERS *policyQualifiers, SEQUENCE **seq);
/*!
* \brief
* Sequence�� POLICY_QUALIFIERS ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param policyQualifiers
* POLICY_QUALIFIERS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_POLICY_QUALIFIERS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_POLICY_QUALIFIERS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_POLICY_QUALIFIERS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_POLICY_QUALIFIER_INFO()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_POLICY_QUALIFIERS(SEQUENCE *seq, POLICY_QUALIFIERS **policyQualifiers);

/*!
* \brief
* POLICY_QUALIFIER_INFO ����ü�� Sequence�� Encode �Լ�
* \param pqInfo
* POLICY_QUALIFIER_INFO ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_POLICY_QUALIFIER_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_POLICY_QUALIFIER_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# USER_NOTICE_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS POLICY_QUALIFIER_INFO_to_Seq(POLICY_QUALIFIER_INFO *pqInfo, SEQUENCE **seq);
/*!
* \brief
* Sequence�� POLICY_QUALIFIER_INFO ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param pqInfo
* POLICY_QUALIFIER_INFO ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_POLICY_QUALIFIER_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_POLICY_QUALIFIER_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_POLICY_QUALIFIER_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_USER_NOTICE()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_POLICY_QUALIFIER_INFO(SEQUENCE *seq, POLICY_QUALIFIER_INFO **pqInfo);

/*!
* \brief
* USER_NOTICE ����ü�� Sequence�� Encode �Լ�
* \param userNotice
* USER_NOTICE ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_USER_NOTICE_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_USER_NOTICE_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# NOTICE_REFERENCE_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS USER_NOTICE_to_Seq(USER_NOTICE *userNotice, SEQUENCE **seq);
/*!
* \brief
* Sequence�� USER_NOTICE ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param userNotice
* USER_NOTICE ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_USER_NOTICE^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_USER_NOTICE^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_USER_NOTICE^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_NOTICE_REFERENCE()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_USER_NOTICE(SEQUENCE *seq, USER_NOTICE **userNotice);

/*!
* \brief
* NOTICE_REFERENCE ����ü�� Sequence�� Encode �Լ�
* \param noticeRef
* NOTICE_REFERENCE ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_NOTICE_REFERENCE_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_NOTICE_REFERENCE_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# NOTICE_NUMBERS_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS NOTICE_REFERENCE_to_Seq(NOTICE_REFERENCE *noticeRef, SEQUENCE **seq);
/*!
* \brief
* Sequence�� NOTICE_REFERENCE ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param noticeRef
* NOTICE_REFERENCE ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_NOTICE_REFERENCE^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_NOTICE_REFERENCE^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_NOTICE_REFERENCE^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_NOTICE_NUMBERS()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_NOTICE_REFERENCE(SEQUENCE *seq, NOTICE_REFERENCE **noticeRef);

/*!
* \brief
* NOTICE_NUMBERS ����ü�� Sequence�� Encode �Լ�
* \param noticeNumbers
* NOTICE_NUMBERS ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_NOTICE_NUMBERS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_NOTICE_NUMBERS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS NOTICE_NUMBERS_to_Seq(NOTICE_NUMBERS *noticeNumbers, SEQUENCE_OF **seq);
/*!
* \brief
* Sequence�� NOTICE_NUMBERS ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param noticeNumbers
* NOTICE_NUMBERS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_NOTICE_NUMBERS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_NOTICE_NUMBERS^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_NOTICE_NUMBERS(SEQUENCE_OF *seq, NOTICE_NUMBERS **noticeNumbers);

/*!
* \brief
* Sequence�� GENERAL_SUBTREE ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param gs
* GENERAL_SUBTREE ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_GENERAL_SUBTREE^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_GENERAL_SUBTREE^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_GENERAL_NAME()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_GENERAL_SUBTREE(SEQUENCE *seq, GENERAL_SUBTREE **gs);
/*!
* \brief
* GENERAL_SUBTREE ����ü�� Sequence�� Encode �Լ�
* \param gs
* GENERAL_SUBTREE ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_GENERAL_SUBTREE_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_GENERAL_SUBTREE_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# GENERAL_NAME_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS GENERAL_SUBTREE_to_Seq(GENERAL_SUBTREE *gs, SEQUENCE **seq);

/*!
* \brief
* Sequence�� GENERAL_SUBTREES ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param gss
* GENERAL_SUBTREES ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_GENERAL_SUBTREES^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_GENERAL_SUBTREES^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_GENERAL_SUBTREES^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_GENERAL_SUBTREE()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_GENERAL_SUBTREES(SEQUENCE *seq, GENERAL_SUBTREES **gss);
/*!
* \brief
* GENERAL_SUBTREES ����ü�� Sequence�� Encode �Լ�
* \param gss
* GENERAL_SUBTREES ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_GENERAL_SUBTREES_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_GENERAL_SUBTREES_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_GENERAL_SUBTREES_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# GENERAL_SUBTREE_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS GENERAL_SUBTREES_to_Seq(GENERAL_SUBTREES *gss, SEQUENCE **seq);

/*!
* \brief
* Sequence�� NAME_CONSTRAINTS ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param nc
* NAME_CONSTRAINTS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_NAME_CONSTRAINTS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_NAME_CONSTRAINTS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_NAME_CONSTRAINTS^ERR_ASN1_DECODING : ASN1 Err
* -# GENERAL_SUBTREES_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_NAME_CONSTRAINTS(SEQUENCE *seq, NAME_CONSTRAINTS **nc);

/*!
* \brief
* NAME_CONSTRAINTS ����ü�� Sequence�� Encode �Լ�
* \param nc
* NAME_CONSTRAINTS ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_NAME_CONSTRAINTS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_NAME_CONSTRAINTS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_NAME_CONSTRAINTS^ERR_ASN1_ENCODING : ASN1 Err
* -# Seq_to_GENERAL_SUBTREES()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS NAME_CONSTRAINTS_to_Seq(NAME_CONSTRAINTS *nc, SEQUENCE **seq);


/*!
* \brief
* ���� KISA ������������ VID�� �̿��� ���� Ȯ�� �Լ�
* \param cert
* ����������
* \param rand
* ����Ű�� ���Ե� random ��
* \param randlen
* rand����
* \param idnum
* �ֹε�Ϲ�ȣ �Ǵ� ����ڹ�ȣ ('-'����)
* \param idnumlen
* idnumlen����
* \returns
* -# TRUE : ����Ȯ�� ����
* -# FALSE : ����Ȯ�� ����
*/
ISC_API ISC_STATUS check_VID(const X509_CERT *cert, const uint8 *rand, int randlen, const char *idnum, int idnumlen);


/*!
* \brief
* Sequence�� X509_SIGN ����ü�� Decode �Լ�
* \param sign
* X509_SIGN ����ü
* \param seq
* Decoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^X509_SIGN_to_Seq^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^X509_SIGN_to_Seq^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^X509_SIGN_to_Seq^ERR_ASN1_DECODING : ASN1 Err
* -# GENERAL_SUBTREES_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS X509_SIGN_to_Seq(X509_SIGN* sign, SEQUENCE **seq);

/*!
* \brief
* X509_SIGN ����ü�� Sequence�� Encode �Լ�
* \param seq
* Encoding Sequence ����ü
* \param sign
* X509_SIGN ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_X509_SIGN^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_X509_SIGN^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_X509_SIGN^ERR_ASN1_ENCODING : ASN1 Err
* -# Seq_to_GENERAL_SUBTREES()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_X509_SIGN(SEQUENCE* seq, X509_SIGN **sign);

/*!
* \brief
* X509_CERT �������� Ȯ�������� ���
* \param cert
* X509_CERT ����ü
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
