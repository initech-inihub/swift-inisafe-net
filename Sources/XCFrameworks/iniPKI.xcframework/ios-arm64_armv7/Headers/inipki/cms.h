/*!
* \file cms.h
* \brief CMS
* Cryptographic Message Syntax
* \remarks
* \author
* Copyright (c) 2008 by \<INITECH\>
*/
#ifndef __CMS_H__
#define __CMS_H__

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/foundation.h>

#include "asn1_objects.h"
#include "issuer_and_serial_number.h"
#include "x509.h"
#include "x509_crl.h"

#ifdef  __cplusplus
extern "C" {
#endif


/* �Է��� �� �������� ��� ������ ������ �������� �ʰ�, ��ȣȭ�� ��ȣ���� ����� der�� ���Խ�Ű�� ����*/
#define CMS_DETACHED						1   /*!< */ 
#define CMS_DEFAULT							0	/*!< */


/* SignerIdentifier/OriginatorIdentifier/KeyAgreeRecipientIdentifier TYPE */
#define TYPE_OF_ISSUER_SERIAL				0	/*!< */ 
#define TYPE_OF_KEYIDENTIFIER				1	/*!< */ 
#define TYPE_OF_ORIGINATOR_PUBLIC_KEY		2	/*!< */ 
#define TYPE_OF_RECIPIENT_KEY				3	/*!< */ 

/* CertificateChoices TYPE */
#define TYPE_OF_CERTCHOICE_CERT				0	/*!< */ 
#define TYPE_OF_CERTCHOICE_EXCERT			1	/*!< */ 

/* CertificateRevocationLists TYPE */
#define TYPE_OF_CERTREVLIST_CRL				0
#define TYPE_OF_CERTREVLIST_OTHER			1

/* RecipientInfo TYPE */
#define TYPE_OF_KEY_TRANS					0
#define TYPE_OF_KEY_AGREE					1
#define TYPE_OF_KEK							2

/* CHOICE OPTIONAL flags */
#define CMS_USE_KEYID						0x1		/*!< */ 
#define CMS_USE_ORKEY						0x2		/*!< */ 
#define CMS_USE_EXCERT						0x4		/*!< */ 
#define CMS_USE_ATTRCERT					0x8		/*!< */ 

#define CMS_USE_KEYAGREE					0x10	/*!< */ 
#define CMS_USE_KEK							0x20	/*!< */ 


/*!
* \brief
* ENCAPSULATED CONTENT INFO�� ������ �����ϴ� ����ü
*/
typedef struct ENCAPSULATED_CONTENT_INFO_st {
	OBJECT_IDENTIFIER				*contentType;				/*!< Content�� Ÿ��(OID)*/
	OCTET_STRING					*eContent;					/*!< OCTET_STRING ����ü�� ������*/
} ENCAPSULATED_CONTENT_INFO;

/*!
* \brief
* SIGNER IDENTIFIER
* SignerIdentifier ::= CHOICE {
*				issuerAndSerialNumber IssuerAndSerialNumber,
*				subjectKeyIdentifier [0] SubjectKeyIdentifier
*			}
* if SignerIdentifier is issuerAndSerialNumber then version shall be 1 
*             or if SignerIdentifier is subjectKeyIdentifier then version shall be 3 
* SubjectKeyIdentifier ::= OCTET STRING
*/
typedef struct SIGNER_IDENTIFIER_st {
	int type;						/* 0 : issuerAndSerialNumber, 1 : subjectKeyIdentifier */
	ISSUER_AND_SERIAL_NUMBER	*issuerAndSerialNumber;
	OCTET_STRING 				*subjectKeyIdentifier;
} SIGNER_IDENTIFIER;

#ifdef CMS_SIGNER_INFO
#undef CMS_SIGNER_INFO
#endif

/*!
* \brief
* CMS SIGNER INFO�� ������ �����ϴ� ����ü
*/
typedef struct CMS_SIGNER_INFO_st {
	INTEGER 					*version;					/*!< version = 1 or 3*/			
	SIGNER_IDENTIFIER			*sid;						/*!< issuerAndSerialNumber OR subjectKeyIdentifier */				
	X509_ALGO_IDENTIFIER		*digestAlgorithm;			/*!< �ؽ� �˰���*/		
	X509_ATTRIBUTES				*signedAttrs;				/*!< ������ �Ӽ�����(IMPLICIT SET OF Context Specific 0 OPTIONAL)*/
	X509_ALGO_IDENTIFIER		*signatureAlgorithm;		/*!< �ؽ�-��ȣȭ �˰���*/
	OCTET_STRING				*signature;					/*!< ��ȣȭ�� �ؽ� ��*/
	X509_ATTRIBUTES				*unsignedAttrs;				/*!< �������� ���� �Ӽ�����(IMPLICIT SET OF Context Specific 1 OPTIONAL)*/	
	ASYMMETRIC_KEY				*signKey;					/*!< ���ο� ���Ǵ� Ű*/
} CMS_SIGNER_INFO;

/*!
* \brief
* CMS_SIGNER_INFO ����ü ����(SET OF)�� ������
*/
typedef STK(CMS_SIGNER_INFO) CMS_SIGNER_INFOS;


/*!
* \brief
* CMS SIGNED DATA�� ������ �����ϴ� ����ü
*/
typedef struct CMS_SIGNED_DATA_st {
	INTEGER							*version;				/*!< Version = 1*/
	X509_ALGO_IDENTIFIERS			*digestAlgorithms;		/*!< �ؽ� �˰����(SET OF) */
	ENCAPSULATED_CONTENT_INFO		*encapContentInfo;		/*!< ENCAPSULATED_CONTENT_INFO ����ü�� ������*/
	X509_CERTS						*certificates;			/*!< X509 ��������(IMPLICIT SET OF Context Specific 0 OPTIONAL)*/
	X509_CRLS						*crls;					/*!< X509 CRL��(IMPLICIT SET OF Context Specific 1 OPTIONAL)*/
	CMS_SIGNER_INFOS				*signerInfos;			/*!< CMS_SIGNER_INFOS ����ü ������ ������(SET OF)*/
	int								detached;				/*!< 0:DER�� ���ڵ��� �� ����, 1:�� �� ���� */
} CMS_SIGNED_DATA;

/*!
* \brief
* CMS_ORIGINATOR_INFO �� ������ �����ϴ� ����ü
*/
typedef struct CMS_ORIGINATOR_INFO_st {
	X509_CERTS						*certificates;			/*!< X509 ��������(IMPLICIT SET OF Context Specific 0 OPTIONAL)*/
	X509_CRLS						*crls;					/*!< X509 CRL��(IMPLICIT SET OF Context Specific 1 OPTIONAL)*/
} CMS_ORIGINATOR_INFO;

/*!
* \brief
* RECIPIENT_IDENTIFIER�� ������ �����ϴ� ����ü
*/
typedef struct RECIPIENT_IDENTIFIER_st {
	int type;						/* 0 : issuerAndSerialNumber, 1 : subjectKeyIdentifier */
	ISSUER_AND_SERIAL_NUMBER	*issuerAndSerialNumber;
	OCTET_STRING 				*subjectKeyIdentifier;
} RECIPIENT_IDENTIFIER;

/*!
* \brief
* KEY_TRANS_RECIPIENT_INFO�� ������ �����ϴ� ����ü
*/
typedef struct KEY_TRANS_RECIPIENT_INFO_st {
	INTEGER							*version;	
	RECIPIENT_IDENTIFIER			*rid;
	X509_ALGO_IDENTIFIER			*keyEncryptionAlgorithm;
	OCTET_STRING					*encryptedKey;
	ASYMMETRIC_KEY					*pubKey;					/*!< ���� �������� ???*/
} KEY_TRANS_RECIPIENT_INFO;

/*!
* \brief
* ORIGINATOR_PUBLIC_KEY�� ������ �����ϴ� ����ü
*/
typedef struct ORIGINATOR_PUBLIC_KEY_st {
	X509_ALGO_IDENTIFIER			*algorithm;
	BIT_STRING						*publicKey;
} ORIGINATOR_PUBLIC_KEY;

/*!
* \brief
* KEY_AGREE_RECIPIENT_INFO�� ������ �����ϴ� ����ü
*/
typedef struct ORIGINATOR_IDENTIFIER_ORKEY_st {
	int type;						/* 0 : issuerAndSerialNumber, 1 : subjectKeyIdentifier */
	ISSUER_AND_SERIAL_NUMBER	*issuerAndSerialNumber;
	OCTET_STRING 				*subjectKeyIdentifier;
	ORIGINATOR_PUBLIC_KEY		*originatorKey;
} ORIGINATOR_IDENTIFIER_ORKEY;

/*!
* \brief
* OTHER_KEY_ATTRIBUTE�� ������ �����ϴ� ����ü
*/
typedef struct OTHER_KEY_ATTRIBUTE_st {
	OBJECT_IDENTIFIER				*keyAttrId;
	void						*keyAttr;			/* Any defined */
} OTHER_KEY_ATTRIBUTE;

/*!
* \brief
* RECIPIENT_KEY_IDENTIFIER�� ������ �����ϴ� ����ü
*/
typedef struct RECIPIENT_KEY_IDENTIFIER_st {
	OCTET_STRING 					*subjectKeyIdentifier;
	GENERALIZED_TIME 				*date;
	OTHER_KEY_ATTRIBUTE				*other;
} RECIPIENT_KEY_IDENTIFIER;

/*!
* \brief
* KEY_AGREE_RECIPIENT_IDENTIFIER�� ������ �����ϴ� ����ü
*/
typedef struct KEY_AGREE_RECIPIENT_IDENTIFIER_st {
	int type;						/* 0 : issuerAndSerialNumber, 1 : recipientKeyIdentifier */
	ISSUER_AND_SERIAL_NUMBER	*issuerAndSerialNumber;
	RECIPIENT_KEY_IDENTIFIER	*rKeyId;
} KEY_AGREE_RECIPIENT_IDENTIFIER;

/*!
* \brief
* RECIPIENT_ENCRYPTED_KEY�� ������ �����ϴ� ����ü
*/
typedef struct RECIPIENT_ENCRYPTED_KEY_st {
	KEY_AGREE_RECIPIENT_IDENTIFIER	*rid;	
	OCTET_STRING					*encryptedKey;
} RECIPIENT_ENCRYPTED_KEY;

/*!
* \brief
* RECIPIENT_ENCRYPTED_KEY ����ü ����Ʈ
*/
typedef STK(RECIPIENT_ENCRYPTED_KEY) RECIPIENT_ENCRYPTED_KEYS;

/*!
* \brief
* KEY_AGREE_RECIPIENT_INFO�� ������ �����ϴ� ����ü
*/
typedef struct KEY_AGREE_RECIPIENT_INFO_st {
	INTEGER							*version;	
	ORIGINATOR_IDENTIFIER_ORKEY		*originator;
	/*
	UserKeyingMaterial				*ukm;
	*/
	X509_ALGO_IDENTIFIER			*keyEncryptionAlgorithm;
	RECIPIENT_ENCRYPTED_KEYS		*recipientEncryptedKeys;
} KEY_AGREE_RECIPIENT_INFO;

/*!
* \brief
* CMS RECIPIENT INFO�� ������ �����ϴ� ����ü
*/
typedef struct CMS_RECIPIENT_INFO_st {
	int type;						/* 0 : key trans, 1 : key agree  */
	KEY_TRANS_RECIPIENT_INFO	*ktri;
	KEY_AGREE_RECIPIENT_INFO 	*kari;
/****
	KEKRECIPIENT_INFO			*kekri
*****/		
} CMS_RECIPIENT_INFO;

/*!
* \brief
* CMS_RECIPIENT_INFO ����ü ����(SET OF)�� ������
*/
typedef STK(CMS_RECIPIENT_INFO) CMS_RECIPIENT_INFOS;

/*!
* \brief
* CMS_ENCRYPTED_CONTENT_INFO �� ������ �����ϴ� ����ü
*/
typedef struct CMS_ENCRYPTED_CONTENT_INFO_st {
	OBJECT_IDENTIFIER				*contentType;				
	X509_ALGO_IDENTIFIER			*contentEncryptionAlgorithm;
	OCTET_STRING					*encryptedContent;
	ISC_BLOCK_CIPHER_UNIT				*cipher;					/*!< ISC_BLOCK_CIPHER_UNIT ����ü�� ������*/
} CMS_ENCRYPTED_CONTENT_INFO;

/*!
* \brief
* CMS ENVELOPED DATA�� ������ �����ϴ� ����ü
*/
typedef struct CMS_ENVELOPED_DATA_st {
	INTEGER							*version;					/*!< Version = 0 */
	CMS_ORIGINATOR_INFO				*originatorInfo;			/*!< CMS_ORIGINATOR_INFO ����ü�� ������*/
	CMS_RECIPIENT_INFOS				*recipientInfos;			/*!< CMS_RECIPIENT_INFOS ����ü ������ ������(SET OF)*/
	CMS_ENCRYPTED_CONTENT_INFO		*encryptedContentInfo;		/*!< CMS_ENCRYPTED_CONTENT_INFO ����ü�� ������*/
	X509_ATTRIBUTES					*unprotectedAttrs;			/*!< X509_ALGO_IDENTIFIERS ����ü�� ������*/
	int								detached;					/*!< 0:DER�� ���ڵ��� �� ����, 1:�� �� ���� */
} CMS_ENVELOPED_DATA;

/*!
* \brief
* CMS DIGESTED DATA�� ������ �����ϴ� ����ü
*/
typedef struct CMS_DIGESTED_DATA_st {
	INTEGER							*version;					
	X509_ALGO_IDENTIFIER			*digestAlgorithm;			
	ENCAPSULATED_CONTENT_INFO		*encapContentInfo;			/*!< ENCAPSULATED_CONTENT_INFO ����ü�� ������*/
	OCTET_STRING					*digest;					
	int								detached;					/*!< 0:DER�� ���ڵ��� �� ����, 1:�� �� ���� */
} CMS_DIGESTED_DATA;

/*!
* \brief
* CMS ENCRYPTED DATA�� ������ �����ϴ� ����ü
*/
typedef struct CMS_ENCRYPTED_DATA_ST {
	INTEGER							*version;					
	X509_ALGO_IDENTIFIER			*digestAlgorithm;			
	CMS_ENCRYPTED_CONTENT_INFO		*encryptedContentInfo;		/*!< CMS_ENCRYPTED_CONTENT_INFO ����ü�� ������*/
	X509_ATTRIBUTES					*unprotectedAttrs;	
	int								detached;					/*!< 0:DER�� ���ڵ��� �� ����, 1:�� �� ���� */
} CMS_ENCRYPTED_DATA;

/*!
* \brief
* CMS AUTHENTICATED DATA�� ������ �����ϴ� ����ü
*/
typedef struct CMS_AUTHENTICATED_DATA_ST {
	INTEGER							*version;					
	CMS_ORIGINATOR_INFO				*originatorInfo;
	CMS_RECIPIENT_INFOS				*recipientInfos;
	X509_ALGO_IDENTIFIER			*macAlgorithm;		
	X509_ALGO_IDENTIFIER			*digestAlgorithm;		
	ENCAPSULATED_CONTENT_INFO		*encapContentInfo;
	X509_ALGO_IDENTIFIERS			*authenticatedAttributes;
	OCTET_STRING					*mac;
	X509_ALGO_IDENTIFIERS			*unauthenticatedAttributes;
	int								detached;				/*!< 0:DER�� ���ڵ��� �� ����, 1:�� �� ���� */
} CMS_AUTHENTICATED_DATA;

/*!
* \brief
* PKCS7 CONTENT INFO�� ������ �����ϴ� ����ü
*/
typedef struct CMS_CONTENT_INFO_st {
	OBJECT_IDENTIFIER					*contentType;				/*!< Content�� Ÿ��(OID)*/
	union {
		OCTET_STRING					*data;						/*!< OCTET_STRING ����ü�� ������*/
		CMS_SIGNED_DATA					*signedData;				/*!< CMS_SIGNED_DATA ����ü�� ������*/
		CMS_ENVELOPED_DATA				*envelopedData;				/*!< CMS_ENVELOPED_DATA ����ü�� ������*/
		CMS_DIGESTED_DATA				*digestedData;				/*!< CMS_ENVELOPED_DATA ����ü�� ������*/
		CMS_ENCRYPTED_DATA				*encryptedData;				/*!< CMS_ENCRYPTED_DATA ����ü�� ������*/
		CMS_AUTHENTICATED_DATA			*authenticatedData;			/*!< CMS_AUTHENTICATED_DATA ����ü�� ������*/
	} content;														/*!< Content ����ü(EXLICIT Context Specific 0 OPTIONAL)*/
} CMS_CONTENT_INFO;

/*!
* \brief
* CMS_CONTENT_INFO ����ü�� Content�� CMS DATA���� Ȯ���ϴ� ��ũ�� �Լ�
* \param a
* CMS_CONTENT_INFO ����ü�� ������
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_CMS_data(a)		(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_data)

/*!
* \brief
* CMS_CONTENT_INFO ����ü�� Content�� CMS SIGNED DATA���� Ȯ���ϴ� ��ũ�� �Լ�
* \param a
* CMS_CONTENT_INFO ����ü�� ������
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_CMS_signed(a)	(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_signedData)

/*!
* \brief
* CMS_CONTENT_INFO ����ü�� Content�� CMS ENVELOPED DATA���� Ȯ���ϴ� ��ũ�� �Լ�
* \param a
* CMS_CONTENT_INFO ����ü�� ������
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_CMS_enveloped(a)	(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_envelopedData)

/*!
* \brief
* CMS_CONTENT_INFO ����ü�� Content�� CMS DIGESTED DATA���� Ȯ���ϴ� ��ũ�� �Լ�
* \param a
* CMS_CONTENT_INFO ����ü�� ������
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_CMS_digest(a)	(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_digestData)

/*!
* \brief
* CMS_CONTENT_INFO ����ü�� Content�� CMS ENCRYPTED DATA���� Ȯ���ϴ� ��ũ�� �Լ�
* \param a
* CMS_CONTENT_INFO ����ü�� ������
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_CMS_encrypted(a)	(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_encryptedData)

/*!
* \brief
* CMS_CONTENT_INFO ����ü�� Content�� CMS AUTHENTICATED DATA���� Ȯ���ϴ� ��ũ�� �Լ�
* \param a
* CMS_CONTENT_INFO ����ü�� ������
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_CMS_Authenticated(a)	\
	(index_from_OBJECT_IDENTIFIER((a)->contentType) == id-smime-ct-authData)

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* ENCAPSULATED_CONTENT_INFO ����ü�� �ʱ�ȭ �Լ�
* \returns
* ENCAPSULATED_CONTENT_INFO ����ü ������
*/
ISC_API ENCAPSULATED_CONTENT_INFO *new_ENCAPSULATED_CONTENT_INFO(void);

/*!
* \brief
* ENCAPSULATED_CONTENT_INFO ����ü�� �޸� �Ҵ� ����
* \param signerInfo
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_ENCAPSULATED_CONTENT_INFO(ENCAPSULATED_CONTENT_INFO *encapsulatedContentInfo);

/*!
* \brief
* CMS_SIGNER_INFO ����ü�� �ʱ�ȭ �Լ�
* \returns
* CMS_SIGNER_INFO ����ü ������
*/
ISC_API CMS_SIGNER_INFO *new_CMS_SIGNER_INFO(void);

/*!
* \brief
* CMS_SIGNER_INFO ����ü�� �޸� �Ҵ� ����
* \param signerInfo
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_CMS_SIGNER_INFO(CMS_SIGNER_INFO *signerInfo);

/*!
* \brief
* CMS_SIGNER_INFOS ����ü�� �ʱ�ȭ �Լ�
* \returns
* CMS_SIGNER_INFOS ����ü ������
*/
ISC_API CMS_SIGNER_INFOS *new_CMS_SIGNER_INFOS(void);
/*!
* \brief
* CMS_SIGNER_INFOS ����ü�� �޸� �Ҵ� ����
* \param signerInfos
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_CMS_SIGNER_INFOS(CMS_SIGNER_INFOS *signerInfos);


/*!
* \brief
* CMS_ORIGINATOR_INFO ����ü�� �ʱ�ȭ �Լ�
* \returns
* CMS_ORIGINATOR_INFO ����ü ������
*/
ISC_API CMS_ORIGINATOR_INFO *new_CMS_ORIGINATOR_INFO(void);

/*!
* \brief
* CMS_ORIGINATOR_INFO ����ü�� �޸� �Ҵ� ����
* \param cmsOriginatorInfo
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_CMS_ORIGINATOR_INFO(CMS_ORIGINATOR_INFO *cmsOriginatorInfo);

/*!
* \brief
* CMS_SIGNED_DATA ����ü�� �ʱ�ȭ �Լ�
* \returns
* CMS_SIGNED_DATA ����ü ������
*/
ISC_API CMS_SIGNED_DATA *new_CMS_SIGNED_DATA(void);

/*!
* \brief
* CMS_SIGNED_DATA ����ü�� �޸� �Ҵ� ����
* \param cmsSignedData
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_CMS_SIGNED_DATA(CMS_SIGNED_DATA *cmsSignedData);

/*!
* \brief
* RECIPIENT_IDENTIFIER ����ü�� �ʱ�ȭ �Լ�
* \returns
* RECIPIENT_IDENTIFIER ����ü ������
*/
ISC_API RECIPIENT_IDENTIFIER *new_RECIPIENT_IDENTIFIER(void);

/*!
* \brief
* RECIPIENT_IDENTIFIER ����ü�� �޸� �Ҵ� ����
* \param recipientIdentifier
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_RECIPIENT_IDENTIFIER(RECIPIENT_IDENTIFIER *recipientIdentifier);

/*!
* \brief
* CMS_RECIPIENT_INFO ����ü�� �ʱ�ȭ �Լ�
* \returns
* CMS_RECIPIENT_INFO ����ü ������
*/
ISC_API CMS_RECIPIENT_INFO *new_CMS_RECIPIENT_INFO(void);

/*!
* \brief
* CMS_RECIPIENT_INFO ����ü�� �޸� �Ҵ� ����
* \param cri
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_CMS_RECIPIENT_INFO(CMS_RECIPIENT_INFO *cri);

/*!
* \brief
* CMS_RECIPIENT_INFOS ����ü�� �ʱ�ȭ �Լ�
* \returns
* CMS_RECIPIENT_INFOS ����ü ������
*/
ISC_API CMS_RECIPIENT_INFOS *new_CMS_RECIPIENT_INFOS(void);

/*!
* \brief
* CMS_RECIPIENT_INFOS ����ü�� �޸� �Ҵ� ����
* \param recipientInfos
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_CMS_RECIPIENT_INFOS(CMS_RECIPIENT_INFOS *recipientInfos);


KEY_TRANS_RECIPIENT_INFO *new_KEY_TRANS_RECIPIENT_INFO(void);
void free_KEY_TRANS_RECIPIENT_INFO(KEY_TRANS_RECIPIENT_INFO *ktri) ;

/*!
* \brief
* CMS_ENCRYPTED_CONTENT_INFO ����ü�� �ʱ�ȭ �Լ�
* \returns
* CMS_ENCRYPTED_CONTENT_INFO ����ü ������
*/
ISC_API CMS_ENCRYPTED_CONTENT_INFO *new_CMS_ENCRYPTED_CONTENT_INFO(void);

/*!
* \brief
* CMS_ENCRYPTED_CONTENT_INFO ����ü�� �޸� �Ҵ� ����
* \param encryptedContentInfo
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_CMS_ENCRYPTED_CONTENT_INFO(CMS_ENCRYPTED_CONTENT_INFO *encryptedContentInfo);


/*!
* \brief
* CMS_ENVELOPED_DATA ����ü�� �ʱ�ȭ �Լ�
* \returns
* CMS_ENVELOPED_DATA ����ü ������
*/
ISC_API CMS_ENVELOPED_DATA *new_CMS_ENVELOPED_DATA(void);

/*!
* \brief
* CMS_ENVELOPED_DATA ����ü�� �޸� �Ҵ� ����
* \param cmsEnvelopedData
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_CMS_ENVELOPED_DATA(CMS_ENVELOPED_DATA *cmsEnvelopedData);

/*!
* \brief
* CMS_DIGESTED_DATA ����ü�� �ʱ�ȭ �Լ�
* \returns
* CMS_DIGESTED_DATA ����ü ������
*/
ISC_API CMS_DIGESTED_DATA *new_CMS_DIGESTED_DATA(void);

/*!
* \brief
* CMS_DIGESTED_DATA ����ü�� �޸� �Ҵ� ����
* \param cmsDigestedData
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_CMS_DIGESTED_DATA(CMS_DIGESTED_DATA *cmsDigestedData);

/*!
* \brief
* CMS_ENCRYPTED_DATA ����ü�� �ʱ�ȭ �Լ�
* \returns
* CMS_ENCRYPTED_DATA ����ü ������
*/
ISC_API CMS_ENCRYPTED_DATA *new_CMS_ENCRYPTED_DATA(void);

/*!
* \brief
* CMS_ENCRYPTED_DATA ����ü�� �޸� �Ҵ� ����
* \param cmsEncryptedData
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_CMS_ENCRYPTED_DATA(CMS_ENCRYPTED_DATA *cmsEncryptedData);

/*!
* \brief
* CMS_AUTHENTICATED_DATA ����ü�� �ʱ�ȭ �Լ�
* \returns
* CMS_AUTHENTICATED_DATA ����ü ������
*/
ISC_API CMS_AUTHENTICATED_DATA *new_CMS_AUTHENTICATED_DATA(void);

/*!
* \brief
* CMS_AUTHENTICATED_DATA ����ü�� �޸� �Ҵ� ����
* \param cmsAuthenticatedData
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_CMS_AUTHENTICATED_DATA(CMS_AUTHENTICATED_DATA *cmsAuthenticatedData);


/*!
* \brief
* CMS_CONTENT_INFO ����ü�� �ʱ�ȭ �Լ�
* \returns
* CMS_CONTENT_INFO ����ü ������
*/
ISC_API CMS_CONTENT_INFO *new_CMS_CONTENT_INFO(void);

/*!
* \brief
* CMS_CONTENT_INFO ����ü�� �޸� �Ҵ� ����
* \param cmsContentInfo
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_CMS_CONTENT_INFO(CMS_CONTENT_INFO *cmsContentInfo);

/*!
* \brief
* CMS_CONTENT_INFO�� ���Ǵ� ISC_BLOCK_CIPHER_UNIT�� ����
* (OID_pkcs7_envelopedData/OID_pkcs7_encryptedData)
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param cipher
* �����Ϸ��� ISC_BLOCK_CIPHER_UNIT ����ü ������ \n
* init �� ISC_BLOCK_CIPHER_UNIT�� ���޵�(�����Ͱ� ���޵ǹǷ� ISC_MEM_FREE ����)
* \return
* -# ISC_SUCCESS : ����
* -# L_PKCS7^ISC_ERR_NULL_INPUT : cipher�� ���� ���
* -# ISC_FAIL : ����
*/
/*ISC_API ISC_STATUS set_CMS_Cipher(CMS_CONTENT_INFO *cci, ISC_BLOCK_CIPHER_UNIT* cipher);*/
ISC_API ISC_STATUS set_CMS_Cipher(CMS_CONTENT_INFO *cci, int cipherID, const uint8 *key, const uint8 *iv, int enc);


ISC_API ISC_STATUS init_CMS_Encrypt_RecipientInfo(CMS_RECIPIENT_INFOS *ris, X509_ALGO_IDENTIFIER *identifier, 
												 uint8 *secretKey, uint8 *iv, int pk_encode);

ISC_API ISC_STATUS encrypt_CMS_RecipientInfo(CMS_CONTENT_INFO *cci, int cipherID, uint8 *key, uint8 *iv) ;

/*!
* \brief
* CMS_CONTENT_INFO �� ��ȣȭ ��� �ʱ�ȭ\n
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData)
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param type_oid
* ��ȣȭ �Ǵ� Ÿ��
* \param identifier
* ��ȣȭ �˰����� ������ Identifier
* \param detached
* detached�� 0�ϰ�� ��ȣ���� p7�� ���Ե�\n
* detached�� 1�ϰ�� ��ȣ���� �����Ͱ� p7�� �ܺο� ������ ����
* \param secretKey
* ��ȣȭ�� ���� ���Ű(Password)
* \param iv
* ��ȣȭ�� ���� �ʱ����(IV)
* \param pk_encode
* ��ȣȭ�� ���� encode �� ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS init_CMS_Encrypt(CMS_CONTENT_INFO *cci, int type_oid, X509_ALGO_IDENTIFIER *identifier, int detached, uint8 *secretKey, uint8 *iv, int pk_encode);

/*!
* \brief
* CMS_CONTENT_INFO �� ��ȣȭ ����(Update)
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData)
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param in
* �ԷµǴ� ������ ����
* \param inLen
* �ԷµǴ� ������ ���� ���� ������
* \param out
* ��µǴ� ��ȣ���� ����
* \param outLen
* ��µǴ� ��ȣ���� ���� ���� ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS update_CMS_encrypt(CMS_CONTENT_INFO *cci, uint8* in, int inLen, uint8 *out, int *outLen);

/*!
* \brief
* CMS_CONTENT_INFO�� ��ȣȭ ���� ���� ����
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData)
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param out
* ��µǴ� ��ȣ���� ����
* \param outLen
* ������ ���� ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS final_CMS_Encrypt(CMS_CONTENT_INFO *cci, uint8 *out, int *outLen);


/*!
* \brief
* CMS_CONTENT_INFO ����ü�� type���� ����
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param type
* cms type oid index
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS new_CMS_Content(CMS_CONTENT_INFO *cci, int type);

/*!
* \brief
* CMS_CONTENT_INFO ����ü�� type�� ����
* \param cms
* CMS_CONTENT_INFO ����ü ������
* \param type
* cms type oid index
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_CMS_Type(CMS_CONTENT_INFO *cms, int type);

/*!
* \brief
* CMS_CONTENT_INFO ����ü�ǹ���������������
* \param cci
* CMS_CONTENT_INFO ����ü
* \param version
* �����ҹ���
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_CMS_version(CMS_CONTENT_INFO *cci, uint32 version);

/*!
* \brief
* ENCRYPTED_CONTENT_INFO�� ��ȣȭ�� ����� ������(encData�� NULL�� ��쿡 ��ȣ���� �ܺο� �ִ� �����)
* \param eci
* ENCRYPTED_CONTENT_INFO ����ü ������
* \param type_oid
* OID �ε��� ��
* \param algorithm
* �˰��� �ĺ���
* \param encData
* ��ȣȭ�� ������(NULL�̸� Detached Type)
* \param encDataLen
* ��ȣȭ�� �������� ����(0�̸� Detached Type)
* \return
* -# ISC_SUCCESS : ����
* -# L_PKCS7^ISC_ERR_NULL_INPUT : �˰���� ENCRYPTED_CONTENT_INFO ����ü �����Ͱ� ���� ���
* -# L_PKCS7^ISC_ERR_INVALID_INPUT : type_oid��	undefined type ��
*/
ISC_API ISC_STATUS set_CMS_ENCRYPTED_CONTENT_INFO(CMS_ENCRYPTED_CONTENT_INFO *eci, int type_oid, 
					X509_ALGO_IDENTIFIER *algorithm, uint8* encData, int encDataLen);

/*!
* \brief
* CMS_SIGNER_INFO�� ������ �������� ������, ����Ű, �ؽþ˰��� �������� ����
* \param signerInfo
* CMS_SIGNER_INFO ����ü ������
* \param x509
* ������
* \param flags
* SignerIdentifier�� Ÿ�� (CMS_SIGNERINFO_ISSUER_SERIAL, CMS_SIGNERINFO_KEYIDENTIFIER)
* \param pkey
* ����Ű
* \param digestOID
* �ؽ� �˰��� id
* \param pk_encode
* ��ȣ �˰��� id
* \param alg_param
* ��ȣ �˰��� �Ķ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_CMS_SIGNER_INFO(CMS_SIGNER_INFO *signerInfo, X509_CERT *x509, uint32 flags,
											ASYMMETRIC_KEY *pkey, int digestOID, int pk_encode, void *alg_param);

/*!
* \brief
* CMS_RECIPIENT_INFO�� �������� �������κ��� ����
* \param cri
* CMS_RECIPIENT_INFO ����ü ������
* \param x509
* �����Ϸ��� X509_CERT ����ü ������
* \param pk_encode
* ��ȣ �˰��� id
* \param alg_param
* ��ȣ �˰��� �Ķ����
* \param flags
* OPTIONAL flags
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_CMS_RECIPIENT_INFO(CMS_RECIPIENT_INFO *cri, X509_CERT *x509, int pk_encode, void *alg_param, uint32 flags);

/*!
* \brief
* CMS_CONTENT_INFO �� content�� ����
* \param cci
* ENCAPSULATED_CONTENT_INFO ����ü ������
* \param eci
* �����Ϸ��� CMS_CONTENT_INFO ����ü ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_ENCAPSULATED_CONTENT_INFO(CMS_CONTENT_INFO *cci, ENCAPSULATED_CONTENT_INFO *eci);

/*!
* \brief
* CMS_CONTENT_INFO �� content�� ����
* \param cci
* \param data
* ���� ������
* \param dataLen 
* ������������ ����
* \param detached
* detached�� 0�ϰ�� ��ȣ���� p7�� ���Ե�\n
* detached�� 1�ϰ�� ��ȣ���� �����Ͱ� p7�� �ܺο� ������ ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_Content_Info(CMS_CONTENT_INFO *cci, uint8* data, int dataLen, int detached);

/*!
* \brief
* CMS_CONTENT_INFO �� authenticated Data�� macAlgorithm�� ����
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param digestOID
* �����Ϸ��� CMS_CONTENT_INFO ����ü ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API	ISC_STATUS set_CMS_macAlgorithm(CMS_CONTENT_INFO *cci, int digestOID);

/*!
* \brief
* CMS_CONTENT_INFO �� authenticated Data�� digestAlgorithm�� ����
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param digestOID
* �����Ϸ��� CMS_CONTENT_INFO ����ü ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API	ISC_STATUS set_CMS_digestAlgorithm(CMS_CONTENT_INFO *cci, int digestOID);

/*!
* \brief
* CMS_CONTENT_INFO �� authenticated Data�� mac�� ����
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param digest
* �����Ϸ��� �޽��� �����ڵ�
* \param digestLen
* �����Ϸ��� �޽��� �����ڵ� ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API	ISC_STATUS set_CMS_mac(CMS_CONTENT_INFO *cci, uint8 *digest, int digestLen);

/*!
* \brief
* CMS_CONTENT_INFO�� �����ڸ� �߰� \n
* (OID_pkcs7_signedData)
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param x509
* ������
* \param pkey
* ����Ű
* \param flag
* �ɼǼ����� ���� flag
* \param flag
* �ؽ� �˰��� id
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API CMS_SIGNER_INFO *add_CMS_Signature(CMS_CONTENT_INFO *cci, X509_CERT *x509, ASYMMETRIC_KEY *pkey, 
										uint32 flag, int digestOID, int pk_encode, void *alg_param);

/*!
* \brief
* CMS_SIGNER_INFO�� Signed Attribute�� �߰� \n
* \param csi
* CMS_SIGNER_INFO ����ü ������
* \param oid
* attribute�� OID
* \param atrtype
* ����Ǵ� attribute ��ü�� asn1 type
* \param value
* attribute�� ������
* \param valueLen
* �������� ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_CMS_Signed_Attribute(CMS_SIGNER_INFO *csi, int oid, int atrtype, uint8 *value, int valueLen);

/*!
* \brief
* CMS_SIGNER_INFO�� Unsigend Attribute�� �߰� \n
* \param csi
* CMS_SIGNER_INFO ����ü ������
* \param oid
* attribute�� OID
* \param atrtype
* ����Ǵ� attribute ��ü�� asn1 type
* \param value
* attribute�� ������
* \param valueLen
* �������� ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_CMS_Unsigned_Attribute(CMS_SIGNER_INFO *csi, int oid, int atrtype, uint8 *value, int valueLen);

/*!
* \brief
* CMS_CONTENT_INFO�� ���� �������� �߰� \n
* (OID_pkcs7_signedData)
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param x509
* ���� ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_CMS_Certificate(CMS_CONTENT_INFO *cci, X509_CERT *x509);

/*!
* \brief
* CMS_CONTENT_INFO�� ���� ����������� �߰� \n
* (OID_pkcs7_signedData)
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param crl
* ���� ������ �����
* \return
* -# ISC_SUCCESS : ����
* -# L_CMS^F_ADD_CMS_CERTIFICATE^ISC_ERR_NOT_SUPPORTED : �������� �ʴ� Ÿ��
* -# L_CMS^LOCATION^F_ADD_CMS_CERTIFICATE^ERR_STK_ERROR : �����߰��� ����
*/
ISC_API ISC_STATUS add_CMS_CRL(CMS_CONTENT_INFO *cci, X509_CRL *crl);

/*!
* \brief
* CMS_CONTENT_INFO�� ���� �۽��� �������� �߰� \n
* (OID_pkcs7_envelopedData. OID_id_smime_ct_authData)
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param x509
* ���� ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_CMS_Originator_Certificate(CMS_CONTENT_INFO *cci, X509_CERT *x509);

/*!
* \brief
* CMS_CONTENT_INFO�� ���� �۽��� ������ ����� �߰� \n
* (OID_pkcs7_envelopedData. OID_id_smime_ct_authData)
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param crl
* ���� ������ �����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_CMS_Originator_CRL(CMS_CONTENT_INFO *cci, X509_CRL *crl);

/*!
* \brief
* CMS_CONTENT_INFO�� �������� �ش��ϴ� �����ڸ� �߰� \n
* (OID_pkcs7_envelopedData)
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param x509
* ������
* \param pk_encode
* ��ȣ �˰��� id
* \param alg_param
* ��ȣ �Ķ�����
* \param flags
* OPTIONAL flags
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_CMS_Recipient(CMS_CONTENT_INFO *cci, X509_CERT *x509, int pk_encode, void *alg_param, uint32 flags);

/*!
* \brief
* CMS_CONTENT_INFO�� �����ڸ� �߰� \n
* (OID_pkcs7_envelopedData)
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param cri
* ������ (�������� ����Ͽ� ������ �����Ǿ�� ��)
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_CMS_RECIPIENT_INFO(CMS_CONTENT_INFO *cci, CMS_RECIPIENT_INFO *cri);

/*!
* \brief
* CMS_CONTENT_INFO�� Unprotected Attribute�� �߰� \n
* \param csi
* CMS_CONTENT_INFO ����ü ������
* \param oid
* attribute�� OID
* \param atrtype
* ����Ǵ� attribute ��ü�� asn1 type
* \param value
* attribute�� ������
* \param valueLen
* �������� ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_CMS_Unprotected_Attribute(CMS_CONTENT_INFO *cci, int oid, int atrtype, uint8 *value, int valueLen);

/*!
* \brief
* CMS_CONTENT_INFO�� Authenticated Attribute�� �߰� \n
* \param csi
* CMS_CONTENT_INFO ����ü ������
* \param oid
* attribute�� OID
* \param atrtype
* ����Ǵ� attribute ��ü�� asn1 type
* \param value
* attribute�� ������
* \param valueLen
* �������� ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_CMS_Authenticated_Attribute(CMS_CONTENT_INFO *cci, int oid, int atrtype, uint8 *value, int valueLen) ;

/*!
* \brief
* CMS_CONTENT_INFO�� unauthenticated Attribute�� �߰� \n
* \param csi
* CMS_CONTENT_INFO ����ü ������
* \param oid
* attribute�� OID
* \param atrtype
* ����Ǵ� attribute ��ü�� asn1 type
* \param value
* attribute�� ������
* \param valueLen
* �������� ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_CMS_Unauthenticated_Attribute(CMS_CONTENT_INFO *cci, int oid, int atrtype, uint8 *value, int valueLen) ;

/*!
* \brief
* CMS_CONTENT_INFO�� ���� ����
* (OID_pkcs7_signedData)
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS sign_CMS(CMS_CONTENT_INFO *cci);

/*!
* \brief
* CMS_CONTENT_INFO�� ���� ����
* (OID_pkcs7_signedData)
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param x509
* ������ ����Ű�� ���Ե� ������
* \param data
* �����Ϸ��� ������ (cci�� �ȿ� ���� �����͸� �����ϰ� ������ NULL)
* \param dataLen 
* �������� ����(cci�� �ȿ� ���� �����͸� �����ϰ� ������ 0)
* \return
* -# ISC_SUCCESS : ���� ��� 
* -# L_CMS^F_CMS_VERIFY^ISC_ERR_NULL_INPUT : data�� dataLen�� NULL�ΰ��
* -# L_CMS^F_CMS_VERIFY^ISC_ERR_INVALID_INPUT : �ش��ϴ� �������� ���ų�, �������� �ִµ� Ű�� ���ų� signer info�� ���ų�, digestAlg, encAlg�� ���� ���
* -# L_CMS^F_CMS_VERIFY^ISC_ERR_VERIFY_FAILURE : �������� �ƿ� ���� ���
* -# ISC_FAIL : ��������� �����߰ų� �� �̿��� ����
*/
ISC_API ISC_STATUS verify_CMS(CMS_CONTENT_INFO *cci, X509_CERT *x509, uint8 *data, int dataLen);

/*!
* \brief
* CMS_CONTENT_INFO�� ��ȣȭ ���� (Detached mode�� ���� �Ұ�)
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData)
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param type_oid
* ��ȣȭ�Ǵ� Content Type
* \param identifier
* ��ȣȭ �˰����� Identifier
* \param in
* �Է�
* \param inLen
* �Է��� ����
* \param pk_encode
* ��ȣȭ�� ���� encode �� ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS encrypt_CMS(CMS_CONTENT_INFO *cci, int type_oid, X509_ALGO_IDENTIFIER *identifier,uint8 *in, int inLen, int pk_encode);

/*!
* \brief
* CMS_CONTENT_INFO�� ��ȣȭ ���� (Detached mode�� ���� �Ұ�)
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData/OID_pkcs7_signedAndEnvelopedData)
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param type_oid
* ��ȣȭ�Ǵ� Content Type
* \param identifier
* ��ȣȭ �˰����� Identifier
* \param in
* �Է�
* \param inLen
* �Է��� ����
* \param secretKey
* ��ȣȭ�� ���� ���Ű(Password)
* \param iv
* ��ȣȭ�� ���� �ʱ����(IV)
* \param pk_encode
* ��ȣȭ�� ���� encode �� ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS encrypt_CMS_userKEY(CMS_CONTENT_INFO *cci,  int type_oid, X509_ALGO_IDENTIFIER *identifier,uint8 *in, int inLen, uint8 *secretKey, uint8 *iv, int pk_encode);


/*!
* \brief
* CMS_CONTENT_INFO - Enveloped Data�� �������� Content-Encryption Key�� ��ȣȭ
* (OID_pkcs7_envelopedData)
* \param p7
* CMS_CONTENT_INFO ����ü ������
* \param cert
* �����ڿ� �ش��ϴ� ������
* \param priKey
* ��ȣȭ�� ���� ���Ű
* \param cek
* ��ȭȭ�� cek
* \param cekLen
* ��ȣȭ�� Ű�� ���� ������ ����
* \param pk_decode
* ��ȣȭ�� ����� decoding �� ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
* -# ISC_Init_RSAES()�� ���� �ڵ�
* -# ISC_Decrypt_RSAES()�� ���� �ڵ�
*/
ISC_API ISC_STATUS decrypt_content_encryption_key(CMS_CONTENT_INFO *cci, X509_CERT *cert, ASYMMETRIC_KEY* priKey, uint8* cek, int *cekLen, int pk_decode);

/*!
* \brief
* CMS_CONTENT_INFO�� ��ȣȭ ���� (Detached mode�� ���� �Ұ�)
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData)
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param key
* ��ȣȭ�� Ű
* \param iv
* initial vector
* \param out
* ��ȣȭ�� ��
* \param outLen
* ������ ���� ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS decrypt_CMS(CMS_CONTENT_INFO *cci, uint8 *key, uint8 *iv, uint8 *out, int *outLen);

/*!
* \brief
* CMS_CONTENT_INFO�� digestedData ����
* (OID_pkcs7_digestedData)
* \param cci
* CMS_CONTENT_INFO ����ü ������
* \param digestID
* ��������Ʈ �˰���
* \param data
* �Է�
* \param dataLen
* �Է��� ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS digest_CMS(CMS_CONTENT_INFO *cci, int digestID, uint8 *data, int dataLen);

/*!
* \brief
* ENCAPSULATED_CONTENT_INFO ����ü�� Sequence�� Encode �Լ�
* \param eci
* ENCAPSULATED_CONTENT_INFO ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ENCAPSULATED_CONTENT_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_ENCAPSULATED_CONTENT_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# CMS_ISSUER_AND_SERIAL_NUMBER_to_Seq()�� ���� �ڵ�\n
* -# X509_ALGO_IDENTIFIER_to_Seq()�� ���� �ڵ�\n

*/
ISC_API ISC_STATUS ENCAPSULATED_CONTENT_INFO_to_Seq(ENCAPSULATED_CONTENT_INFO *eci, SEQUENCE **seq);

/*!
* \brief
* Sequence�� ENCAPSULATED_CONTENT_INFO ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param eci
* ENCAPSULATED_CONTENT_INFO ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_ENCAPSULATED_CONTENT_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_ENCAPSULATED_CONTENT_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_ENCAPSULATED_CONTENT_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_CMS_ISSUER_AND_SERIAL_NUMBER()�� ���� �ڵ�\n
* -# Seq_to_X509_ALGO_IDENTIFIER()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_ENCAPSULATED_CONTENT_INFO(SEQUENCE *seq, ENCAPSULATED_CONTENT_INFO **eci);

/*!
* \brief
* CMS_SIGNER_INFO ����ü�� Sequence�� Encode �Լ�
* \param signerInfo
* CMS_SIGNER_INFO ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_CMS_SIGNER_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_SIGNER_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# CMS_ISSUER_AND_SERIAL_NUMBER_to_Seq()�� ���� �ڵ�\n
* -# X509_ALGO_IDENTIFIER_to_Seq()�� ���� �ڵ�\n
* -# X509_ATTRIBUTES_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS CMS_SIGNER_INFO_to_Seq(CMS_SIGNER_INFO *signerInfo, SEQUENCE **seq);

/*!
* \brief
* Sequence�� CMS_SIGNER_INFO ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param signerInfo
* CMS_SIGNER_INFO ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_CMS_SIGNER_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_SIGNER_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_SIGNER_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_CMS_ISSUER_AND_SERIAL_NUMBER()�� ���� �ڵ�\n
* -# Seq_to_X509_ALGO_IDENTIFIER()�� ���� �ڵ�\n
* -# Seq_to_X509_ATTRIBUTES()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_CMS_SIGNER_INFO(SEQUENCE *seq, CMS_SIGNER_INFO **signerInfo);

/*!
* \brief
* CMS_SIGNER_INFOS ����ü�� Sequence�� Encode �Լ�
* \param signerInfos
* CMS_SIGNER_INFOS ����ü
* \param setOf
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_CMS_SIGNER_INFOS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_SIGNER_INFOS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# CMS_SIGNER_INFO_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS CMS_SIGNER_INFOS_to_Seq(CMS_SIGNER_INFOS *signerInfos, SET_OF **setOf);

/*!
* \brief
* Sequence�� CMS_SIGNER_INFOS ����ü�� Decode �Լ�
* \param setOf
* Decoding Sequence ����ü
* \param signerInfos
* CMS_SIGNER_INFOS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_CMS_SIGNER_INFOS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_SIGNER_INFOS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_SIGNER_INFOS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_CMS_SIGNER_INFO()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_CMS_SIGNER_INFOS(SET_OF *setOf, CMS_SIGNER_INFOS **signerInfos);

/*!
* \brief
* CMS_SIGNED_DATA ����ü�� Sequence�� Encode �Լ�
* \param csd
* CMS_SIGNED_DATA ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_CMS_SIGNED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_SIGNED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_ALGO_IDENTIFIERS_to_Seq()�� ���� �ڵ�\n
* -# CMS_CONTENT_INFO_to_Seq()�� ���� �ڵ�\n
* -# X509_CERTIFICATES_to_Seq()�� ���� �ڵ�\n
* -# X509_CRLS_to_Seq()�� ���� �ڵ�\n
* -# CMS_SIGNER_INFOS_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS CMS_SIGNED_DATA_to_Seq(CMS_SIGNED_DATA *csd, SEQUENCE **seq);

/*!
* \brief
* Sequence�� CMS_SIGNED_DATA ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param csd
* CMS_SIGNED_DATA ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_CMS_SIGNED_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_SIGNED_DATA^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_SIGNED_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_ALGO_IDENTIFIERS()�� ���� �ڵ�\n
* -# Seq_to_CMS_CONTENT_INFO()�� ���� �ڵ�\n
* -# Seq_to_X509_CERTIFICATES()�� ���� �ڵ�\n
* -# Seq_to_X509_CRLS()�� ���� �ڵ�\n
* -# Seq_to_CMS_SIGNER_INFOS()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_CMS_SIGNED_DATA(SEQUENCE *seq, CMS_SIGNED_DATA **csd);


/*!
* \brief
* CMS_ORIGINATOR_INFO ����ü�� Sequence�� Encode �Լ�
* \param csd
* CMS_ORIGINATOR_INFO ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_CMS_ORIGINATOR_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_ORIGINATOR_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_CERTIFICATES_to_Seq()�� ���� �ڵ�\n
* -# X509_CRLS_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS CMS_ORIGINATOR_INFO_to_Seq(CMS_ORIGINATOR_INFO *coi, SEQUENCE **seq);

/*!
* \brief
* Sequence�� CMS_ORIGINATOR_INFO ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param csd
* CMS_ORIGINATOR_INFO ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_CMS_ORIGINATOR_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_ORIGINATOR_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_ORIGINATOR_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_CERTIFICATES()�� ���� �ڵ�\n
* -# Seq_to_X509_CRLS()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_CMS_ORIGINATOR_INFO(SEQUENCE *seq, CMS_ORIGINATOR_INFO **csd);

/*!
* \brief
* CMS_RECIPIENT_INFO ����ü�� Sequence�� Encode �Լ�
* \param cri
* CMS_RECIPIENT_INFO ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_CMS_RECIPIENT_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_RECIPIENT_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# CMS_ISSUER_AND_SERIAL_NUMBER_to_Seq()�� ���� �ڵ�\n
* -# X509_ALGO_IDENTIFIER_to_Seq()�� ���� �ڵ�\n

*/
ISC_API ISC_STATUS CMS_RECIPIENT_INFO_to_Seq(CMS_RECIPIENT_INFO *cri, SEQUENCE **seq);

/*!
* \brief
* Sequence�� CMS_RECIPIENT_INFO ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param cri
* CMS_RECIPIENT_INFO ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_CMS_RECIPIENT_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_RECIPIENT_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_RECIPIENT_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_CMS_ISSUER_AND_SERIAL_NUMBER()�� ���� �ڵ�\n
* -# Seq_to_X509_ALGO_IDENTIFIER()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_CMS_RECIPIENT_INFO(SEQUENCE *seq, CMS_RECIPIENT_INFO **cri);

/*!
* \brief
* CMS_RECIPIENT_INFOS ����ü�� Sequence�� Encode �Լ�
* \param recipientInfos
* CMS_RECIPIENT_INFOS ����ü
* \param setOf
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_CMS_RECIPIENT_INFOS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_RECIPIENT_INFOS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# CMS_RECIPIENT_INFO_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS CMS_RECIPIENT_INFOS_to_Seq(CMS_RECIPIENT_INFOS *recipientInfos, SET_OF **setOf);

/*!
* \brief
* Sequence�� CMS_RECIPIENT_INFOS ����ü�� Decode �Լ�
* \param setOf
* Decoding Sequence ����ü
* \param cris
* CMS_RECIPIENT_INFOS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_CMS_RECIPIENT_INFOS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_RECIPIENT_INFOS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_CMS_RECIPIENT_INFO()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_CMS_RECIPIENT_INFOS(SET_OF *setOf, CMS_RECIPIENT_INFOS **cris);

/*!
* \brief
* Sequence�� CMS_ENCRYPTED_CONTENT_INFO ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param ceci
* CMS_ENCRYPTED_CONTENT_INFO ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_CMS_ENCRYPTED_CONTENT_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_ENCRYPTED_CONTENT_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_ENCRYPTED_CONTENT_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_ALGO_IDENTIFIER()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_CMS_ENCRYPTED_CONTENT_INFO(SEQUENCE *seq, CMS_ENCRYPTED_CONTENT_INFO **ceci);

/*!
* \brief
* CMS_ENVELOPED_DATA ����ü�� Sequence�� Encode �Լ�
* \param p7EnvelopedData
* CMS_ENVELOPED_DATA ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_CMS_ENVELOPED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_ENVELOPED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# CMS_RECIPIENT_INFOS_to_Seq()�� ���� �ڵ�\n
* -# CMS_ENCRYPTED_CONTENT_INFO_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS CMS_ENVELOPED_DATA_to_Seq(CMS_ENVELOPED_DATA *p7EnvelopedData, SEQUENCE **seq);

/*!
* \brief
* CMS_ENCRYPTED_DATA ����ü�� Sequence�� Encode �Լ�
* \param ced
* CMS_ENCRYPTED_DATA ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_CMS_ENCRYPTED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_ENCRYPTED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# CMS_ENCRYPTED_CONTENT_INFO_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS CMS_ENCRYPTED_DATA_to_Seq(CMS_ENCRYPTED_DATA *ced, SEQUENCE **seq);

/*!
* \brief
* Sequence�� CMS_ENCRYPTED_DATA ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param ced
* CMS_ENCRYPTED_DATA ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_CMS_ENCRYPTED_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_ENCRYPTED_DATA^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_ENCRYPTED_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_CMS_ENCRYPTED_CONTENT_INFO()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_CMS_ENCRYPTED_DATA(SEQUENCE *seq, CMS_ENCRYPTED_DATA **ced);

/*!
* \brief
* CMS_ENVELOPED_DATA ����ü�� Sequence�� Encode �Լ�
* \param ced
* CMS_ENVELOPED_DATA ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_CMS_ENVELOPED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_ENVELOPED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# CMS_RECIPIENT_INFOS_to_Seq()�� ���� �ڵ�\n
* -# CMS_ENCRYPTED_CONTENT_INFO_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS CMS_ENVELOPED_DATA_to_Seq(CMS_ENVELOPED_DATA *ced, SEQUENCE **seq);

/*!
* \brief
* Sequence�� CMS_ENVELOPED_DATA ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param ced
* CMS_ENVELOPED_DATA ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_CMS_ENVELOPED_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_ENVELOPED_DATA^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_ENVELOPED_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_CMS_RECIPIENT_INFOS()�� ���� �ڵ�\n
* -# Seq_to_CMS_ENCRYPTED_CONTENT_INFO()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_CMS_ENVELOPED_DATA(SEQUENCE *seq, CMS_ENVELOPED_DATA **ced);

/*!
* \brief
* CMS_DIGESTED_DATA ����ü�� Sequence�� Encode �Լ�
* \param cdd
* CMS_DIGESTED_DATA ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_CMS_DIGESTED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_DIGESTED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_ALGO_IDENTIFIER_to_Seq()�� ���� �ڵ�\n
* -# CMS_CONTENT_INFO_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS CMS_DIGESTED_DATA_to_Seq(CMS_DIGESTED_DATA *cdd, SEQUENCE **seq);

/*!
* \brief
* Sequence�� CMS_DIGESTED_DATA ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param cdd
* CMS_DIGESTED_DATA ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_CMS_DIGESTED_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_DIGESTED_DATA^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_DIGESTED_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_ALGO_IDENTIFIER()�� ���� �ڵ�\n
* -# Seq_to_CMS_CONTENT_INFO()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_CMS_DIGESTED_DATA(SEQUENCE *seq, CMS_DIGESTED_DATA **cdd);

/*!
* \brief
* CMS_AUTHENTICATED_DATA ����ü�� Sequence�� Encode �Լ�
* \param cad
* CMS_AUTHENTICATED_DATA ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS CMS_AUTHENTICATED_DATA_to_Seq(CMS_AUTHENTICATED_DATA *cad, SEQUENCE **seq);

/*!
* \brief
* Sequence�� CMS_AUTHENTICATED_DATA ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param cad
* CMS_AUTHENTICATED_DATA ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS Seq_to_CMS_AUTHENTICATED_DATA(SEQUENCE *seq, CMS_AUTHENTICATED_DATA **cad);


/*!
* \brief
* CMS_CONTENT_INFO ����ü�� Sequence�� Encode �Լ�
* \param cci
* CMS_CONTENT_INFO ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_CMS_CONTENT_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_CONTENT_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# CMS_SIGNED_DATA_to_Seq()�� ���� �ڵ�\n
* -# CMS_ENVELOPED_DATA_to_Seq()�� ���� �ڵ�\n
* -# CMS_SIGNED_AND_ENVELOPED_DATA_to_Seq()�� ���� �ڵ�\n
* -# CMS_DIGESTED_DATA_to_Seq()�� ���� �ڵ�\n
* -# CMS_ENCRYPTED_DATA_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS CMS_CONTENT_INFO_to_Seq(CMS_CONTENT_INFO *cci, SEQUENCE **seq);


/*!
* \brief
* Sequence�� CMS_CONTENT_INFO ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param cci
* CMS_CONTENT_INFO ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_CMS_CONTENT_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_CONTENT_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_CONTENT_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_CMS_SIGNED_DATA()�� ���� �ڵ�\n
* -# Seq_to_CMS_ENVELOPED_DATA()�� ���� �ڵ�\n
* -# Seq_to_CMS_DIGESTED_DATA()�� ���� �ڵ�\n
* -# Seq_to_CMS_ENCRYPTED_DATA()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_CMS_CONTENT_INFO(SEQUENCE *seq, CMS_CONTENT_INFO **cci);

#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(ENCAPSULATED_CONTENT_INFO*, new_ENCAPSULATED_CONTENT_INFO, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_ENCAPSULATED_CONTENT_INFO, (ENCAPSULATED_CONTENT_INFO *encapsulatedContentInfo), (encapsulatedContentInfo) );
INI_RET_LOADLIB_PKI(CMS_SIGNER_INFO*, new_CMS_SIGNER_INFO, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_CMS_SIGNER_INFO, (CMS_SIGNER_INFO *signerInfo), (signerInfo) );
INI_RET_LOADLIB_PKI(CMS_SIGNER_INFOS*, new_CMS_SIGNER_INFOS, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_CMS_SIGNER_INFOS, (CMS_SIGNER_INFOS *signerInfos), (signerInfos) );
INI_RET_LOADLIB_PKI(CMS_ORIGINATOR_INFO*, new_CMS_ORIGINATOR_INFO, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_CMS_ORIGINATOR_INFO, (CMS_ORIGINATOR_INFO *cmsOriginatorInfo), (cmsOriginatorInfo) );
INI_RET_LOADLIB_PKI(CMS_SIGNED_DATA*, new_CMS_SIGNED_DATA, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_CMS_SIGNED_DATA, (CMS_SIGNED_DATA *cmsSignedData), (cmsSignedData) );
INI_RET_LOADLIB_PKI(RECIPIENT_IDENTIFIER*, new_RECIPIENT_IDENTIFIER, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_RECIPIENT_IDENTIFIER, (RECIPIENT_IDENTIFIER *recipientIdentifier), (recipientIdentifier) );
INI_RET_LOADLIB_PKI(CMS_RECIPIENT_INFO*, new_CMS_RECIPIENT_INFO, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_CMS_RECIPIENT_INFO, (CMS_RECIPIENT_INFO *cri), (cri) );
INI_RET_LOADLIB_PKI(CMS_RECIPIENT_INFOS*, new_CMS_RECIPIENT_INFOS, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_CMS_RECIPIENT_INFOS, (CMS_RECIPIENT_INFOS *recipientInfos), (recipientInfos) );
INI_RET_LOADLIB_PKI(CMS_ENCRYPTED_CONTENT_INFO*, new_CMS_ENCRYPTED_CONTENT_INFO, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_CMS_ENCRYPTED_CONTENT_INFO, (CMS_ENCRYPTED_CONTENT_INFO *encryptedContentInfo), (encryptedContentInfo) );
INI_RET_LOADLIB_PKI(CMS_ENVELOPED_DATA*, new_CMS_ENVELOPED_DATA, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_CMS_ENVELOPED_DATA, (CMS_ENVELOPED_DATA *cmsEnvelopedData), (cmsEnvelopedData) );
INI_RET_LOADLIB_PKI(CMS_DIGESTED_DATA*, new_CMS_DIGESTED_DATA, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_CMS_DIGESTED_DATA, (CMS_DIGESTED_DATA *cmsDigestedData), (cmsDigestedData) );
INI_RET_LOADLIB_PKI(CMS_ENCRYPTED_DATA*, new_CMS_ENCRYPTED_DATA, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_CMS_ENCRYPTED_DATA, (CMS_ENCRYPTED_DATA *cmsEncryptedData), (cmsEncryptedData) );
INI_RET_LOADLIB_PKI(CMS_AUTHENTICATED_DATA*, new_CMS_AUTHENTICATED_DATA, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_CMS_AUTHENTICATED_DATA, (CMS_AUTHENTICATED_DATA *cmsAuthenticatedData), (cmsAuthenticatedData) );
INI_RET_LOADLIB_PKI(CMS_CONTENT_INFO*, new_CMS_CONTENT_INFO, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_CMS_CONTENT_INFO, (CMS_CONTENT_INFO *cmsContentInfo), (cmsContentInfo) );
INI_RET_LOADLIB_PKI(ISC_STATUS, set_CMS_Cipher, (CMS_CONTENT_INFO *cci, int cipherID, const uint8 *key, const uint8 *iv, int enc), (cci,cipherID,key,iv,enc), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, init_CMS_Encrypt_RecipientInfo, (CMS_RECIPIENT_INFOS *ris, X509_ALGO_IDENTIFIER *identifier, uint8 *secretKey, uint8 *iv, int pk_encode), (ris,identifier,secretKey,iv,pk_encode), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encrypt_CMS_RecipientInfo, (CMS_CONTENT_INFO *cci, int cipherID, uint8 *key, uint8 *iv), (cci,cipherID,key,iv), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, init_CMS_Encrypt, (CMS_CONTENT_INFO *cci, int type_oid, X509_ALGO_IDENTIFIER *identifier, int detached, uint8 *secretKey, uint8 *iv, int pk_encode), (cci,type_oid,identifier,detached,secretKey,iv,pk_encode), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, update_CMS_encrypt, (CMS_CONTENT_INFO *cci, uint8* in, int inLen, uint8 *out, int *outLen), (cci,in,inLen,out,outLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, final_CMS_Encrypt, (CMS_CONTENT_INFO *cci, uint8 *out, int *outLen), (cci,out,outLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, new_CMS_Content, (CMS_CONTENT_INFO *cci, int type), (cci,type), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_CMS_Type, (CMS_CONTENT_INFO *cms, int type), (cms,type), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_CMS_version, (CMS_CONTENT_INFO *cci, uint32 version), (cci,version), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_CMS_ENCRYPTED_CONTENT_INFO, (CMS_ENCRYPTED_CONTENT_INFO *eci, int type_oid, X509_ALGO_IDENTIFIER *algorithm, uint8* encData, int encDataLen), (eci,type_oid,algorithm,encData,encDataLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_CMS_SIGNER_INFO, (CMS_SIGNER_INFO *signerInfo, X509_CERT *x509, uint32 flags, ASYMMETRIC_KEY *pkey, int digestOID, int pk_encode, void *alg_param), (signerInfo,x509,flags,pkey,digestOID,pk_encode,alg_param), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_CMS_RECIPIENT_INFO, (CMS_RECIPIENT_INFO *cri, X509_CERT *x509, int pk_encode, void *alg_param, uint32 flags), (cri,x509,pk_encode,alg_param,flags), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_ENCAPSULATED_CONTENT_INFO, (CMS_CONTENT_INFO *cci, ENCAPSULATED_CONTENT_INFO *eci), (cci,eci), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_Content_Info, (CMS_CONTENT_INFO *cci, uint8* data, int dataLen, int detached), (cci,data,dataLen,detached), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_CMS_macAlgorithm, (CMS_CONTENT_INFO *cci, int digestOID), (cci,digestOID), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_CMS_digestAlgorithm, (CMS_CONTENT_INFO *cci, int digestOID), (cci,digestOID), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_CMS_mac, (CMS_CONTENT_INFO *cci, uint8 *digest, int digestLen), (cci,digest,digestLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(CMS_SIGNER_INFO*, add_CMS_Signature, (CMS_CONTENT_INFO *cci, X509_CERT *x509, ASYMMETRIC_KEY *pkey, uint32 flag, int digestOID, int pk_encode, void *alg_param), (cci,x509,pkey,flag,digestOID,pk_encode,alg_param), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_CMS_Signed_Attribute, (CMS_SIGNER_INFO *csi, int oid, int atrtype, uint8 *value, int valueLen), (csi,oid,atrtype,value,valueLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_CMS_Unsigned_Attribute, (CMS_SIGNER_INFO *csi, int oid, int atrtype, uint8 *value, int valueLen), (csi,oid,atrtype,value,valueLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_CMS_Certificate, (CMS_CONTENT_INFO *cci, X509_CERT *x509), (cci,x509), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_CMS_CRL, (CMS_CONTENT_INFO *cci, X509_CRL *crl), (cci,crl), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_CMS_Originator_Certificate, (CMS_CONTENT_INFO *cci, X509_CERT *x509), (cci,x509), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_CMS_Originator_CRL, (CMS_CONTENT_INFO *cci, X509_CRL *crl), (cci,crl), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_CMS_Recipient, (CMS_CONTENT_INFO *cci, X509_CERT *x509, int pk_encode, void *alg_param, uint32 flags), (cci,x509,pk_encode,alg_param,flags), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_CMS_RECIPIENT_INFO, (CMS_CONTENT_INFO *cci, CMS_RECIPIENT_INFO *cri), (cci,cri), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_CMS_Unprotected_Attribute, (CMS_CONTENT_INFO *cci, int oid, int atrtype, uint8 *value, int valueLen), (cci,oid,atrtype,value,valueLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_CMS_Authenticated_Attribute, (CMS_CONTENT_INFO *cci, int oid, int atrtype, uint8 *value, int valueLen), (cci,oid,atrtype,value,valueLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_CMS_Unauthenticated_Attribute, (CMS_CONTENT_INFO *cci, int oid, int atrtype, uint8 *value, int valueLen), (cci,oid,atrtype,value,valueLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, sign_CMS, (CMS_CONTENT_INFO *cci), (cci), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, verify_CMS, (CMS_CONTENT_INFO *cci, X509_CERT *x509, uint8 *data, int dataLen), (cci,x509,data,dataLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encrypt_CMS, (CMS_CONTENT_INFO *cci, int type_oid, X509_ALGO_IDENTIFIER *identifier,uint8 *in, int inLen, int pk_encode), (cci,type_oid,identifier,in,inLen,pk_encode), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encrypt_CMS_userKEY, (CMS_CONTENT_INFO *cci, int type_oid, X509_ALGO_IDENTIFIER *identifier,uint8 *in, int inLen, uint8 *secretKey, uint8 *iv, int pk_encode), (cci,type_oid,identifier,in,inLen,secretKey,iv,pk_encode), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, decrypt_content_encryption_key, (CMS_CONTENT_INFO *cci, X509_CERT *cert, ASYMMETRIC_KEY* priKey, uint8* cek, int *cekLen, int pk_decode), (cci,cert,priKey,cek,cekLen,pk_decode), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, decrypt_CMS, (CMS_CONTENT_INFO *cci, uint8 *key, uint8 *iv, uint8 *out, int *outLen), (cci,key,iv,out,outLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, digest_CMS, (CMS_CONTENT_INFO *cci, int digestID, uint8 *data, int dataLen), (cci,digestID,data,dataLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, ENCAPSULATED_CONTENT_INFO_to_Seq, (ENCAPSULATED_CONTENT_INFO *eci, SEQUENCE **seq), (eci,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_ENCAPSULATED_CONTENT_INFO, (SEQUENCE *seq, ENCAPSULATED_CONTENT_INFO **eci), (seq,eci), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, CMS_SIGNER_INFO_to_Seq, (CMS_SIGNER_INFO *signerInfo, SEQUENCE **seq), (signerInfo,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_CMS_SIGNER_INFO, (SEQUENCE *seq, CMS_SIGNER_INFO **signerInfo), (seq,signerInfo), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, CMS_SIGNER_INFOS_to_Seq, (CMS_SIGNER_INFOS *signerInfos, SET_OF **setOf), (signerInfos,setOf), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_CMS_SIGNER_INFOS, (SET_OF *setOf, CMS_SIGNER_INFOS **signerInfos), (setOf,signerInfos), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, CMS_SIGNED_DATA_to_Seq, (CMS_SIGNED_DATA *csd, SEQUENCE **seq), (csd,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_CMS_SIGNED_DATA, (SEQUENCE *seq, CMS_SIGNED_DATA **csd), (seq,csd), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, CMS_ORIGINATOR_INFO_to_Seq, (CMS_ORIGINATOR_INFO *coi, SEQUENCE **seq), (coi,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_CMS_ORIGINATOR_INFO, (SEQUENCE *seq, CMS_ORIGINATOR_INFO **csd), (seq,csd), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, CMS_RECIPIENT_INFO_to_Seq, (CMS_RECIPIENT_INFO *cri, SEQUENCE **seq), (cri,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_CMS_RECIPIENT_INFO, (SEQUENCE *seq, CMS_RECIPIENT_INFO **cri), (seq,cri), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, CMS_RECIPIENT_INFOS_to_Seq, (CMS_RECIPIENT_INFOS *recipientInfos, SET_OF **setOf), (recipientInfos,setOf), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_CMS_RECIPIENT_INFOS, (SET_OF *setOf, CMS_RECIPIENT_INFOS **cris), (setOf,cris), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_CMS_ENCRYPTED_CONTENT_INFO, (SEQUENCE *seq, CMS_ENCRYPTED_CONTENT_INFO **ceci), (seq,ceci), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, CMS_ENVELOPED_DATA_to_Seq, (CMS_ENVELOPED_DATA *p7EnvelopedData, SEQUENCE **seq), (p7EnvelopedData,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, CMS_ENCRYPTED_DATA_to_Seq, (CMS_ENCRYPTED_DATA *ced, SEQUENCE **seq), (ced,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_CMS_ENCRYPTED_DATA, (SEQUENCE *seq, CMS_ENCRYPTED_DATA **ced), (seq,ced), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_CMS_ENVELOPED_DATA, (SEQUENCE *seq, CMS_ENVELOPED_DATA **ced), (seq,ced), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, CMS_DIGESTED_DATA_to_Seq, (CMS_DIGESTED_DATA *cdd, SEQUENCE **seq), (cdd,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_CMS_DIGESTED_DATA, (SEQUENCE *seq, CMS_DIGESTED_DATA **cdd), (seq,cdd), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, CMS_AUTHENTICATED_DATA_to_Seq, (CMS_AUTHENTICATED_DATA *cad, SEQUENCE **seq), (cad,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_CMS_AUTHENTICATED_DATA, (SEQUENCE *seq, CMS_AUTHENTICATED_DATA **cad), (seq,cad), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, CMS_CONTENT_INFO_to_Seq, (CMS_CONTENT_INFO *cci, SEQUENCE **seq), (cci,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_CMS_CONTENT_INFO, (SEQUENCE *seq, CMS_CONTENT_INFO **cci), (seq,cci), ISC_FAIL);


#endif

#ifdef  __cplusplus
}
#endif
#endif /* __CMS_H__ */

