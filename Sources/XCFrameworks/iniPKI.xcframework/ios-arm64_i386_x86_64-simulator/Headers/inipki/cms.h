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


/* 입력이 이 지시자일 경우 서명은 원문을 포함하지 않고, 암호화는 암호문의 결과를 der에 포함시키지 않음*/
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
* ENCAPSULATED CONTENT INFO의 정보를 저장하는 구조체
*/
typedef struct ENCAPSULATED_CONTENT_INFO_st {
	OBJECT_IDENTIFIER				*contentType;				/*!< Content의 타입(OID)*/
	OCTET_STRING					*eContent;					/*!< OCTET_STRING 구조체의 포인터*/
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
* CMS SIGNER INFO의 정보를 저장하는 구조체
*/
typedef struct CMS_SIGNER_INFO_st {
	INTEGER 					*version;					/*!< version = 1 or 3*/			
	SIGNER_IDENTIFIER			*sid;						/*!< issuerAndSerialNumber OR subjectKeyIdentifier */				
	X509_ALGO_IDENTIFIER		*digestAlgorithm;			/*!< 해쉬 알고리즘*/		
	X509_ATTRIBUTES				*signedAttrs;				/*!< 인증된 속성값들(IMPLICIT SET OF Context Specific 0 OPTIONAL)*/
	X509_ALGO_IDENTIFIER		*signatureAlgorithm;		/*!< 해쉬-암호화 알고리즘*/
	OCTET_STRING				*signature;					/*!< 암호화된 해쉬 값*/
	X509_ATTRIBUTES				*unsignedAttrs;				/*!< 인증되지 않은 속성값들(IMPLICIT SET OF Context Specific 1 OPTIONAL)*/	
	ASYMMETRIC_KEY				*signKey;					/*!< 사인에 사용되는 키*/
} CMS_SIGNER_INFO;

/*!
* \brief
* CMS_SIGNER_INFO 구조체 스택(SET OF)의 재정의
*/
typedef STK(CMS_SIGNER_INFO) CMS_SIGNER_INFOS;


/*!
* \brief
* CMS SIGNED DATA의 정보를 저장하는 구조체
*/
typedef struct CMS_SIGNED_DATA_st {
	INTEGER							*version;				/*!< Version = 1*/
	X509_ALGO_IDENTIFIERS			*digestAlgorithms;		/*!< 해쉬 알고리즘들(SET OF) */
	ENCAPSULATED_CONTENT_INFO		*encapContentInfo;		/*!< ENCAPSULATED_CONTENT_INFO 구조체의 포인터*/
	X509_CERTS						*certificates;			/*!< X509 인증서들(IMPLICIT SET OF Context Specific 0 OPTIONAL)*/
	X509_CRLS						*crls;					/*!< X509 CRL들(IMPLICIT SET OF Context Specific 1 OPTIONAL)*/
	CMS_SIGNER_INFOS				*signerInfos;			/*!< CMS_SIGNER_INFOS 구조체 스택의 포인터(SET OF)*/
	int								detached;				/*!< 0:DER로 인코딩시 평문 포함, 1:평문 미 포함 */
} CMS_SIGNED_DATA;

/*!
* \brief
* CMS_ORIGINATOR_INFO 의 정보를 저장하는 구조체
*/
typedef struct CMS_ORIGINATOR_INFO_st {
	X509_CERTS						*certificates;			/*!< X509 인증서들(IMPLICIT SET OF Context Specific 0 OPTIONAL)*/
	X509_CRLS						*crls;					/*!< X509 CRL들(IMPLICIT SET OF Context Specific 1 OPTIONAL)*/
} CMS_ORIGINATOR_INFO;

/*!
* \brief
* RECIPIENT_IDENTIFIER의 정보를 저장하는 구조체
*/
typedef struct RECIPIENT_IDENTIFIER_st {
	int type;						/* 0 : issuerAndSerialNumber, 1 : subjectKeyIdentifier */
	ISSUER_AND_SERIAL_NUMBER	*issuerAndSerialNumber;
	OCTET_STRING 				*subjectKeyIdentifier;
} RECIPIENT_IDENTIFIER;

/*!
* \brief
* KEY_TRANS_RECIPIENT_INFO의 정보를 저장하는 구조체
*/
typedef struct KEY_TRANS_RECIPIENT_INFO_st {
	INTEGER							*version;	
	RECIPIENT_IDENTIFIER			*rid;
	X509_ALGO_IDENTIFIER			*keyEncryptionAlgorithm;
	OCTET_STRING					*encryptedKey;
	ASYMMETRIC_KEY					*pubKey;					/*!< 제거 가능한지 ???*/
} KEY_TRANS_RECIPIENT_INFO;

/*!
* \brief
* ORIGINATOR_PUBLIC_KEY의 정보를 저장하는 구조체
*/
typedef struct ORIGINATOR_PUBLIC_KEY_st {
	X509_ALGO_IDENTIFIER			*algorithm;
	BIT_STRING						*publicKey;
} ORIGINATOR_PUBLIC_KEY;

/*!
* \brief
* KEY_AGREE_RECIPIENT_INFO의 정보를 저장하는 구조체
*/
typedef struct ORIGINATOR_IDENTIFIER_ORKEY_st {
	int type;						/* 0 : issuerAndSerialNumber, 1 : subjectKeyIdentifier */
	ISSUER_AND_SERIAL_NUMBER	*issuerAndSerialNumber;
	OCTET_STRING 				*subjectKeyIdentifier;
	ORIGINATOR_PUBLIC_KEY		*originatorKey;
} ORIGINATOR_IDENTIFIER_ORKEY;

/*!
* \brief
* OTHER_KEY_ATTRIBUTE의 정보를 저장하는 구조체
*/
typedef struct OTHER_KEY_ATTRIBUTE_st {
	OBJECT_IDENTIFIER				*keyAttrId;
	void						*keyAttr;			/* Any defined */
} OTHER_KEY_ATTRIBUTE;

/*!
* \brief
* RECIPIENT_KEY_IDENTIFIER의 정보를 저장하는 구조체
*/
typedef struct RECIPIENT_KEY_IDENTIFIER_st {
	OCTET_STRING 					*subjectKeyIdentifier;
	GENERALIZED_TIME 				*date;
	OTHER_KEY_ATTRIBUTE				*other;
} RECIPIENT_KEY_IDENTIFIER;

/*!
* \brief
* KEY_AGREE_RECIPIENT_IDENTIFIER의 정보를 저장하는 구조체
*/
typedef struct KEY_AGREE_RECIPIENT_IDENTIFIER_st {
	int type;						/* 0 : issuerAndSerialNumber, 1 : recipientKeyIdentifier */
	ISSUER_AND_SERIAL_NUMBER	*issuerAndSerialNumber;
	RECIPIENT_KEY_IDENTIFIER	*rKeyId;
} KEY_AGREE_RECIPIENT_IDENTIFIER;

/*!
* \brief
* RECIPIENT_ENCRYPTED_KEY의 정보를 저장하는 구조체
*/
typedef struct RECIPIENT_ENCRYPTED_KEY_st {
	KEY_AGREE_RECIPIENT_IDENTIFIER	*rid;	
	OCTET_STRING					*encryptedKey;
} RECIPIENT_ENCRYPTED_KEY;

/*!
* \brief
* RECIPIENT_ENCRYPTED_KEY 구조체 리스트
*/
typedef STK(RECIPIENT_ENCRYPTED_KEY) RECIPIENT_ENCRYPTED_KEYS;

/*!
* \brief
* KEY_AGREE_RECIPIENT_INFO의 정보를 저장하는 구조체
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
* CMS RECIPIENT INFO의 정보를 저장하는 구조체
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
* CMS_RECIPIENT_INFO 구조체 스택(SET OF)의 재정의
*/
typedef STK(CMS_RECIPIENT_INFO) CMS_RECIPIENT_INFOS;

/*!
* \brief
* CMS_ENCRYPTED_CONTENT_INFO 의 정보를 저장하는 구조체
*/
typedef struct CMS_ENCRYPTED_CONTENT_INFO_st {
	OBJECT_IDENTIFIER				*contentType;				
	X509_ALGO_IDENTIFIER			*contentEncryptionAlgorithm;
	OCTET_STRING					*encryptedContent;
	ISC_BLOCK_CIPHER_UNIT				*cipher;					/*!< ISC_BLOCK_CIPHER_UNIT 구조체의 포인터*/
} CMS_ENCRYPTED_CONTENT_INFO;

/*!
* \brief
* CMS ENVELOPED DATA의 정보를 저장하는 구조체
*/
typedef struct CMS_ENVELOPED_DATA_st {
	INTEGER							*version;					/*!< Version = 0 */
	CMS_ORIGINATOR_INFO				*originatorInfo;			/*!< CMS_ORIGINATOR_INFO 구조체의 포인터*/
	CMS_RECIPIENT_INFOS				*recipientInfos;			/*!< CMS_RECIPIENT_INFOS 구조체 스택의 포인터(SET OF)*/
	CMS_ENCRYPTED_CONTENT_INFO		*encryptedContentInfo;		/*!< CMS_ENCRYPTED_CONTENT_INFO 구조체의 포인터*/
	X509_ATTRIBUTES					*unprotectedAttrs;			/*!< X509_ALGO_IDENTIFIERS 구조체의 포인터*/
	int								detached;					/*!< 0:DER로 인코딩시 평문 포함, 1:평문 미 포함 */
} CMS_ENVELOPED_DATA;

/*!
* \brief
* CMS DIGESTED DATA의 정보를 저장하는 구조체
*/
typedef struct CMS_DIGESTED_DATA_st {
	INTEGER							*version;					
	X509_ALGO_IDENTIFIER			*digestAlgorithm;			
	ENCAPSULATED_CONTENT_INFO		*encapContentInfo;			/*!< ENCAPSULATED_CONTENT_INFO 구조체의 포인터*/
	OCTET_STRING					*digest;					
	int								detached;					/*!< 0:DER로 인코딩시 평문 포함, 1:평문 미 포함 */
} CMS_DIGESTED_DATA;

/*!
* \brief
* CMS ENCRYPTED DATA의 정보를 저장하는 구조체
*/
typedef struct CMS_ENCRYPTED_DATA_ST {
	INTEGER							*version;					
	X509_ALGO_IDENTIFIER			*digestAlgorithm;			
	CMS_ENCRYPTED_CONTENT_INFO		*encryptedContentInfo;		/*!< CMS_ENCRYPTED_CONTENT_INFO 구조체의 포인터*/
	X509_ATTRIBUTES					*unprotectedAttrs;	
	int								detached;					/*!< 0:DER로 인코딩시 평문 포함, 1:평문 미 포함 */
} CMS_ENCRYPTED_DATA;

/*!
* \brief
* CMS AUTHENTICATED DATA의 정보를 저장하는 구조체
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
	int								detached;				/*!< 0:DER로 인코딩시 평문 포함, 1:평문 미 포함 */
} CMS_AUTHENTICATED_DATA;

/*!
* \brief
* PKCS7 CONTENT INFO의 정보를 저장하는 구조체
*/
typedef struct CMS_CONTENT_INFO_st {
	OBJECT_IDENTIFIER					*contentType;				/*!< Content의 타입(OID)*/
	union {
		OCTET_STRING					*data;						/*!< OCTET_STRING 구조체의 포인터*/
		CMS_SIGNED_DATA					*signedData;				/*!< CMS_SIGNED_DATA 구조체의 포인터*/
		CMS_ENVELOPED_DATA				*envelopedData;				/*!< CMS_ENVELOPED_DATA 구조체의 포인터*/
		CMS_DIGESTED_DATA				*digestedData;				/*!< CMS_ENVELOPED_DATA 구조체의 포인터*/
		CMS_ENCRYPTED_DATA				*encryptedData;				/*!< CMS_ENCRYPTED_DATA 구조체의 포인터*/
		CMS_AUTHENTICATED_DATA			*authenticatedData;			/*!< CMS_AUTHENTICATED_DATA 구조체의 포인터*/
	} content;														/*!< Content 공용체(EXLICIT Context Specific 0 OPTIONAL)*/
} CMS_CONTENT_INFO;

/*!
* \brief
* CMS_CONTENT_INFO 구조체의 Content가 CMS DATA인지 확인하는 매크로 함수
* \param a
* CMS_CONTENT_INFO 구조체의 포인터
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_CMS_data(a)		(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_data)

/*!
* \brief
* CMS_CONTENT_INFO 구조체의 Content가 CMS SIGNED DATA인지 확인하는 매크로 함수
* \param a
* CMS_CONTENT_INFO 구조체의 포인터
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_CMS_signed(a)	(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_signedData)

/*!
* \brief
* CMS_CONTENT_INFO 구조체의 Content가 CMS ENVELOPED DATA인지 확인하는 매크로 함수
* \param a
* CMS_CONTENT_INFO 구조체의 포인터
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_CMS_enveloped(a)	(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_envelopedData)

/*!
* \brief
* CMS_CONTENT_INFO 구조체의 Content가 CMS DIGESTED DATA인지 확인하는 매크로 함수
* \param a
* CMS_CONTENT_INFO 구조체의 포인터
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_CMS_digest(a)	(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_digestData)

/*!
* \brief
* CMS_CONTENT_INFO 구조체의 Content가 CMS ENCRYPTED DATA인지 확인하는 매크로 함수
* \param a
* CMS_CONTENT_INFO 구조체의 포인터
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_CMS_encrypted(a)	(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_encryptedData)

/*!
* \brief
* CMS_CONTENT_INFO 구조체의 Content가 CMS AUTHENTICATED DATA인지 확인하는 매크로 함수
* \param a
* CMS_CONTENT_INFO 구조체의 포인터
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_CMS_Authenticated(a)	\
	(index_from_OBJECT_IDENTIFIER((a)->contentType) == id-smime-ct-authData)

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* ENCAPSULATED_CONTENT_INFO 구조체의 초기화 함수
* \returns
* ENCAPSULATED_CONTENT_INFO 구조체 포인터
*/
ISC_API ENCAPSULATED_CONTENT_INFO *new_ENCAPSULATED_CONTENT_INFO(void);

/*!
* \brief
* ENCAPSULATED_CONTENT_INFO 구조체를 메모리 할당 해제
* \param signerInfo
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_ENCAPSULATED_CONTENT_INFO(ENCAPSULATED_CONTENT_INFO *encapsulatedContentInfo);

/*!
* \brief
* CMS_SIGNER_INFO 구조체의 초기화 함수
* \returns
* CMS_SIGNER_INFO 구조체 포인터
*/
ISC_API CMS_SIGNER_INFO *new_CMS_SIGNER_INFO(void);

/*!
* \brief
* CMS_SIGNER_INFO 구조체를 메모리 할당 해제
* \param signerInfo
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_CMS_SIGNER_INFO(CMS_SIGNER_INFO *signerInfo);

/*!
* \brief
* CMS_SIGNER_INFOS 구조체의 초기화 함수
* \returns
* CMS_SIGNER_INFOS 구조체 포인터
*/
ISC_API CMS_SIGNER_INFOS *new_CMS_SIGNER_INFOS(void);
/*!
* \brief
* CMS_SIGNER_INFOS 구조체를 메모리 할당 해제
* \param signerInfos
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_CMS_SIGNER_INFOS(CMS_SIGNER_INFOS *signerInfos);


/*!
* \brief
* CMS_ORIGINATOR_INFO 구조체의 초기화 함수
* \returns
* CMS_ORIGINATOR_INFO 구조체 포인터
*/
ISC_API CMS_ORIGINATOR_INFO *new_CMS_ORIGINATOR_INFO(void);

/*!
* \brief
* CMS_ORIGINATOR_INFO 구조체를 메모리 할당 해제
* \param cmsOriginatorInfo
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_CMS_ORIGINATOR_INFO(CMS_ORIGINATOR_INFO *cmsOriginatorInfo);

/*!
* \brief
* CMS_SIGNED_DATA 구조체의 초기화 함수
* \returns
* CMS_SIGNED_DATA 구조체 포인터
*/
ISC_API CMS_SIGNED_DATA *new_CMS_SIGNED_DATA(void);

/*!
* \brief
* CMS_SIGNED_DATA 구조체를 메모리 할당 해제
* \param cmsSignedData
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_CMS_SIGNED_DATA(CMS_SIGNED_DATA *cmsSignedData);

/*!
* \brief
* RECIPIENT_IDENTIFIER 구조체의 초기화 함수
* \returns
* RECIPIENT_IDENTIFIER 구조체 포인터
*/
ISC_API RECIPIENT_IDENTIFIER *new_RECIPIENT_IDENTIFIER(void);

/*!
* \brief
* RECIPIENT_IDENTIFIER 구조체를 메모리 할당 해제
* \param recipientIdentifier
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_RECIPIENT_IDENTIFIER(RECIPIENT_IDENTIFIER *recipientIdentifier);

/*!
* \brief
* CMS_RECIPIENT_INFO 구조체의 초기화 함수
* \returns
* CMS_RECIPIENT_INFO 구조체 포인터
*/
ISC_API CMS_RECIPIENT_INFO *new_CMS_RECIPIENT_INFO(void);

/*!
* \brief
* CMS_RECIPIENT_INFO 구조체를 메모리 할당 해제
* \param cri
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_CMS_RECIPIENT_INFO(CMS_RECIPIENT_INFO *cri);

/*!
* \brief
* CMS_RECIPIENT_INFOS 구조체의 초기화 함수
* \returns
* CMS_RECIPIENT_INFOS 구조체 포인터
*/
ISC_API CMS_RECIPIENT_INFOS *new_CMS_RECIPIENT_INFOS(void);

/*!
* \brief
* CMS_RECIPIENT_INFOS 구조체를 메모리 할당 해제
* \param recipientInfos
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_CMS_RECIPIENT_INFOS(CMS_RECIPIENT_INFOS *recipientInfos);


KEY_TRANS_RECIPIENT_INFO *new_KEY_TRANS_RECIPIENT_INFO(void);
void free_KEY_TRANS_RECIPIENT_INFO(KEY_TRANS_RECIPIENT_INFO *ktri) ;

/*!
* \brief
* CMS_ENCRYPTED_CONTENT_INFO 구조체의 초기화 함수
* \returns
* CMS_ENCRYPTED_CONTENT_INFO 구조체 포인터
*/
ISC_API CMS_ENCRYPTED_CONTENT_INFO *new_CMS_ENCRYPTED_CONTENT_INFO(void);

/*!
* \brief
* CMS_ENCRYPTED_CONTENT_INFO 구조체를 메모리 할당 해제
* \param encryptedContentInfo
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_CMS_ENCRYPTED_CONTENT_INFO(CMS_ENCRYPTED_CONTENT_INFO *encryptedContentInfo);


/*!
* \brief
* CMS_ENVELOPED_DATA 구조체의 초기화 함수
* \returns
* CMS_ENVELOPED_DATA 구조체 포인터
*/
ISC_API CMS_ENVELOPED_DATA *new_CMS_ENVELOPED_DATA(void);

/*!
* \brief
* CMS_ENVELOPED_DATA 구조체를 메모리 할당 해제
* \param cmsEnvelopedData
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_CMS_ENVELOPED_DATA(CMS_ENVELOPED_DATA *cmsEnvelopedData);

/*!
* \brief
* CMS_DIGESTED_DATA 구조체의 초기화 함수
* \returns
* CMS_DIGESTED_DATA 구조체 포인터
*/
ISC_API CMS_DIGESTED_DATA *new_CMS_DIGESTED_DATA(void);

/*!
* \brief
* CMS_DIGESTED_DATA 구조체를 메모리 할당 해제
* \param cmsDigestedData
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_CMS_DIGESTED_DATA(CMS_DIGESTED_DATA *cmsDigestedData);

/*!
* \brief
* CMS_ENCRYPTED_DATA 구조체의 초기화 함수
* \returns
* CMS_ENCRYPTED_DATA 구조체 포인터
*/
ISC_API CMS_ENCRYPTED_DATA *new_CMS_ENCRYPTED_DATA(void);

/*!
* \brief
* CMS_ENCRYPTED_DATA 구조체를 메모리 할당 해제
* \param cmsEncryptedData
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_CMS_ENCRYPTED_DATA(CMS_ENCRYPTED_DATA *cmsEncryptedData);

/*!
* \brief
* CMS_AUTHENTICATED_DATA 구조체의 초기화 함수
* \returns
* CMS_AUTHENTICATED_DATA 구조체 포인터
*/
ISC_API CMS_AUTHENTICATED_DATA *new_CMS_AUTHENTICATED_DATA(void);

/*!
* \brief
* CMS_AUTHENTICATED_DATA 구조체를 메모리 할당 해제
* \param cmsAuthenticatedData
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_CMS_AUTHENTICATED_DATA(CMS_AUTHENTICATED_DATA *cmsAuthenticatedData);


/*!
* \brief
* CMS_CONTENT_INFO 구조체의 초기화 함수
* \returns
* CMS_CONTENT_INFO 구조체 포인터
*/
ISC_API CMS_CONTENT_INFO *new_CMS_CONTENT_INFO(void);

/*!
* \brief
* CMS_CONTENT_INFO 구조체를 메모리 할당 해제
* \param cmsContentInfo
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_CMS_CONTENT_INFO(CMS_CONTENT_INFO *cmsContentInfo);

/*!
* \brief
* CMS_CONTENT_INFO에 사용되는 ISC_BLOCK_CIPHER_UNIT를 설정
* (OID_pkcs7_envelopedData/OID_pkcs7_encryptedData)
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param cipher
* 설정하려는 ISC_BLOCK_CIPHER_UNIT 구조체 포인터 \n
* init 된 ISC_BLOCK_CIPHER_UNIT이 전달됨(포인터가 전달되므로 ISC_MEM_FREE 금지)
* \return
* -# ISC_SUCCESS : 성공
* -# L_PKCS7^ISC_ERR_NULL_INPUT : cipher가 널인 경우
* -# ISC_FAIL : 실패
*/
/*ISC_API ISC_STATUS set_CMS_Cipher(CMS_CONTENT_INFO *cci, ISC_BLOCK_CIPHER_UNIT* cipher);*/
ISC_API ISC_STATUS set_CMS_Cipher(CMS_CONTENT_INFO *cci, int cipherID, const uint8 *key, const uint8 *iv, int enc);


ISC_API ISC_STATUS init_CMS_Encrypt_RecipientInfo(CMS_RECIPIENT_INFOS *ris, X509_ALGO_IDENTIFIER *identifier, 
												 uint8 *secretKey, uint8 *iv, int pk_encode);

ISC_API ISC_STATUS encrypt_CMS_RecipientInfo(CMS_CONTENT_INFO *cci, int cipherID, uint8 *key, uint8 *iv) ;

/*!
* \brief
* CMS_CONTENT_INFO 의 암호화 모드 초기화\n
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData)
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param type_oid
* 암호화 되는 타입
* \param identifier
* 암호화 알고리즘이 지정된 Identifier
* \param detached
* detached가 0일경우 암호문이 p7에 포함됨\n
* detached가 1일경우 암호문이 데이터가 p7의 외부에 있음을 가정
* \param secretKey
* 암호화에 사용될 비밀키(Password)
* \param iv
* 암호화에 사용될 초기백터(IV)
* \param pk_encode
* 암호화에 사용될 encode 값 설정
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS init_CMS_Encrypt(CMS_CONTENT_INFO *cci, int type_oid, X509_ALGO_IDENTIFIER *identifier, int detached, uint8 *secretKey, uint8 *iv, int pk_encode);

/*!
* \brief
* CMS_CONTENT_INFO 의 암호화 수행(Update)
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData)
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param in
* 입력되는 원문의 버퍼
* \param inLen
* 입력되는 원문의 버퍼 길이 포인터
* \param out
* 출력되는 암호문의 버퍼
* \param outLen
* 출력되는 암호문의 버퍼 길이 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS update_CMS_encrypt(CMS_CONTENT_INFO *cci, uint8* in, int inLen, uint8 *out, int *outLen);

/*!
* \brief
* CMS_CONTENT_INFO의 암호화 최종 절차 수행
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData)
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param out
* 출력되는 암호문의 버퍼
* \param outLen
* 버퍼의 길이 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS final_CMS_Encrypt(CMS_CONTENT_INFO *cci, uint8 *out, int *outLen);


/*!
* \brief
* CMS_CONTENT_INFO 구조체를 type으로 생성
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param type
* cms type oid index
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS new_CMS_Content(CMS_CONTENT_INFO *cci, int type);

/*!
* \brief
* CMS_CONTENT_INFO 구조체의 type을 설정
* \param cms
* CMS_CONTENT_INFO 구조체 포인터
* \param type
* cms type oid index
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_CMS_Type(CMS_CONTENT_INFO *cms, int type);

/*!
* \brief
* CMS_CONTENT_INFO 구조체의버전정보를설정함
* \param cci
* CMS_CONTENT_INFO 구조체
* \param version
* 설정할버전
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_CMS_version(CMS_CONTENT_INFO *cci, uint32 version);

/*!
* \brief
* ENCRYPTED_CONTENT_INFO에 암호화된 결과가 지정됨(encData가 NULL일 경우에 암호문이 외부에 있는 경우임)
* \param eci
* ENCRYPTED_CONTENT_INFO 구조체 포인터
* \param type_oid
* OID 인덱스 값
* \param algorithm
* 알고리즘 식별자
* \param encData
* 암호화된 데이터(NULL이면 Detached Type)
* \param encDataLen
* 암호화된 데이터의 길이(0이면 Detached Type)
* \return
* -# ISC_SUCCESS : 성공
* -# L_PKCS7^ISC_ERR_NULL_INPUT : 알고리즘과 ENCRYPTED_CONTENT_INFO 구조체 포인터가 널인 경우
* -# L_PKCS7^ISC_ERR_INVALID_INPUT : type_oid가	undefined type 임
*/
ISC_API ISC_STATUS set_CMS_ENCRYPTED_CONTENT_INFO(CMS_ENCRYPTED_CONTENT_INFO *eci, int type_oid, 
					X509_ALGO_IDENTIFIER *algorithm, uint8* encData, int encDataLen);

/*!
* \brief
* CMS_SIGNER_INFO의 정보를 서명자의 인증서, 개인키, 해시알고리즘 지정으로 설정
* \param signerInfo
* CMS_SIGNER_INFO 구조체 포인터
* \param x509
* 인증서
* \param flags
* SignerIdentifier의 타입 (CMS_SIGNERINFO_ISSUER_SERIAL, CMS_SIGNERINFO_KEYIDENTIFIER)
* \param pkey
* 개인키
* \param digestOID
* 해시 알고리즘 id
* \param pk_encode
* 암호 알고리즘 id
* \param alg_param
* 암호 알고리즘 파라미터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_CMS_SIGNER_INFO(CMS_SIGNER_INFO *signerInfo, X509_CERT *x509, uint32 flags,
											ASYMMETRIC_KEY *pkey, int digestOID, int pk_encode, void *alg_param);

/*!
* \brief
* CMS_RECIPIENT_INFO를 수신자의 인증서로부터 설정
* \param cri
* CMS_RECIPIENT_INFO 구조체 포인터
* \param x509
* 설정하려는 X509_CERT 구조체 포인터
* \param pk_encode
* 암호 알고리즘 id
* \param alg_param
* 암호 알고리즘 파라미터
* \param flags
* OPTIONAL flags
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_CMS_RECIPIENT_INFO(CMS_RECIPIENT_INFO *cri, X509_CERT *x509, int pk_encode, void *alg_param, uint32 flags);

/*!
* \brief
* CMS_CONTENT_INFO 의 content를 설정
* \param cci
* ENCAPSULATED_CONTENT_INFO 구조체 포인터
* \param eci
* 설정하려는 CMS_CONTENT_INFO 구조체 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_ENCAPSULATED_CONTENT_INFO(CMS_CONTENT_INFO *cci, ENCAPSULATED_CONTENT_INFO *eci);

/*!
* \brief
* CMS_CONTENT_INFO 의 content를 설정
* \param cci
* \param data
* 원본 데이터
* \param dataLen 
* 원본데이터의 길이
* \param detached
* detached가 0일경우 암호문이 p7에 포함됨\n
* detached가 1일경우 암호문이 데이터가 p7의 외부에 있음을 가정
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_Content_Info(CMS_CONTENT_INFO *cci, uint8* data, int dataLen, int detached);

/*!
* \brief
* CMS_CONTENT_INFO 의 authenticated Data의 macAlgorithm를 설정
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param digestOID
* 설정하려는 CMS_CONTENT_INFO 구조체 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API	ISC_STATUS set_CMS_macAlgorithm(CMS_CONTENT_INFO *cci, int digestOID);

/*!
* \brief
* CMS_CONTENT_INFO 의 authenticated Data의 digestAlgorithm를 설정
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param digestOID
* 설정하려는 CMS_CONTENT_INFO 구조체 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API	ISC_STATUS set_CMS_digestAlgorithm(CMS_CONTENT_INFO *cci, int digestOID);

/*!
* \brief
* CMS_CONTENT_INFO 의 authenticated Data의 mac를 설정
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param digest
* 설정하려는 메시지 인증코드
* \param digestLen
* 설정하려는 메시지 인증코드 길이
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API	ISC_STATUS set_CMS_mac(CMS_CONTENT_INFO *cci, uint8 *digest, int digestLen);

/*!
* \brief
* CMS_CONTENT_INFO에 서명자를 추가 \n
* (OID_pkcs7_signedData)
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param x509
* 인증서
* \param pkey
* 개인키
* \param flag
* 옵션선택을 위한 flag
* \param flag
* 해시 알고리즘 id
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API CMS_SIGNER_INFO *add_CMS_Signature(CMS_CONTENT_INFO *cci, X509_CERT *x509, ASYMMETRIC_KEY *pkey, 
										uint32 flag, int digestOID, int pk_encode, void *alg_param);

/*!
* \brief
* CMS_SIGNER_INFO에 Signed Attribute를 추가 \n
* \param csi
* CMS_SIGNER_INFO 구조체 포인터
* \param oid
* attribute의 OID
* \param atrtype
* 저장되는 attribute 자체의 asn1 type
* \param value
* attribute의 데이터
* \param valueLen
* 데이터의 길이
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_CMS_Signed_Attribute(CMS_SIGNER_INFO *csi, int oid, int atrtype, uint8 *value, int valueLen);

/*!
* \brief
* CMS_SIGNER_INFO에 Unsigend Attribute를 추가 \n
* \param csi
* CMS_SIGNER_INFO 구조체 포인터
* \param oid
* attribute의 OID
* \param atrtype
* 저장되는 attribute 자체의 asn1 type
* \param value
* attribute의 데이터
* \param valueLen
* 데이터의 길이
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_CMS_Unsigned_Attribute(CMS_SIGNER_INFO *csi, int oid, int atrtype, uint8 *value, int valueLen);

/*!
* \brief
* CMS_CONTENT_INFO에 관련 인증서를 추가 \n
* (OID_pkcs7_signedData)
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param x509
* 관련 인증서
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_CMS_Certificate(CMS_CONTENT_INFO *cci, X509_CERT *x509);

/*!
* \brief
* CMS_CONTENT_INFO에 관련 인증서폐기목록 추가 \n
* (OID_pkcs7_signedData)
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param crl
* 관련 인증서 폐기목록
* \return
* -# ISC_SUCCESS : 성공
* -# L_CMS^F_ADD_CMS_CERTIFICATE^ISC_ERR_NOT_SUPPORTED : 지원하지 않는 타입
* -# L_CMS^LOCATION^F_ADD_CMS_CERTIFICATE^ERR_STK_ERROR : 스택추가시 에러
*/
ISC_API ISC_STATUS add_CMS_CRL(CMS_CONTENT_INFO *cci, X509_CRL *crl);

/*!
* \brief
* CMS_CONTENT_INFO에 관련 송신자 인증서를 추가 \n
* (OID_pkcs7_envelopedData. OID_id_smime_ct_authData)
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param x509
* 관련 인증서
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_CMS_Originator_Certificate(CMS_CONTENT_INFO *cci, X509_CERT *x509);

/*!
* \brief
* CMS_CONTENT_INFO에 관련 송신자 인증서 폐기목록 추가 \n
* (OID_pkcs7_envelopedData. OID_id_smime_ct_authData)
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param crl
* 관련 인증서 폐기목록
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_CMS_Originator_CRL(CMS_CONTENT_INFO *cci, X509_CRL *crl);

/*!
* \brief
* CMS_CONTENT_INFO에 인증서에 해당하는 수신자를 추가 \n
* (OID_pkcs7_envelopedData)
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param x509
* 인증서
* \param pk_encode
* 암호 알고리즘 id
* \param alg_param
* 암호 파라이터
* \param flags
* OPTIONAL flags
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_CMS_Recipient(CMS_CONTENT_INFO *cci, X509_CERT *x509, int pk_encode, void *alg_param, uint32 flags);

/*!
* \brief
* CMS_CONTENT_INFO에 수신자를 추가 \n
* (OID_pkcs7_envelopedData)
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param cri
* 수신자 (인증서에 기반하여 적절히 생성되어야 함)
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_CMS_RECIPIENT_INFO(CMS_CONTENT_INFO *cci, CMS_RECIPIENT_INFO *cri);

/*!
* \brief
* CMS_CONTENT_INFO에 Unprotected Attribute를 추가 \n
* \param csi
* CMS_CONTENT_INFO 구조체 포인터
* \param oid
* attribute의 OID
* \param atrtype
* 저장되는 attribute 자체의 asn1 type
* \param value
* attribute의 데이터
* \param valueLen
* 데이터의 길이
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_CMS_Unprotected_Attribute(CMS_CONTENT_INFO *cci, int oid, int atrtype, uint8 *value, int valueLen);

/*!
* \brief
* CMS_CONTENT_INFO에 Authenticated Attribute를 추가 \n
* \param csi
* CMS_CONTENT_INFO 구조체 포인터
* \param oid
* attribute의 OID
* \param atrtype
* 저장되는 attribute 자체의 asn1 type
* \param value
* attribute의 데이터
* \param valueLen
* 데이터의 길이
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_CMS_Authenticated_Attribute(CMS_CONTENT_INFO *cci, int oid, int atrtype, uint8 *value, int valueLen) ;

/*!
* \brief
* CMS_CONTENT_INFO에 unauthenticated Attribute를 추가 \n
* \param csi
* CMS_CONTENT_INFO 구조체 포인터
* \param oid
* attribute의 OID
* \param atrtype
* 저장되는 attribute 자체의 asn1 type
* \param value
* attribute의 데이터
* \param valueLen
* 데이터의 길이
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_CMS_Unauthenticated_Attribute(CMS_CONTENT_INFO *cci, int oid, int atrtype, uint8 *value, int valueLen) ;

/*!
* \brief
* CMS_CONTENT_INFO의 서명 생성
* (OID_pkcs7_signedData)
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS sign_CMS(CMS_CONTENT_INFO *cci);

/*!
* \brief
* CMS_CONTENT_INFO의 서명 검증
* (OID_pkcs7_signedData)
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param x509
* 검증용 공개키가 포함된 인증서
* \param data
* 검증하려는 데이터 (cci이 안에 원본 데이터를 포함하고 있으면 NULL)
* \param dataLen 
* 데이터의 길이(cci이 안에 원본 데이터를 포함하고 있으면 0)
* \return
* -# ISC_SUCCESS : 검증 통과 
* -# L_CMS^F_CMS_VERIFY^ISC_ERR_NULL_INPUT : data와 dataLen이 NULL인경우
* -# L_CMS^F_CMS_VERIFY^ISC_ERR_INVALID_INPUT : 해당하는 인증서가 없거나, 인증서는 있는데 키가 없거나 signer info가 없거나, digestAlg, encAlg가 없는 경우
* -# L_CMS^F_CMS_VERIFY^ISC_ERR_VERIFY_FAILURE : 인증서가 아예 없는 경우
* -# ISC_FAIL : 서명검증에 실패했거나 그 이외의 오류
*/
ISC_API ISC_STATUS verify_CMS(CMS_CONTENT_INFO *cci, X509_CERT *x509, uint8 *data, int dataLen);

/*!
* \brief
* CMS_CONTENT_INFO의 암호화 수행 (Detached mode는 지원 불가)
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData)
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param type_oid
* 암호화되는 Content Type
* \param identifier
* 암호화 알고리즘의 Identifier
* \param in
* 입력
* \param inLen
* 입력의 길이
* \param pk_encode
* 암호화에 사용될 encode 값 설정
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS encrypt_CMS(CMS_CONTENT_INFO *cci, int type_oid, X509_ALGO_IDENTIFIER *identifier,uint8 *in, int inLen, int pk_encode);

/*!
* \brief
* CMS_CONTENT_INFO의 암호화 수행 (Detached mode는 지원 불가)
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData/OID_pkcs7_signedAndEnvelopedData)
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param type_oid
* 암호화되는 Content Type
* \param identifier
* 암호화 알고리즘의 Identifier
* \param in
* 입력
* \param inLen
* 입력의 길이
* \param secretKey
* 암호화에 사용될 비밀키(Password)
* \param iv
* 암호화에 사용될 초기백터(IV)
* \param pk_encode
* 암호화에 사용될 encode 값 설정
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS encrypt_CMS_userKEY(CMS_CONTENT_INFO *cci,  int type_oid, X509_ALGO_IDENTIFIER *identifier,uint8 *in, int inLen, uint8 *secretKey, uint8 *iv, int pk_encode);


/*!
* \brief
* CMS_CONTENT_INFO - Enveloped Data에 수신자의 Content-Encryption Key를 복호화
* (OID_pkcs7_envelopedData)
* \param p7
* CMS_CONTENT_INFO 구조체 포인터
* \param cert
* 수신자에 해당하는 인증서
* \param priKey
* 복호화에 사용될 비밀키
* \param cek
* 복화화될 cek
* \param cekLen
* 복호화될 키의 길이 포인터 변수
* \param pk_decode
* 복호화시 사용할 decoding 값 설정
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
* -# ISC_Init_RSAES()의 에러 코드
* -# ISC_Decrypt_RSAES()의 에러 코드
*/
ISC_API ISC_STATUS decrypt_content_encryption_key(CMS_CONTENT_INFO *cci, X509_CERT *cert, ASYMMETRIC_KEY* priKey, uint8* cek, int *cekLen, int pk_decode);

/*!
* \brief
* CMS_CONTENT_INFO의 복호화 수행 (Detached mode는 지원 불가)
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData)
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param key
* 복호화할 키
* \param iv
* initial vector
* \param out
* 복호화된 평문
* \param outLen
* 버퍼의 길이 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS decrypt_CMS(CMS_CONTENT_INFO *cci, uint8 *key, uint8 *iv, uint8 *out, int *outLen);

/*!
* \brief
* CMS_CONTENT_INFO의 digestedData 생성
* (OID_pkcs7_digestedData)
* \param cci
* CMS_CONTENT_INFO 구조체 포인터
* \param digestID
* 다이제스트 알고리즘
* \param data
* 입력
* \param dataLen
* 입력의 길이
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS digest_CMS(CMS_CONTENT_INFO *cci, int digestID, uint8 *data, int dataLen);

/*!
* \brief
* ENCAPSULATED_CONTENT_INFO 구조체를 Sequence로 Encode 함수
* \param eci
* ENCAPSULATED_CONTENT_INFO 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ENCAPSULATED_CONTENT_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_ENCAPSULATED_CONTENT_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# CMS_ISSUER_AND_SERIAL_NUMBER_to_Seq()의 에러 코드\n
* -# X509_ALGO_IDENTIFIER_to_Seq()의 에러 코드\n

*/
ISC_API ISC_STATUS ENCAPSULATED_CONTENT_INFO_to_Seq(ENCAPSULATED_CONTENT_INFO *eci, SEQUENCE **seq);

/*!
* \brief
* Sequence를 ENCAPSULATED_CONTENT_INFO 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param eci
* ENCAPSULATED_CONTENT_INFO 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_ENCAPSULATED_CONTENT_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_ENCAPSULATED_CONTENT_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_ENCAPSULATED_CONTENT_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_CMS_ISSUER_AND_SERIAL_NUMBER()의 에러 코드\n
* -# Seq_to_X509_ALGO_IDENTIFIER()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_ENCAPSULATED_CONTENT_INFO(SEQUENCE *seq, ENCAPSULATED_CONTENT_INFO **eci);

/*!
* \brief
* CMS_SIGNER_INFO 구조체를 Sequence로 Encode 함수
* \param signerInfo
* CMS_SIGNER_INFO 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_CMS_SIGNER_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_SIGNER_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# CMS_ISSUER_AND_SERIAL_NUMBER_to_Seq()의 에러 코드\n
* -# X509_ALGO_IDENTIFIER_to_Seq()의 에러 코드\n
* -# X509_ATTRIBUTES_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS CMS_SIGNER_INFO_to_Seq(CMS_SIGNER_INFO *signerInfo, SEQUENCE **seq);

/*!
* \brief
* Sequence를 CMS_SIGNER_INFO 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param signerInfo
* CMS_SIGNER_INFO 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_CMS_SIGNER_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_SIGNER_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_SIGNER_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_CMS_ISSUER_AND_SERIAL_NUMBER()의 에러 코드\n
* -# Seq_to_X509_ALGO_IDENTIFIER()의 에러 코드\n
* -# Seq_to_X509_ATTRIBUTES()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_CMS_SIGNER_INFO(SEQUENCE *seq, CMS_SIGNER_INFO **signerInfo);

/*!
* \brief
* CMS_SIGNER_INFOS 구조체를 Sequence로 Encode 함수
* \param signerInfos
* CMS_SIGNER_INFOS 구조체
* \param setOf
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_CMS_SIGNER_INFOS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_SIGNER_INFOS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# CMS_SIGNER_INFO_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS CMS_SIGNER_INFOS_to_Seq(CMS_SIGNER_INFOS *signerInfos, SET_OF **setOf);

/*!
* \brief
* Sequence를 CMS_SIGNER_INFOS 구조체로 Decode 함수
* \param setOf
* Decoding Sequence 구조체
* \param signerInfos
* CMS_SIGNER_INFOS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_CMS_SIGNER_INFOS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_SIGNER_INFOS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_SIGNER_INFOS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_CMS_SIGNER_INFO()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_CMS_SIGNER_INFOS(SET_OF *setOf, CMS_SIGNER_INFOS **signerInfos);

/*!
* \brief
* CMS_SIGNED_DATA 구조체를 Sequence로 Encode 함수
* \param csd
* CMS_SIGNED_DATA 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_CMS_SIGNED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_SIGNED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_ALGO_IDENTIFIERS_to_Seq()의 에러 코드\n
* -# CMS_CONTENT_INFO_to_Seq()의 에러 코드\n
* -# X509_CERTIFICATES_to_Seq()의 에러 코드\n
* -# X509_CRLS_to_Seq()의 에러 코드\n
* -# CMS_SIGNER_INFOS_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS CMS_SIGNED_DATA_to_Seq(CMS_SIGNED_DATA *csd, SEQUENCE **seq);

/*!
* \brief
* Sequence를 CMS_SIGNED_DATA 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param csd
* CMS_SIGNED_DATA 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_CMS_SIGNED_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_SIGNED_DATA^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_SIGNED_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_ALGO_IDENTIFIERS()의 에러 코드\n
* -# Seq_to_CMS_CONTENT_INFO()의 에러 코드\n
* -# Seq_to_X509_CERTIFICATES()의 에러 코드\n
* -# Seq_to_X509_CRLS()의 에러 코드\n
* -# Seq_to_CMS_SIGNER_INFOS()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_CMS_SIGNED_DATA(SEQUENCE *seq, CMS_SIGNED_DATA **csd);


/*!
* \brief
* CMS_ORIGINATOR_INFO 구조체를 Sequence로 Encode 함수
* \param csd
* CMS_ORIGINATOR_INFO 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_CMS_ORIGINATOR_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_ORIGINATOR_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_CERTIFICATES_to_Seq()의 에러 코드\n
* -# X509_CRLS_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS CMS_ORIGINATOR_INFO_to_Seq(CMS_ORIGINATOR_INFO *coi, SEQUENCE **seq);

/*!
* \brief
* Sequence를 CMS_ORIGINATOR_INFO 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param csd
* CMS_ORIGINATOR_INFO 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_CMS_ORIGINATOR_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_ORIGINATOR_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_ORIGINATOR_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_CERTIFICATES()의 에러 코드\n
* -# Seq_to_X509_CRLS()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_CMS_ORIGINATOR_INFO(SEQUENCE *seq, CMS_ORIGINATOR_INFO **csd);

/*!
* \brief
* CMS_RECIPIENT_INFO 구조체를 Sequence로 Encode 함수
* \param cri
* CMS_RECIPIENT_INFO 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_CMS_RECIPIENT_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_RECIPIENT_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# CMS_ISSUER_AND_SERIAL_NUMBER_to_Seq()의 에러 코드\n
* -# X509_ALGO_IDENTIFIER_to_Seq()의 에러 코드\n

*/
ISC_API ISC_STATUS CMS_RECIPIENT_INFO_to_Seq(CMS_RECIPIENT_INFO *cri, SEQUENCE **seq);

/*!
* \brief
* Sequence를 CMS_RECIPIENT_INFO 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param cri
* CMS_RECIPIENT_INFO 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_CMS_RECIPIENT_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_RECIPIENT_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_RECIPIENT_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_CMS_ISSUER_AND_SERIAL_NUMBER()의 에러 코드\n
* -# Seq_to_X509_ALGO_IDENTIFIER()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_CMS_RECIPIENT_INFO(SEQUENCE *seq, CMS_RECIPIENT_INFO **cri);

/*!
* \brief
* CMS_RECIPIENT_INFOS 구조체를 Sequence로 Encode 함수
* \param recipientInfos
* CMS_RECIPIENT_INFOS 구조체
* \param setOf
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_CMS_RECIPIENT_INFOS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_RECIPIENT_INFOS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# CMS_RECIPIENT_INFO_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS CMS_RECIPIENT_INFOS_to_Seq(CMS_RECIPIENT_INFOS *recipientInfos, SET_OF **setOf);

/*!
* \brief
* Sequence를 CMS_RECIPIENT_INFOS 구조체로 Decode 함수
* \param setOf
* Decoding Sequence 구조체
* \param cris
* CMS_RECIPIENT_INFOS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_CMS_RECIPIENT_INFOS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_RECIPIENT_INFOS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_CMS_RECIPIENT_INFO()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_CMS_RECIPIENT_INFOS(SET_OF *setOf, CMS_RECIPIENT_INFOS **cris);

/*!
* \brief
* Sequence를 CMS_ENCRYPTED_CONTENT_INFO 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param ceci
* CMS_ENCRYPTED_CONTENT_INFO 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_CMS_ENCRYPTED_CONTENT_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_ENCRYPTED_CONTENT_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_ENCRYPTED_CONTENT_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_ALGO_IDENTIFIER()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_CMS_ENCRYPTED_CONTENT_INFO(SEQUENCE *seq, CMS_ENCRYPTED_CONTENT_INFO **ceci);

/*!
* \brief
* CMS_ENVELOPED_DATA 구조체를 Sequence로 Encode 함수
* \param p7EnvelopedData
* CMS_ENVELOPED_DATA 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_CMS_ENVELOPED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_ENVELOPED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# CMS_RECIPIENT_INFOS_to_Seq()의 에러 코드\n
* -# CMS_ENCRYPTED_CONTENT_INFO_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS CMS_ENVELOPED_DATA_to_Seq(CMS_ENVELOPED_DATA *p7EnvelopedData, SEQUENCE **seq);

/*!
* \brief
* CMS_ENCRYPTED_DATA 구조체를 Sequence로 Encode 함수
* \param ced
* CMS_ENCRYPTED_DATA 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_CMS_ENCRYPTED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_ENCRYPTED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# CMS_ENCRYPTED_CONTENT_INFO_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS CMS_ENCRYPTED_DATA_to_Seq(CMS_ENCRYPTED_DATA *ced, SEQUENCE **seq);

/*!
* \brief
* Sequence를 CMS_ENCRYPTED_DATA 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param ced
* CMS_ENCRYPTED_DATA 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_CMS_ENCRYPTED_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_ENCRYPTED_DATA^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_ENCRYPTED_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_CMS_ENCRYPTED_CONTENT_INFO()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_CMS_ENCRYPTED_DATA(SEQUENCE *seq, CMS_ENCRYPTED_DATA **ced);

/*!
* \brief
* CMS_ENVELOPED_DATA 구조체를 Sequence로 Encode 함수
* \param ced
* CMS_ENVELOPED_DATA 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_CMS_ENVELOPED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_ENVELOPED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# CMS_RECIPIENT_INFOS_to_Seq()의 에러 코드\n
* -# CMS_ENCRYPTED_CONTENT_INFO_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS CMS_ENVELOPED_DATA_to_Seq(CMS_ENVELOPED_DATA *ced, SEQUENCE **seq);

/*!
* \brief
* Sequence를 CMS_ENVELOPED_DATA 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param ced
* CMS_ENVELOPED_DATA 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_CMS_ENVELOPED_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_ENVELOPED_DATA^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_ENVELOPED_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_CMS_RECIPIENT_INFOS()의 에러 코드\n
* -# Seq_to_CMS_ENCRYPTED_CONTENT_INFO()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_CMS_ENVELOPED_DATA(SEQUENCE *seq, CMS_ENVELOPED_DATA **ced);

/*!
* \brief
* CMS_DIGESTED_DATA 구조체를 Sequence로 Encode 함수
* \param cdd
* CMS_DIGESTED_DATA 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_CMS_DIGESTED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_DIGESTED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_ALGO_IDENTIFIER_to_Seq()의 에러 코드\n
* -# CMS_CONTENT_INFO_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS CMS_DIGESTED_DATA_to_Seq(CMS_DIGESTED_DATA *cdd, SEQUENCE **seq);

/*!
* \brief
* Sequence를 CMS_DIGESTED_DATA 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param cdd
* CMS_DIGESTED_DATA 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_CMS_DIGESTED_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_DIGESTED_DATA^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_DIGESTED_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_ALGO_IDENTIFIER()의 에러 코드\n
* -# Seq_to_CMS_CONTENT_INFO()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_CMS_DIGESTED_DATA(SEQUENCE *seq, CMS_DIGESTED_DATA **cdd);

/*!
* \brief
* CMS_AUTHENTICATED_DATA 구조체를 Sequence로 Encode 함수
* \param cad
* CMS_AUTHENTICATED_DATA 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS CMS_AUTHENTICATED_DATA_to_Seq(CMS_AUTHENTICATED_DATA *cad, SEQUENCE **seq);

/*!
* \brief
* Sequence를 CMS_AUTHENTICATED_DATA 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param cad
* CMS_AUTHENTICATED_DATA 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS Seq_to_CMS_AUTHENTICATED_DATA(SEQUENCE *seq, CMS_AUTHENTICATED_DATA **cad);


/*!
* \brief
* CMS_CONTENT_INFO 구조체를 Sequence로 Encode 함수
* \param cci
* CMS_CONTENT_INFO 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_CMS_CONTENT_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_CMS_CONTENT_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# CMS_SIGNED_DATA_to_Seq()의 에러 코드\n
* -# CMS_ENVELOPED_DATA_to_Seq()의 에러 코드\n
* -# CMS_SIGNED_AND_ENVELOPED_DATA_to_Seq()의 에러 코드\n
* -# CMS_DIGESTED_DATA_to_Seq()의 에러 코드\n
* -# CMS_ENCRYPTED_DATA_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS CMS_CONTENT_INFO_to_Seq(CMS_CONTENT_INFO *cci, SEQUENCE **seq);


/*!
* \brief
* Sequence를 CMS_CONTENT_INFO 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param cci
* CMS_CONTENT_INFO 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_CMS_CONTENT_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_CMS_CONTENT_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_CMS_CONTENT_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_CMS_SIGNED_DATA()의 에러 코드\n
* -# Seq_to_CMS_ENVELOPED_DATA()의 에러 코드\n
* -# Seq_to_CMS_DIGESTED_DATA()의 에러 코드\n
* -# Seq_to_CMS_ENCRYPTED_DATA()의 에러 코드\n
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

