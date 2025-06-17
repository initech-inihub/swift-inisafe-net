/*!
* \file pkcs7.h
* \brief PKCS7
* Cryptographic Message Syntax
* \remarks
* \author
* Copyright (c) 2008 by \<INITech\>
*/
#ifndef HEADER_PKCS7_H
#define HEADER_PKCS7_H

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/foundation.h>

#include "asn1_objects.h"
#include "issuer_and_serial_number.h"
#include "x509.h"
#include "x509_crl.h"
#include "ctl.h"

#define IGNORE_X509_ALGO_IDENTIFER_PARAM 1

#ifdef  __cplusplus
extern "C" {
#endif


#define PF_STAGE_INIT 0
#define PF_STAGE_UPDATE 1
#define PF_STAGE_FINAL 2

/*
stage: PF_STAGE_INIT, PF_STAGE_UPDATE, PF_STAGE_FINAL 
*/
typedef int (*PF_SIGN_CB)(int stage, unsigned char* in, int inlen, unsigned char** sig_out, int* sig_outlen);
typedef int (*PF_VERIFY_CB)(int stage, unsigned char* in, int inlen, unsigned char* sig_in, int sig_len);

/*!
* \brief
* PKCS7 SIGNER INFO의 정보를 저장하는 구조체
*/
typedef struct P7_SIGNER_INFO_st {
	INTEGER 					*version;					/*!< Version = 1*/			
	ISSUER_AND_SERIAL_NUMBER	*issuerAndSerialNumber;		/*!< ISSUER_AND_SERIAL_NUMBER 구조체의 포인터*/	
	X509_ALGO_IDENTIFIER		*digestAlgorithm;			/*!< 해쉬 알고리즘*/		
	X509_ATTRIBUTES				*authenticatedAttributes;	/*!< 인증된 속성값들(IMPLICIT SET OF Context Specific 0 OPTIONAL)*/
	X509_ALGO_IDENTIFIER		*digestEncryptionAlgorithm;	/*!< 해쉬-암호화 알고리즘*/
	OCTET_STRING				*encryptedDigest;			/*!< 암호화된 해쉬 값*/
	X509_ATTRIBUTES				*unauthenticatedAttributes;	/*!< 인증되지 않은 속성값들(IMPLICIT SET OF Context Specific 1 OPTIONAL)*/	
	ASYMMETRIC_KEY				*signKey;					/*!< 사인에 사용되는 키*/
} P7_SIGNER_INFO;



/*!
* \brief
* ISC_DIGEST-Encryption의 결과 값을 저장하는 구조체
*/
typedef struct pkcs7_P7_DIGEST_INFO_st {
	X509_ALGO_IDENTIFIER		*digestAlgorithm;	/*!< 해쉬 알고리즘*/
	OCTET_STRING				*digest;			/*!< 해쉬 값*/
} P7_DIGEST_INFO;

/*!
* \brief
* SIGNER_INFO 구조체 스택(SET OF)의 재정의
*/
typedef STK(P7_SIGNER_INFO) P7_SIGNER_INFOS;

/*!
* \brief
* PKCS7 SIGNED DATA의 정보를 저장하는 구조체
*/
typedef struct P7_SIGNED_DATA_st {
	INTEGER							*version;			/*!< Version = 1*/
	X509_ALGO_IDENTIFIERS			*digestAlgorithms;	/*!< 해쉬 알고리즘들(SET OF) */
	struct P7_CONTENT_INFO_st		*contentInfo;		/*!< P7_CONTENT_INFO 구조체의 포인터*/
	X509_CERTS						*certificates;		/*!< X509 인증서들(IMPLICIT SET OF Context Specific 0 OPTIONAL)*/
	X509_CRLS						*crls;				/*!< X509 CRL들(IMPLICIT SET OF Context Specific 1 OPTIONAL)*/
	P7_SIGNER_INFOS					*signerInfos;	    /*!< P7_SIGNER_INFOS 구조체 스택의 포인터(SET OF)*/
	int								detached;			/*!< 0:DER로 인코딩시 평문 포함, 1:평문 미 포함 */
} P7_SIGNED_DATA;

/*!
* \brief
* PKCS7 RECIPIENT INFO의 정보를 저장하는 구조체
*/
typedef struct P7_RECIPIENT_INFO_st {
	INTEGER						*version;					/*!< Version = 0 */
	ISSUER_AND_SERIAL_NUMBER	*issuerAndSerialNumber;		/*!< ISSUER_AND_SERIAL_NUMBER 구조체의 포인터*/
	X509_ALGO_IDENTIFIER		*keyEncryptionAlgorithm;	/*!< 키 암호화 알고리즘*/
	OCTET_STRING				*encryptedKey;				/*!< 암호화된 키의 값*/
	ASYMMETRIC_KEY				*pubKey;					/*!< 암호화에 사용되는 공개키*/
} P7_RECIPIENT_INFO;

/*!
* \brief
* RECIPIENT_INFO 구조체 스택(SET OF)의 재정의
*/
typedef STK(P7_RECIPIENT_INFO) P7_RECIPIENT_INFOS;

/*!
* \brief
* PKCS7 ENCRYPTED CONTENT INFO의 정보를 저장하는 구조체
*/
typedef struct P7_ENCRYPTED_CONTENT_INFO_st {
	OBJECT_IDENTIFIER		*contentType;					/*!< Content의 타입(OID)*/
	X509_ALGO_IDENTIFIER	*contentEncryptionAlgorithm;	/*!< Content 암호화 알고리즘*/
	OCTET_STRING			*encryptedContent;				/*!< 암호화된 Content(IMPLICIT Context Specific 0 OPTIONAL)*/
	ISC_BLOCK_CIPHER_UNIT		*cipher;						/*!< ISC_BLOCK_CIPHER_UNIT 구조체의 포인터*/
} P7_ENCRYPTED_CONTENT_INFO;

/*!
* \brief
* PKCS7 ENVELOPED DATA의 정보를 저장하는 구조체
*/
typedef struct P7_ENVELOPED_DATA_st {
	INTEGER						*version;					/*!< Version = 0 */
	P7_RECIPIENT_INFOS			*recipientInfos;			/*!< P7_RECIPIENT_INFOS 구조체 스택의 포인터(SET OF)*/
	P7_ENCRYPTED_CONTENT_INFO	*encryptedContentInfo;		/*!< P7_ENCRYPTED_CONTENT_INFO 구조체의 포인터*/
	int							detached;					/*!< 0:DER로 인코딩시 암호문 포함, 1:암호문 미 포함*/
} P7_ENVELOPED_DATA;

/*!
* \brief
* PKCS7 SIGNED AND ENVELOPED DATA의 정보를 저장하는 구조체
*/
typedef struct P7_SIGNED_AND_ENVELOPED_DATA_st {
	INTEGER						*version;				/*!< Version = 1 */
	P7_RECIPIENT_INFOS			*recipientInfos;		/*!< P7_RECIPIENT_INFOS 구조체 스택의 포인터(SET OF)*/
	X509_ALGO_IDENTIFIERS		*digestAlgorithms;		/*!< 해쉬 알고리즘들(SET OF)*/
	P7_ENCRYPTED_CONTENT_INFO	*encryptedContentInfo;	/*!< P7_ENCRYPTED_CONTENT_INFO 구조체의 포인터*/
	X509_CERTS					*certificates;			/*!< X509 인증서들(IMPLICIT SET OF Context Specific 0 OPTIONAL)*/
	X509_CRLS					*crls;					/*!< X509 CRL들(IMPLICIT SET OF Context Specific 1 OPTIONAL)*/
	P7_SIGNER_INFOS				*signerInfos;			/*!< P7_SIGNER_INFOS 구조체 스택의 포인터(SET OF)*/
} P7_SIGNED_AND_ENVELOPED_DATA;

/*!
* \brief
* PKCS7 DIGESTED DATA의 정보를 저장하는 구조체
*/
typedef struct P7_DIGESTED_DATA_st {
	INTEGER							*version;			/*!< Version = 0 */
	X509_ALGO_IDENTIFIER			*digestAlgorithm;	/*!< 해쉬 알고리즘*/
	struct P7_CONTENT_INFO_st		*contentInfo;		/*!< P7_CONTENT_INFO 구조체의 포인터*/
	OCTET_STRING					*digest;			/*!< 해쉬 값*/
} P7_DIGESTED_DATA;

/*!
* \brief
* PKCS7 ENCRYPTED DATA의 정보를 저장하는 구조체
*/
typedef struct P7_ENCRYPTED_DATA_st {
	INTEGER						*version;				/*!< Version  = 0 */
	P7_ENCRYPTED_CONTENT_INFO	*encryptedContentInfo;	/*!< P7_ENCRYPTED_CONTENT_INFO 구조체의 포인터*/
	int							detached;				/*!< 0:DER로 인코딩시 암호문 포함, 1:암호문 미 포함*/
} P7_ENCRYPTED_DATA;

/*!
* \brief
* PKCS7 CONTENT INFO의 정보를 저장하는 구조체
*/
typedef struct P7_CONTENT_INFO_st {
	OBJECT_IDENTIFIER					*contentType;				/*!< Content의 타입(OID)*/
	union {
		OCTET_STRING					*data;						/*!< OCTET_STRING 구조체의 포인터*/
		P7_SIGNED_DATA					*signedData;				/*!< P7_SIGNED_DATA 구조체의 포인터*/
		P7_ENVELOPED_DATA				*envelopedData;				/*!< P7_ENVELOPED_DATA 구조체의 포인터*/
		P7_SIGNED_AND_ENVELOPED_DATA	*SignedAndEnvelopedData;	/*!< P7_SIGNED_AND_ENVELOPED_DATA 구조체의 포인터*/
		P7_DIGESTED_DATA				*digestedData;				/*!< P7_DIGESTED_DATA 구조체의 포인터*/
		P7_ENCRYPTED_DATA				*encryptedData;				/*!< P7_ENCRYPTED_DATA 구조체의 포인터*/
		CERT_TRUST_LIST					*ctlData;					/*!< CTL DATA 구조체 포인터 추가 (for CPV) */
	} content;														/*!< Content 공용체(EXLICIT Context Specific 0 OPTIONAL)*/
} P7_CONTENT_INFO;

/*!
* \brief
* P7_CONTENT_INFO구조체의 Content가 PKCS7 SIGNED DATA인지 확인하는 매크로 함수
* \param a
* P7_CONTENT_INFO 구조체의 포인터
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_PKCS7_signed(a)				(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_signedData)
/*!
* \brief
* P7_CONTENT_INFO구조체의 Content가 PKCS7 ENCRYPTED DATA인지 확인하는 매크로 함수
* \param a
* P7_CONTENT_INFO 구조체의 포인터
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_PKCS7_encrypted(a)			(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_encryptedData)
/*!
* \brief
* P7_CONTENT_INFO구조체의 Content가 PKCS7 ENVELOPED DATA인지 확인하는 매크로 함수
* \param a
* P7_CONTENT_INFO 구조체의 포인터
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_PKCS7_enveloped(a)			(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_envelopedData)
/*!
* \brief
* P7_CONTENT_INFO구조체의 Content가 PKCS7 SIGNED AND ENVELOPED DATA인지 확인하는 매크로 함수
* \param a
* P7_CONTENT_INFO 구조체의 포인터
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_PKCS7_signedAndEnveloped(a)	(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_signedAndEnvelopedData)
/*!
* \brief
* P7_CONTENT_INFO구조체의 Content가 PKCS7 DATA인지 확인하는 매크로 함수
* \param a
* P7_CONTENT_INFO 구조체의 포인터
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_PKCS7_data(a)				(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_data)
/*!
* \brief
* P7_CONTENT_INFO구조체의 Content가 PKCS7 DIGESTED DATA인지 확인하는 매크로 함수
* \param a
* P7_CONTENT_INFO 구조체의 포인터
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_PKCS7_digest(a)				(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_digestData)

#define PKCS7_DETACHED		 1   /*!< */ /* 입력이 이 지시자일 경우 서명은 원문을 포함하지 않고, 암호화는 암호문의 결과를 der에 포함시키지 않음*/
#define PKCS7_DEFAULT		 0	 /*!< */

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* ISSUER_AND_SERIAL_NUMBER 구조체의 초기화 함수
* \returns
* ISSUER_AND_SERIAL_NUMBER 구조체 포인터
*/
ISC_API ISSUER_AND_SERIAL_NUMBER *new_P7_ISSUER_AND_SERIAL_NUMBER(void);

/*!
* \brief
* ISSUER_AND_SERIAL_NUMBER 구조체를 메모리 할당 해제
* \param issuerAndSerial
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_P7_ISSUER_AND_SERIAL_NUMBER(ISSUER_AND_SERIAL_NUMBER *issuerAndSerial);

/*!
* \brief
* P7_SIGNER_INFO 구조체의 초기화 함수
* \returns
* P7_SIGNER_INFO 구조체 포인터
*/
ISC_API P7_SIGNER_INFO *new_P7_SIGNER_INFO(void);

/*!
* \brief
* P7_SIGNER_INFO 구조체를 메모리 할당 해제
* \param signerInfo
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_P7_SIGNER_INFO(P7_SIGNER_INFO *signerInfo);

/*!
* \brief
* P7_DIGEST_INFO 구조체의 초기화 함수
* \returns
* P7_DIGEST_INFO 구조체 포인터
*/
ISC_API P7_DIGEST_INFO *new_P7_DIGEST_INFO(void);

/*!
* \brief
* P7_DIGEST_INFO 구조체를 메모리 할당 해제
* \param digestInfo
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_P7_DIGEST_INFO(P7_DIGEST_INFO *digestInfo);

/*!
* \brief
* P7_SIGNER_INFOS 구조체의 초기화 함수
* \returns
* P7_SIGNER_INFOS 구조체 포인터
*/
ISC_API P7_SIGNER_INFOS *new_P7_SIGNER_INFOS(void);
/*!
* \brief
* P7_SIGNER_INFOS 구조체를 메모리 할당 해제
* \param signerInfos
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_P7_SIGNER_INFOS(P7_SIGNER_INFOS *signerInfos);

/*!
* \brief
* P7_SIGNED_DATA 구조체의 초기화 함수
* \returns
* P7_SIGNED_DATA 구조체 포인터
*/
ISC_API P7_SIGNED_DATA *new_P7_SIGNED_DATA(void);

/*!
* \brief
* P7_SIGNED_DATA 구조체를 메모리 할당 해제
* \param pkcs7SignedData
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_P7_SIGNED_DATA(P7_SIGNED_DATA *pkcs7SignedData);

/*!
* \brief
* P7_RECIPIENT_INFO 구조체의 초기화 함수
* \returns
* P7_RECIPIENT_INFO 구조체 포인터
*/
ISC_API P7_RECIPIENT_INFO *new_P7_RECIPIENT_INFO(void);

/*!
* \brief
* P7_RECIPIENT_INFO 구조체를 메모리 할당 해제
* \param recipientInfo
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_P7_RECIPIENT_INFO(P7_RECIPIENT_INFO *recipientInfo);

/*!
* \brief
* P7_RECIPIENT_INFOS 구조체의 초기화 함수
* \returns
* P7_RECIPIENT_INFOS 구조체 포인터
*/
ISC_API P7_RECIPIENT_INFOS *new_P7_RECIPIENT_INFOS(void);

/*!
* \brief
* P7_RECIPIENT_INFOS 구조체를 메모리 할당 해제
* \param recipientInfos
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_P7_RECIPIENT_INFOS(P7_RECIPIENT_INFOS *recipientInfos);

/*!
* \brief
* P7_ENCRYPTED_CONTENT_INFO 구조체의 초기화 함수
* \returns
* P7_ENCRYPTED_CONTENT_INFO 구조체 포인터
*/
ISC_API P7_ENCRYPTED_CONTENT_INFO *new_P7_ENCRYPTED_CONTENT_INFO(void);

/*!
* \brief
* P7_ENCRYPTED_CONTENT_INFO 구조체를 메모리 할당 해제
* \param encryptedContentInfo
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_P7_ENCRYPTED_CONTENT_INFO(P7_ENCRYPTED_CONTENT_INFO *encryptedContentInfo);

/*!
* \brief
* P7_ENVELOPED_DATA 구조체의 초기화 함수
* \returns
* P7_ENVELOPED_DATA 구조체 포인터
*/
ISC_API P7_ENVELOPED_DATA *new_P7_ENVELOPED_DATA(void);

/*!
* \brief
* P7_ENVELOPED_DATA 구조체를 메모리 할당 해제
* \param pkcs7EnvelopedData
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_P7_ENVELOPED_DATA(P7_ENVELOPED_DATA *pkcs7EnvelopedData);

/*!
* \brief
* P7_SIGNED_AND_ENVELOPED_DATA 구조체의 초기화 함수
* \returns
* P7_SIGNED_AND_ENVELOPED_DATA 구조체 포인터
*/
ISC_API P7_SIGNED_AND_ENVELOPED_DATA *new_P7_SIGNED_AND_ENVELOPED_DATA(void);

/*!
* \brief
* P7_SIGNED_AND_ENVELOPED_DATA 구조체를 메모리 할당 해제
* \param pkcs7SignedAndEnvelopedData
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_P7_SIGNED_AND_ENVELOPED_DATA(P7_SIGNED_AND_ENVELOPED_DATA *pkcs7SignedAndEnvelopedData);

/*!
* \brief
* P7_DIGESTED_DATA 구조체의 초기화 함수
* \returns
* P7_DIGESTED_DATA 구조체 포인터
*/
ISC_API P7_DIGESTED_DATA *new_P7_DIGESTED_DATA(void);

/*!
* \brief
* P7_DIGESTED_DATA 구조체를 메모리 할당 해제
* \param pkcs7DigestedData
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_P7_DIGESTED_DATA(P7_DIGESTED_DATA *pkcs7DigestedData);

/*!
* \brief
* P7_ENCRYPTED_DATA 구조체의 초기화 함수
* \returns
* P7_ENCRYPTED_DATA 구조체 포인터
*/
ISC_API P7_ENCRYPTED_DATA *new_P7_ENCRYPTED_DATA(void);

/*!
* \brief
* P7_ENCRYPTED_DATA 구조체를 메모리 할당 해제
* \param pkcs7EncryptedData
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_P7_ENCRYPTED_DATA(P7_ENCRYPTED_DATA *pkcs7EncryptedData);

/*!
* \brief
* P7_CONTENT_INFO 구조체의 초기화 함수
* \returns
* P7_CONTENT_INFO 구조체 포인터
*/
ISC_API P7_CONTENT_INFO *new_P7_CONTENT_INFO(void);
/*!
* \brief
* P7_CONTENT_INFO 구조체를 메모리 할당 해제
* \param pkcs7ContentInfo
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_P7_CONTENT_INFO(P7_CONTENT_INFO *pkcs7ContentInfo);

/*!
* \brief
* P7_CONTENT_INFO 구조체를 type으로 생성
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param type
* pkcs7 type oid index
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS new_PKCS7_Content(P7_CONTENT_INFO *p7, int type);

/*!
* \brief
* P7_CONTENT_INFO 구조체의 type을 설정
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param type
* pkcs7 type oid index
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_PKCS7_Type(P7_CONTENT_INFO *p7, int type);

/*!
* \brief
* P7_CONTENT_INFO 의 content를 설정
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param p7_data
* 설정하려는 P7_CONTENT_INFO 구조체 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_PKCS7_Content(P7_CONTENT_INFO *p7, P7_CONTENT_INFO *p7_data);

/*!
* \brief
* P7_RECIPIENT_INFO를 수신자의 인증서로부터 설정
* \param p7i
* P7_RECIPIENT_INFO 구조체 포인터
* \param x509
* 설정하려는 X509_CERT 구조체 포인터
* \param pk_encode
* 암호 알고리즘 id
* \param alg_param
* 암호 알고리즘 파라미터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_PKCS7_P7_RECIPIENT_INFO(P7_RECIPIENT_INFO *p7i, X509_CERT *x509, int pk_encode, void *alg_param);

/*!
* \brief
* P7_CONTENT_INFO에 사용되는 ISC_BLOCK_CIPHER_UNIT를 설정
* (OID_pkcs7_signedAndEnvelopedData/OID_pkcs7_envelopedData/OID_pkcs7_encryptedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param cipher
* 설정하려는 ISC_BLOCK_CIPHER_UNIT 구조체 포인터 \n
* init 된 ISC_BLOCK_CIPHER_UNIT이 전달됨(포인터가 전달되므로 ISC_MEM_FREE 금지)
* \return
* -# ISC_SUCCESS : 성공
* -# L_PKCS7^ISC_ERR_NULL_INPUT : cipher가 널인 경우
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_PKCS7_Cipher(P7_CONTENT_INFO *p7, ISC_BLOCK_CIPHER_UNIT* cipher);

/*!
* \brief
* P7_ENCRYPTED_CONTENT_INFO에 암호화된 결과가 지정됨(encData가 NULL일 경우에 암호문이 외부에 있는 경우임)
* \param enc_inf
* P7_ENCRYPTED_CONTENT_INFO 구조체 포인터
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
* -# L_PKCS7^ISC_ERR_NULL_INPUT : 알고리즘과 P7_ENCRYPTED_CONTENT_INFO 구조체 포인터가 널인 경우
* -# L_PKCS7^ISC_ERR_INVALID_INPUT : type_oid가	undefined type 임
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_PKCS7_P7_ENCRYPTED_CONTENT_INFO(P7_ENCRYPTED_CONTENT_INFO *enc_inf, int type_oid, X509_ALGO_IDENTIFIER *algorithm, uint8* encData, int encDataLen);

/*!
* \brief
* P7_CONTENT_INFO에 암호화된 데이터의 길이 반환
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \return
* -# P7_CONTENT_INFO에 암호화된 데이터의 길이
* -# -1 : 실패
*/
ISC_API int get_PKCS7_ENCRYPTED_CONTENT_length(P7_CONTENT_INFO *p7);

/*!
* \brief
* 바이너리를 Pkcs7 Data type으로 생성
* \param p7_data
* P7_CONTENT_INFO 구조체 포인터
* \param data
* 데이터
* \param dataLen
* 데이터의 길이
* \return
* -# ISC_SUCCESS : 성공
* -# L_PKCS7^F_GET_PKCS7_DATA^ISC_ERR_NULL_INPUT : 입력 파라미터가 NULL인 경우
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS gen_PKCS7_DATA_from_Binary(P7_CONTENT_INFO **p7_data, uint8* data, int dataLen);

/*!
* \brief
* P7_SIGNER_INFO의 정보를 서명자의 인증서, 개인키, 해시알고리즘 지정으로 설정
* \param p7i
* P7_SIGNER_INFO 구조체 포인터
* \param x509
* 인증서
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
ISC_API ISC_STATUS set_PKCS7_P7_SIGNER_INFO(P7_SIGNER_INFO *p7i, X509_CERT *x509, ASYMMETRIC_KEY *pkey, int digestOID, int pk_encode, void *alg_param);

/*!
* \brief
* P7_SIGNER_INFO의 정보를 서명자의 인증서, 개인키, 해시알고리즘 지정으로 설정
* \param p7i
* P7_SIGNER_INFO 구조체 포인터
* \param x509
* 인증서
* \param pkey
* 개인키
* \param digestOID
* 해시 알고리즘 id
* \param pk_encode
* 암호 알고리즘 id
* \param alg_param
* 암호 알고리즘 파라미터
* \param option 
* IGNORE_X509_ALGO_IDENTIFER_PARAM = 1, 0 인경우 기존 함수와 동일
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_PKCS7_P7_SIGNER_INFO_Ex(P7_SIGNER_INFO *p7i, X509_CERT *x509, ASYMMETRIC_KEY *pkey, int digestOID, int pk_encode, void *alg_param, int option);


/*!
* \brief
* P7_CONTENT_INFO에 서명자를 추가(P7_SIGNER_INFO가 적절히 생성되어 있어야 함) \n
* (OID_pkcs7_signedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param p7i
* P7_SIGNER_INFO 구조체 포인터(서명자)
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_PKCS7_Signer(P7_CONTENT_INFO *p7, P7_SIGNER_INFO *p7i);

/*!
* \brief
* P7_CONTENT_INFO에 관련 인증서를 추가 \n
* (OID_pkcs7_signedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param x509
* 관련 인증서
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_PKCS7_Certificate(P7_CONTENT_INFO *p7, X509_CERT *x509);

/*!
* \brief
* P7_CONTENT_INFO에 관련 CRL을 추가 \n
* (OID_pkcs7_signedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param crl
* 관련 CRL
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_PKCS7_Crl(P7_CONTENT_INFO *p7, X509_CRL *crl);

/*!
* \brief
* P7_CONTENT_INFO에 서명자를 추가 \n
* (OID_pkcs7_signedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param x509
* 인증서
* \param pkey
* 개인키
* \param digestOID
* 해시 알고리즘 id
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API P7_SIGNER_INFO *add_PKCS7_Signature(P7_CONTENT_INFO *p7, X509_CERT *x509, ASYMMETRIC_KEY *pkey, int digestOID);

/*!
* \brief
* P7_CONTENT_INFO에 서명자를 추가 \n
* (OID_pkcs7_signedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param x509
* 인증서
* \param pkey
* 개인키
* \param digestOID
* 해시 알고리즘 id
* \param option 
* IGNORE_X509_ALGO_IDENTIFER_PARAM = 1, 0 인경우 기존 함수와 동일
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API P7_SIGNER_INFO *add_PKCS7_Signature_Ex(P7_CONTENT_INFO *p7, X509_CERT *x509, ASYMMETRIC_KEY *pkey, int digestOID, int option);

/*!
* \brief
* P7_CONTENT_INFO에 서명자를 추가 \n
* (OID_pkcs7_signedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* \param pk_encode
* 암호 알고리즘 id
* \param alg_param
* 암호 파라이터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API P7_SIGNER_INFO *add_PKCS7_Signature_withEncryptedAlgorithm(P7_CONTENT_INFO *p7, X509_CERT *x509, ASYMMETRIC_KEY *pkey, int digestOID, int pk_encode, void *alg_param);

/*!
* \brief
* P7_CONTENT_INFO에 서명자를 추가 \n
* (OID_pkcs7_signedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param x509
* 인증서
* \param pkey
* 개인키
* \param digestOID
* 해시 알고리즘 id
* \param pk_encode
* 암호 알고리즘 id
* \param alg_param
* 암호 파라이터
* \param option 
* IGNORE_X509_ALGO_IDENTIFER_PARAM = 1, 0 인경우 기존 함수와 동일
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API P7_SIGNER_INFO *add_PKCS7_Signature_withEncryptedAlgorithm_Ex(P7_CONTENT_INFO *p7, X509_CERT *x509, ASYMMETRIC_KEY *pkey, int digestOID, int pk_encode, void *alg_param, int option);


/*!
* \brief
* P7_CONTENT_INFO에 인증서에 해당하는 수신자를 추가 \n
* (OID_pkcs7_signedAndEnvelopedData/OID_pkcs7_envelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param x509
* 인증서
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API P7_RECIPIENT_INFO *add_PKCS7_Recipient(P7_CONTENT_INFO *p7, X509_CERT *x509);

/*!
* \brief
* P7_CONTENT_INFO에 인증서에 해당하는 수신자를 추가 \n
* (OID_pkcs7_signedAndEnvelopedData/OID_pkcs7_envelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param x509
* 인증서
* \param pk_encode
* 암호 알고리즘 id
* \param alg_param
* 암호 파라이터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API P7_RECIPIENT_INFO *add_PKCS7_Recipient_withEncryptedAlgorithm(P7_CONTENT_INFO *p7, X509_CERT *x509, 
															  int pk_encode, void *alg_param);

/*!
* \brief
* P7_CONTENT_INFO에 수신자를 추가 \n
* (OID_pkcs7_signedAndEnvelopedData/OID_pkcs7_envelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param ri
* 수신자 (인증서에 기반하여 적절히 생성되어야 함)
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_PKCS7_P7_RECIPIENT_INFO(P7_CONTENT_INFO *p7, P7_RECIPIENT_INFO *ri);

/*!
* \brief
* P7_SIGNER_INFO에 Authenticated Attribute를 추가 \n
* \param p7si
* P7_SIGNER_INFO 구조체 포인터
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
ISC_API ISC_STATUS add_PKCS7_Signed_Attribute(P7_SIGNER_INFO *p7si, int oid, int atrtype, uint8 *value, int valueLen);

/*!
* \brief
* P7_SIGNER_INFO에 Unauthenticated Attribute를 추가 \n
* \param p7si
* P7_SIGNER_INFO 구조체 포인터
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
ISC_API ISC_STATUS add_PKCS7_Unauthenticated_Attribute(P7_SIGNER_INFO *p7si, int oid, int atrtype, uint8 *value, int valueLen); 

/*!
* \brief
* P7_SIGNER_INFO의 Signed Attribute 에서 지정한 oid 와 type 의 Attribute 를 찾아 첫번째 data를 반환한다. \n
* \param p7si
* P7_SIGNER_INFO 구조체 포인터
* \param oid
* attribute의 OID
* \param atrtype
* 찾는 attribute 의 asn1 type
* \param found_not_free 
* 찾은 attribute 의 첫번째 데이터 (외부에서 free 하면 안됨)
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS find_PKCS7_Signed_Attribute(P7_SIGNER_INFO *p7si, int oid, int atrtype, void** found_not_free);

/*!
* \brief
* P7_SIGNER_INFO의 Unauthenticated Attribute 에서 지정한 oid 와 type 의 Attribute 를 찾아 첫번째 data를 반환한다. \n
* \param p7si
* P7_SIGNER_INFO 구조체 포인터
* \param oid
* attribute의 OID
* \param atrtype
* 찾는 attribute 의 asn1 type
* \param found_not_free
* 찾은 attribute의 첫번째 데이터 (외부에서 free 하면 안됨)
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS find_PKCS7_Unauthenticated_Attribute(P7_SIGNER_INFO *p7si, int oid, int atrtype, void** found_not_free);
/*!
* \brief
* P7_CONTENT_INFO의 서명 초기화
* (OID_pkcs7_signedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param detached
* detached가 0일경우 서명되는 데이터가 p7에 포함됨\n
* detached가 1일경우 서명되는 데이터가 p7의 외부에 있음을 가정
* \return
* -# ISC_SUCCESS : 성공
* -# L_PKCS7^F_P7_SIGN^ISC_ERR_NULL_INPUT : p7이 NULL인 경우
* -# L_PKCS7^F_P7_SIGN^ISC_ERR_INVALID_INPUT : signer가 없거나 digestAlg, encAlg이 NULL인 경우
* -# ISC_FAIL : 지원하지 않는 타입이거나 ISC_Init_RSASSA()에 실패한 경우
*/
ISC_API ISC_STATUS init_PKCS7_Sign(P7_CONTENT_INFO *p7,int detached);

/*!
* \brief
* P7_CONTENT_INFO의 서명 초기화
* (OID_pkcs7_signedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param detached
* detached가 0일경우 서명되는 데이터가 p7에 포함됨\n
* detached가 1일경우 서명되는 데이터가 p7의 외부에 있음을 가정
* \param pf_sign_cb 
* 실제로 서명을 수행하는 콜백함수 (PKCS#11, PACCEL 연동을 위해)
* \return
* -# ISC_SUCCESS : 성공
* -# L_PKCS7^F_P7_SIGN^ISC_ERR_NULL_INPUT : p7이 NULL인 경우
* -# L_PKCS7^F_P7_SIGN^ISC_ERR_INVALID_INPUT : signer가 없거나 digestAlg, encAlg이 NULL인 경우
* -# ISC_FAIL : 지원하지 않는 타입이거나 ISC_Init_RSASSA()에 실패한 경우
*/
ISC_API ISC_STATUS init_PKCS7_Sign_cb(P7_CONTENT_INFO *p7,int detached, PF_SIGN_CB pf_sign_cb);

/*!
* \brief
* P7_CONTENT_INFO의 서명 갱신 (update)
* (OID_pkcs7_signedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param data
* 서명하려는 데이터
* \param dataLen
* 데이터의 길이
* \return
* -# ISC_SUCCESS : 성공
* -# L_PKCS7^F_P7_SIGN^ISC_ERR_NULL_INPUT : p7이 NULL인 경우
* -# L_PKCS7^F_P7_SIGN^ISC_ERR_INVALID_INPUT : data와 dataLen이 유효하지 않거나, signer가 없는 경우
* -# ISC_FAIL : 지원하지 않는 타입인 경우
*/
ISC_API ISC_STATUS update_PKCS7_Sign(P7_CONTENT_INFO *p7, uint8* data, int dataLen);

/*!
* \brief
* P7_CONTENT_INFO의 서명 생성 최종 절차 수행
* (OID_pkcs7_signedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# L_PKCS7^F_P7_SIGN^ISC_ERR_NULL_INPUT : p7이 NULL인 경우
* -# ISC_FAIL : 지원하지 않는 경우나 ISC_Update_RSASSA(), ISC_Final_RSASSA()에 실패한 경우
*/
ISC_API ISC_STATUS final_PKCS7_Sign(P7_CONTENT_INFO *p7);

/*!
* \brief
* P7_CONTENT_INFO의 서명 생성 최종 절차 수행
* (OID_pkcs7_signedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param pf_sign_cb 
* 실제로 서명을 수행할 콜백함수 (PKCS#11, PACCEL 연동을 위해)
* \return
* -# ISC_SUCCESS : 성공
* -# L_PKCS7^F_P7_SIGN^ISC_ERR_NULL_INPUT : p7이 NULL인 경우
* -# ISC_FAIL : 지원하지 않는 경우나 ISC_Update_RSASSA(), ISC_Final_RSASSA()에 실패한 경우
*/
ISC_API ISC_STATUS final_PKCS7_Sign_cb(P7_CONTENT_INFO *p7, PF_SIGN_CB pf_sign_cb);

/*!
* \brief
* P7_CONTENT_INFO의 서명 생성
* (OID_pkcs7_signedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param data
* 서명하려는 데이터
* \param dataLen
* 데이터의 길이
* \param detached
* detached가 0일경우 서명되는 데이터가 p7에 포함됨\n
* detached가 1일경우 서명되는 데이터가 p7의 외부에 있음을 가정
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS sign_PKCS7(P7_CONTENT_INFO *p7, uint8 *data, int dataLen, int detached);



/*!
* \brief
* P7_CONTENT_INFO의 서명 생성
* (OID_pkcs7_signedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param data
* 서명하려는 데이터
* \param dataLen
* 데이터의 길이
* \param detached
* detached가 0일경우 서명되는 데이터가 p7에 포함됨\n
* detached가 1일경우 서명되는 데이터가 p7의 외부에 있음을 가정
* \param pf_sign_cb
* 실제로 서명을 수행할 함수를 콜백으로 전달한다. (외부 crypto, hsm 연동시 사용)
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS sign_PKCS7_CB(P7_CONTENT_INFO *p7, uint8 *data, int dataLen, int detached, PF_SIGN_CB pf_sign_cb);

/*!
* \brief
* P7_CONTENT_INFO의 서명 검증
* (OID_pkcs7_signedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param x509
* 검증용 공개키가 포함된 인증서
* \param data
* 검증하려는 데이터 (p7이 안에 원본 데이터를 포함하고 있으면 NULL)
* \param dataLen 
* 데이터의 길이(p7이 안에 원본 데이터를 포함하고 있으면 0)
* 원문과 authenticatedAttributes 비교를 건너뛰고 싶으면 -1
* \return
* -# ISC_SUCCESS : 검증 통과 
* -# L_PKCS7^F_P7_VERIFY^ISC_ERR_NULL_INPUT : data와 dataLen이 NULL인경우
* -# L_PKCS7^F_P7_VERIFY^ISC_ERR_INVALID_INPUT : 해당하는 인증서가 없거나, 인증서는 있는데 키가 없거나 signer info가 없거나, digestAlg, encAlg가 없는 경우
* -# L_PKCS7^F_P7_VERIFY^ISC_ERR_VERIFY_FAILURE : 인증서가 아예 없는 경우
* -# ISC_FAIL : 서명검증에 실패했거나 그 이외의 오류
*/
ISC_API ISC_STATUS verify_PKCS7(P7_CONTENT_INFO *p7,X509_CERT *x509, uint8 *data, int dataLen);

/*!
* \brief
* P7_CONTENT_INFO의 서명 검증
* (OID_pkcs7_signedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param x509
* 검증용 공개키가 포함된 인증서
* \param data
* 검증하려는 데이터 (p7이 안에 원본 데이터를 포함하고 있으면 NULL)
* \param dataLen 
* 데이터의 길이(p7이 안에 원본 데이터를 포함하고 있으면 0)
* 원문과 authenticatedAttributes 비교를 건너뛰고 싶으면 -1
* \param pf_verify_cb
* 실제로 서명 검증을 수행할 함수를 콜백으로 전달한다. (PKCS#11, PACCEL 연동)
* \return
* -# ISC_SUCCESS : 검증 통과 
* -# L_PKCS7^F_P7_VERIFY^ISC_ERR_NULL_INPUT : data와 dataLen이 NULL인경우
* -# L_PKCS7^F_P7_VERIFY^ISC_ERR_INVALID_INPUT : 해당하는 인증서가 없거나, 인증서는 있는데 키가 없거나 signer info가 없거나, digestAlg, encAlg가 없는 경우
* -# L_PKCS7^F_P7_VERIFY^ISC_ERR_VERIFY_FAILURE : 인증서가 아예 없는 경우
* -# ISC_FAIL : 서명검증에 실패했거나 그 이외의 오류
*/
ISC_API ISC_STATUS verify_PKCS7_CB(P7_CONTENT_INFO *p7,X509_CERT *x509, uint8 *data, int dataLen, PF_VERIFY_CB pf_verify_cb );

/*!
* \brief
* P7_CONTENT_INFO의 SignedAndEnveloped 생성
* (OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param type_oid
* 암호화 되는 타입
* \param identifier
* 암호화 알고리즘이 지정된 Identifier
* \param data
* 데이터
* \param dataLen
* 데이터의 길이
* \param pk_encode
* 암호화시 설정할 encoding 값 설정
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS sign_encrypt_PKCS7(P7_CONTENT_INFO *p7,  int type_oid, X509_ALGO_IDENTIFIER *identifier, uint8 *data, int dataLen, int pk_encode);

/*!
* \brief
* P7_CONTENT_INFO의 SignedAndEnveloped 생성
* (OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param type_oid
* 암호화 되는 타입
* \param identifier
* 암호화 알고리즘이 지정된 Identifier
* \param data
* 데이터
* \param dataLen
* 데이터의 길이
* \param secretKey
* 암호화에 사용될 비밀키(Password)
* \para, KeyLen
* 비밀키의 길이
* \param iv
* 암호화에 사용될 초기백터(IV)
* \param pk_encode
* 암호화시 사용할 encoding 값 설정
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS sign_encrypt_PKCS7_userKEY(P7_CONTENT_INFO *p7,  int type_oid, X509_ALGO_IDENTIFIER *identifier, uint8 *in, int inLen, uint8 *secretKey, uint8 *iv, int pk_encode);

/*!
* \brief
* P7_CONTENT_INFO의 SignedAndEnveloped 생성(금결원지원용)
* (OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param type_oid
* 암호화 되는 타입
* \param identifier
* 암호화 알고리즘이 지정된 Identifier
* \param data
* 데이터
* \param dataLen
* 데이터의 길이
* \param pk_encode
* 암호화시 사용할 encoding 값 설정
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS sign_encrypt_PKCS7_SP(P7_CONTENT_INFO *p7,  int type_oid, X509_ALGO_IDENTIFIER *identifier, uint8 *data, int dataLen,int pk_encode);

/*!
* \brief
* P7_CONTENT_INFO의 SignedAndEnveloped 생성(금결원지원용)
* (OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param type_oid
* 암호화 되는 타입
* \param identifier
* 암호화 알고리즘이 지정된 Identifier
* \param data
* 데이터
* \param dataLen
* 데이터의 길이
* \param secretKey
* 암호화에 사용될 비밀키(Password)
* \para, KeyLen
* 비밀키의 길이
* \param iv
* 암호화에 사용될 초기백터(IV)
* \param pk_encode
* 암호화시 사용할 encoding 값 설정
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS sign_encrypt_PKCS7_userKEY_SP(P7_CONTENT_INFO *p7,  int type_oid, X509_ALGO_IDENTIFIER *identifier, uint8 *in, int inLen, uint8 *secretKey, uint8 *iv, int pk_encode);

/*!
* \brief
* P7_CONTENT_INFO의 SignedAndEnveloped 복호화하고 서명을 검증
* (OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param cert
* 서명 검증에 사용될 인증서 (decrypt_PKCS7_enveloped_CEK 함수 참조)
* \param cek
* 복호화에 사용될 Content Encryption Key
* \param out
* 복화화될 버퍼
* \param outLen
* 복호화될 버퍼 길이의 포인터
* \return
* -# 1 : 검증 통과
* -# -1 : 검증 실패
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS verify_decrypt_PKCS7(P7_CONTENT_INFO *p7, X509_CERT* cert, uint8 *cek, uint8 *out, int *outLen);

/*!
* \brief
* P7_CONTENT_INFO - SignedAndEnveloped 에 수신자에 해당하는 CEK를 복호화
* (OID_pkcs7_envelopedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
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
ISC_API ISC_STATUS decrypt_PKCS7_enveloped_CEK(P7_CONTENT_INFO *p7, X509_CERT *cert, ASYMMETRIC_KEY* priKey, uint8* cek, int *cekLen, int pk_decode);

/*!
* \brief
* P7_CONTENT_INFO의 암호화 모드 초기화\n
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
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
ISC_API ISC_STATUS init_PKCS7_Encrypt(P7_CONTENT_INFO *p7, int type_oid, X509_ALGO_IDENTIFIER *identifier, int detached, uint8 *secretKey, uint8 *iv, int pk_encode);

/*!
* \brief
* P7_CONTENT_INFO의 암호화 수행(Update)
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
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
ISC_API ISC_STATUS update_PKCS7_encrypt(P7_CONTENT_INFO *p7, uint8* in, int inLen, uint8 *out, int *outLen);

/*!
* \brief
* P7_CONTENT_INFO의 암호화 최종 절차 수행
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param out
* 출력되는 암호문의 버퍼
* \param outLen
* 버퍼의 길이 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS final_PKCS7_Encrypt(P7_CONTENT_INFO *p7, uint8 *out, int *outLen);

/*!
* \brief
* P7_CONTENT_INFO의 암호화 수행 (Detached mode는 지원 불가)
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
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
ISC_API ISC_STATUS encrypt_PKCS7(P7_CONTENT_INFO *p7,  int type_oid, X509_ALGO_IDENTIFIER *identifier,uint8 *in, int inLen, int pk_encode);

/*!
* \brief
* P7_CONTENT_INFO의 암호화 수행 (Detached mode는 지원 불가)
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
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
ISC_API ISC_STATUS encrypt_PKCS7_userKEY(P7_CONTENT_INFO *p7,  int type_oid, X509_ALGO_IDENTIFIER *identifier,uint8 *in, int inLen, uint8 *secretKey, uint8 *iv, int pk_encode);

/*!
* \brief
* P7_CONTENT_INFO의 복호화 수행 (Detached mode는 지원 불가)
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
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
ISC_API ISC_STATUS decrypt_PKCS7(P7_CONTENT_INFO *p7, uint8 *key, uint8 *iv, uint8 *out, int *outLen);

/*!
* \brief
* P7_CONTENT_INFO의 digestedData 생성
* (OID_pkcs7_digestedData)
* \param p7
* P7_CONTENT_INFO 구조체 포인터
* \param DigestID
* 다이제스트 알고리즘
* \param data
* 입력
* \param dataLen
* 입력의 길이
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS digest_PKCS7(P7_CONTENT_INFO *p7, int DigestID, uint8 *data, int dataLen);


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
ISC_API int cmp_P7_ISSUER_AND_SERIAL_NUMBER(X509_CERT *x509, ISSUER_AND_SERIAL_NUMBER *ias);

/*!
* \brief
* ISSUER_AND_SERIAL_NUMBER 구조체를 Sequence로 Encode 함수
* \param isAndSeNum
* ISSUER_AND_SERIAL_NUMBER 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_P7_IS_AND_SN_TO_SEQ^ISC_ERR_NULL_INPUT : 입력 파라미터가 NULL임
* -# LOCATION^F_P7_IS_AND_SN_TO_SEQ^ERR_ASN1_ENCODING : ASN1 에러
* -# X509_NAME_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS P7_ISSUER_AND_SERIAL_NUMBER_to_Seq(ISSUER_AND_SERIAL_NUMBER *isAndSeNum, SEQUENCE **seq);

/*!
* \brief
* Sequence를 ISSUER_AND_SERIAL_NUMBER 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param isAndSeNum
* ISSUER_AND_SERIAL_NUMBER 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_P7_IS_AND_SN^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_IS_AND_SN^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_IS_AND_SN^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_NAME()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_P7_ISSUER_AND_SERIAL_NUMBER(SEQUENCE *seq, ISSUER_AND_SERIAL_NUMBER **isAndSeNum);

/*!
* \brief
* P7_SIGNER_INFO 구조체를 Sequence로 Encode 함수
* \param signerInfo
* P7_SIGNER_INFO 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_P7_SIGNER_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_SIGNER_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P7_ISSUER_AND_SERIAL_NUMBER_to_Seq()의 에러 코드\n
* -# X509_ALGO_IDENTIFIER_to_Seq()의 에러 코드\n
* -# X509_ATTRIBUTES_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS P7_SIGNER_INFO_to_Seq(P7_SIGNER_INFO *signerInfo, SEQUENCE **seq);

/*!
* \brief
* Sequence를 P7_SIGNER_INFO 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param signerInfo
* P7_SIGNER_INFO 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_P7_SIGNER_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_SIGNER_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_SIGNER_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P7_ISSUER_AND_SERIAL_NUMBER()의 에러 코드\n
* -# Seq_to_X509_ALGO_IDENTIFIER()의 에러 코드\n
* -# Seq_to_X509_ATTRIBUTES()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_P7_SIGNER_INFO(SEQUENCE *seq, P7_SIGNER_INFO **signerInfo);

/*!
* \brief
* P7_DIGEST_INFO 구조체를 Sequence로 Encode 함수
* \param digestInfo
* P7_DIGEST_INFO 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_P7_DIGEST_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_DIGEST_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_ALGO_IDENTIFIER_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS P7_DIGEST_INFO_to_Seq(P7_DIGEST_INFO *digestInfo, SEQUENCE **seq);

/*!
* \brief
* Sequence를 P7_DIGEST_INFO 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param digestInfo
* P7_DIGEST_INFO 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_P7_DIGEST_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_DIGEST_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_DIGEST_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_ALGO_IDENTIFIER()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_P7_DIGEST_INFO(SEQUENCE *seq, P7_DIGEST_INFO **digestInfo);

/*!
* \brief
* P7_SIGNER_INFOS 구조체를 Sequence로 Encode 함수
* \param signerInfos
* P7_SIGNER_INFOS 구조체
* \param setOf
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_P7_SIGNER_INFOS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_SIGNER_INFOS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P7_SIGNER_INFO_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS P7_SIGNER_INFOS_to_Seq(P7_SIGNER_INFOS *signerInfos, SET_OF **setOf);

/*!
* \brief
* Sequence를 P7_SIGNER_INFOS 구조체로 Decode 함수
* \param setOf
* Decoding Sequence 구조체
* \param signerInfos
* P7_SIGNER_INFOS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_P7_SIGNER_INFOS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_SIGNER_INFOS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_SIGNER_INFOS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P7_SIGNER_INFO()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_P7_SIGNER_INFOS(SET_OF *setOf, P7_SIGNER_INFOS **signerInfos);

/*!
* \brief
* P7_SIGNED_DATA 구조체를 Sequence로 Encode 함수
* \param p7SignedData
* P7_SIGNED_DATA 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_P7_SIGNED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_SIGNED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_ALGO_IDENTIFIERS_to_Seq()의 에러 코드\n
* -# P7_CONTENT_INFO_to_Seq()의 에러 코드\n
* -# X509_CERTIFICATES_to_Seq()의 에러 코드\n
* -# X509_CRLS_to_Seq()의 에러 코드\n
* -# P7_SIGNER_INFOS_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS P7_SIGNED_DATA_to_Seq(P7_SIGNED_DATA *p7SignedData, SEQUENCE **seq);

/*!
* \brief
* Sequence를 P7_SIGNED_DATA 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param p7SignedData
* P7_SIGNED_DATA 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_P7_SIGNED_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_SIGNED_DATA^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_SIGNED_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_ALGO_IDENTIFIERS()의 에러 코드\n
* -# Seq_to_P7_CONTENT_INFO()의 에러 코드\n
* -# Seq_to_X509_CERTIFICATES()의 에러 코드\n
* -# Seq_to_X509_CRLS()의 에러 코드\n
* -# Seq_to_P7_SIGNER_INFOS()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_P7_SIGNED_DATA(SEQUENCE *seq, P7_SIGNED_DATA **p7SignedData);

/*!
* \brief
* P7_RECIPIENT_INFO 구조체를 Sequence로 Encode 함수
* \param recipientInfo
* P7_RECIPIENT_INFO 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_P7_RECIPIENT_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_RECIPIENT_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P7_ISSUER_AND_SERIAL_NUMBER_to_Seq()의 에러 코드\n
* -# X509_ALGO_IDENTIFIER_to_Seq()의 에러 코드\n

*/
ISC_API ISC_STATUS P7_RECIPIENT_INFO_to_Seq(P7_RECIPIENT_INFO *recipientInfo, SEQUENCE **seq);

/*!
* \brief
* Sequence를 P7_RECIPIENT_INFO 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param recipientInfo
* P7_RECIPIENT_INFO 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_P7_RECIPIENT_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_RECIPIENT_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_RECIPIENT_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P7_ISSUER_AND_SERIAL_NUMBER()의 에러 코드\n
* -# Seq_to_X509_ALGO_IDENTIFIER()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_P7_RECIPIENT_INFO(SEQUENCE *seq, P7_RECIPIENT_INFO **recipientInfo);

/*!
* \brief
* P7_RECIPIENT_INFOS 구조체를 Sequence로 Encode 함수
* \param recipientInfos
* P7_RECIPIENT_INFOS 구조체
* \param setOf
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_P7_RECIPIENT_INFOS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_RECIPIENT_INFOS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P7_RECIPIENT_INFO_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS P7_RECIPIENT_INFOS_to_Seq(P7_RECIPIENT_INFOS *recipientInfos, SET_OF **setOf);

/*!
* \brief
* Sequence를 P7_RECIPIENT_INFOS 구조체로 Decode 함수
* \param setOf
* Decoding Sequence 구조체
* \param recipientInfos
* P7_RECIPIENT_INFOS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_P7_RECIPIENT_INFOS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_RECIPIENT_INFOS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P7_RECIPIENT_INFO()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_P7_RECIPIENT_INFOS(SET_OF *setOf, P7_RECIPIENT_INFOS **recipientInfos);

/*!
* \brief
* P7_ENCRYPTED_CONTENT_INFO 구조체를 Sequence로 Encode 함수
* \param encContentInfo
* P7_ENCRYPTED_CONTENT_INFO 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_P7_ENCRYPTED_CONTENT_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_ENCRYPTED_CONTENT_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_ALGO_IDENTIFIER_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS P7_ENCRYPTED_CONTENT_INFO_to_Seq(P7_ENCRYPTED_CONTENT_INFO *encContentInfo, SEQUENCE **seq);
/*!
 * \brief
 * P7_ENCRYPTED_CONTENT_INFO 구조체를 Sequence로 Encode 함수
 * \param encContentInfo
 * P7_ENCRYPTED_CONTENT_INFO 구조체
 * \param seq
 * Encoding Sequence 구조체
 * \returns
 * -# ISC_SUCCESS : 성공
 * -# LOCATION^F_P7_ENCRYPTED_CONTENT_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
 * -# LOCATION^F_P7_ENCRYPTED_CONTENT_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
 * -# X509_ALGO_IDENTIFIER_to_Seq()의 에러 코드\n
 */
ISC_STATUS P7_ENCRYPTED_CONTENT_INFO_to_Seq_Scraping(P7_ENCRYPTED_CONTENT_INFO *encContentInfo, SEQUENCE **seq);
/*!
* \brief
* Sequence를 P7_ENCRYPTED_CONTENT_INFO 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param encContentInfo
* P7_ENCRYPTED_CONTENT_INFO 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_P7_ENCRYPTED_CONTENT_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_ENCRYPTED_CONTENT_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_ENCRYPTED_CONTENT_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_ALGO_IDENTIFIER()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_P7_ENCRYPTED_CONTENT_INFO(SEQUENCE *seq, P7_ENCRYPTED_CONTENT_INFO **encContentInfo);

/*!
* \brief
* P7_ENVELOPED_DATA 구조체를 Sequence로 Encode 함수
* \param p7EnvelopedData
* P7_ENVELOPED_DATA 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_P7_ENVELOPED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_ENVELOPED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P7_RECIPIENT_INFOS_to_Seq()의 에러 코드\n
* -# P7_ENCRYPTED_CONTENT_INFO_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS P7_ENVELOPED_DATA_to_Seq(P7_ENVELOPED_DATA *p7EnvelopedData, SEQUENCE **seq);
/*!
 * \brief
 * P7_ENVELOPED_DATA 구조체를 Sequence로 Encode 함수
 * \param p7EnvelopedData
 * P7_ENVELOPED_DATA 구조체
 * \param seq
 * Encoding Sequence 구조체
 * \returns
 * -# ISC_SUCCESS : 성공
 * -# LOCATION^F_P7_ENVELOPED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
 * -# LOCATION^F_P7_ENVELOPED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
 * -# P7_RECIPIENT_INFOS_to_Seq()의 에러 코드\n
 * -# P7_ENCRYPTED_CONTENT_INFO_to_Seq()의 에러 코드\n
 */
ISC_API ISC_STATUS P7_ENVELOPED_DATA_to_Seq_Scraping(P7_ENVELOPED_DATA *p7EnvelopedData, SEQUENCE **seq);

/*!
* \brief
* Sequence를 P7_ENVELOPED_DATA 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param p7EnvelopedData
* P7_ENVELOPED_DATA 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_P7_ENVELOPED_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_ENVELOPED_DATA^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_ENVELOPED_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P7_RECIPIENT_INFOS()의 에러 코드\n
* -# Seq_to_P7_ENCRYPTED_CONTENT_INFO()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_P7_ENVELOPED_DATA(SEQUENCE *seq, P7_ENVELOPED_DATA **p7EnvelopedData);

/*!
* \brief
* P7_SIGNED_AND_ENVELOPED_DATA 구조체를 Sequence로 Encode 함수
* \param p7SnEData
* P7_SIGNED_AND_ENVELOPED_DATA 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_P7_SIG_AND_ENV_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_SIG_AND_ENV_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P7_RECIPIENT_INFOS_to_Seq()의 에러 코드\n
* -# X509_ALGO_IDENTIFIERS_to_Seq()의 에러 코드\n
* -# P7_ENCRYPTED_CONTENT_INFO_to_Seq()의 에러 코드\n
* -# X509_CERTIFICATES_to_Seq()의 에러 코드\n
* -# X509_CRLS_to_Seq()의 에러 코드\n
* -# P7_SIGNER_INFOS_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS P7_SIGNED_AND_ENVELOPED_DATA_to_Seq(P7_SIGNED_AND_ENVELOPED_DATA *p7SnEData, SEQUENCE **seq);

/*!
* \brief
* Sequence를 P7_SIGNED_AND_ENVELOPED_DATA 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param p7SnEData
* P7_SIGNED_AND_ENVELOPED_DATA 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_P7_SIG_AND_ENV_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_SIG_AND_ENV_DATA^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_SIG_AND_ENV_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P7_RECIPIENT_INFOS()의 에러 코드\n
* -# Seq_to_X509_ALGO_IDENTIFIERS()의 에러 코드\n
* -# Seq_to_P7_ENCRYPTED_CONTENT_INFO()의 에러 코드\n
* -# Seq_to_X509_CERTIFICATES()의 에러 코드\n
* -# Seq_to_X509_CRLS()의 에러 코드\n
* -# Seq_to_P7_SIGNER_INFOS()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_P7_SIGNED_AND_ENVELOPED_DATA(SEQUENCE *seq, P7_SIGNED_AND_ENVELOPED_DATA **p7SnEData);

/*!
* \brief
* P7_DIGESTED_DATA 구조체를 Sequence로 Encode 함수
* \param p7DigestedData
* P7_DIGESTED_DATA 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_P7_DIGESTED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_DIGESTED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_ALGO_IDENTIFIER_to_Seq()의 에러 코드\n
* -# P7_CONTENT_INFO_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS P7_DIGESTED_DATA_to_Seq(P7_DIGESTED_DATA *p7DigestedData, SEQUENCE **seq);

/*!
* \brief
* Sequence를 P7_DIGESTED_DATA 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param p7DigestedData
* P7_DIGESTED_DATA 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_P7_DIGESTED_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_DIGESTED_DATA^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_DIGESTED_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_ALGO_IDENTIFIER()의 에러 코드\n
* -# Seq_to_P7_CONTENT_INFO()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_P7_DIGESTED_DATA(SEQUENCE *seq, P7_DIGESTED_DATA **p7DigestedData);

/*!
* \brief
* P7_ENCRYPTED_DATA 구조체를 Sequence로 Encode 함수
* \param p7EncryptedData
* P7_ENCRYPTED_DATA 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_P7_ENCRYPTED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_ENCRYPTED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P7_ENCRYPTED_CONTENT_INFO_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS P7_ENCRYPTED_DATA_to_Seq(P7_ENCRYPTED_DATA *p7EncryptedData, SEQUENCE **seq);

/*!
* \brief
* Sequence를 P7_ENCRYPTED_DATA 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param p7EncryptedData
* P7_ENCRYPTED_DATA 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_P7_ENCRYPTED_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_ENCRYPTED_DATA^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_ENCRYPTED_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P7_ENCRYPTED_CONTENT_INFO()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_P7_ENCRYPTED_DATA(SEQUENCE *seq, P7_ENCRYPTED_DATA **p7EncryptedData);

/*!
* \brief
* P7_CONTENT_INFO 구조체를 Sequence로 Encode 함수
* \param p7ContentInfo
* P7_CONTENT_INFO 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_P7_CONTENT_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_CONTENT_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P7_SIGNED_DATA_to_Seq()의 에러 코드\n
* -# P7_ENVELOPED_DATA_to_Seq()의 에러 코드\n
* -# P7_SIGNED_AND_ENVELOPED_DATA_to_Seq()의 에러 코드\n
* -# P7_DIGESTED_DATA_to_Seq()의 에러 코드\n
* -# P7_ENCRYPTED_DATA_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS P7_CONTENT_INFO_to_Seq(P7_CONTENT_INFO *p7ContentInfo, SEQUENCE **seq);
/*!
 * \brief
 * P7_CONTENT_INFO 구조체를 Sequence로 Encode 함수
 * \param p7ContentInfo
 * P7_CONTENT_INFO 구조체
 * \param seq
 * Encoding Sequence 구조체
 * \returns
 * -# ISC_SUCCESS : 성공
 * -# LOCATION^F_P7_CONTENT_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
 * -# LOCATION^F_P7_CONTENT_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
 * -# P7_SIGNED_DATA_to_Seq()의 에러 코드\n
 * -# P7_ENVELOPED_DATA_to_Seq()의 에러 코드\n
 * -# P7_SIGNED_AND_ENVELOPED_DATA_to_Seq()의 에러 코드\n
 * -# P7_DIGESTED_DATA_to_Seq()의 에러 코드\n
 * -# P7_ENCRYPTED_DATA_to_Seq()의 에러 코드\n
 */
ISC_API ISC_STATUS P7_CONTENT_INFO_to_Seq_Scraping(P7_CONTENT_INFO *p7ContentInfo, SEQUENCE **seq);

/*!
* \brief
* Sequence를 P7_CONTENT_INFO 구조체로 Decode 함수
* \param seq
* Decoding Sequence 구조체
* \param p7ContentInfo
* P7_CONTENT_INFO 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_P7_CONTENT_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_CONTENT_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_CONTENT_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P7_SIGNED_DATA()의 에러 코드\n
* -# Seq_to_P7_ENVELOPED_DATA()의 에러 코드\n
* -# Seq_to_P7_SIGNED_AND_ENVELOPED_DATA()의 에러 코드\n
* -# Seq_to_P7_DIGESTED_DATA()의 에러 코드\n
* -# Seq_to_P7_ENCRYPTED_DATA()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_P7_CONTENT_INFO(SEQUENCE *seq, P7_CONTENT_INFO **p7ContentInfo);

/*!
* \brief
* P7_CONTENT_INFO 구조체의버전정보를설정함
* \param p7
* P7_CONTENT_INFO 구조체
* \param version
* 설정할버전
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_P7_version(P7_CONTENT_INFO *p7, uint32 version);

#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(ISSUER_AND_SERIAL_NUMBER*, new_P7_ISSUER_AND_SERIAL_NUMBER, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P7_ISSUER_AND_SERIAL_NUMBER, (ISSUER_AND_SERIAL_NUMBER *issuerAndSerial), (issuerAndSerial) );
INI_RET_LOADLIB_PKI(P7_SIGNER_INFO*, new_P7_SIGNER_INFO, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P7_SIGNER_INFO, (P7_SIGNER_INFO *signerInfo), (signerInfo) );
INI_RET_LOADLIB_PKI(P7_DIGEST_INFO*, new_P7_DIGEST_INFO, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P7_DIGEST_INFO, (P7_DIGEST_INFO *digestInfo), (digestInfo) );
INI_RET_LOADLIB_PKI(P7_SIGNER_INFOS*, new_P7_SIGNER_INFOS, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P7_SIGNER_INFOS, (P7_SIGNER_INFOS *signerInfos), (signerInfos) );
INI_RET_LOADLIB_PKI(P7_SIGNED_DATA*, new_P7_SIGNED_DATA, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P7_SIGNED_DATA, (P7_SIGNED_DATA *pkcs7SignedData), (pkcs7SignedData) );
INI_RET_LOADLIB_PKI(P7_RECIPIENT_INFO*, new_P7_RECIPIENT_INFO, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P7_RECIPIENT_INFO, (P7_RECIPIENT_INFO *recipientInfo), (recipientInfo) );
INI_RET_LOADLIB_PKI(P7_RECIPIENT_INFOS*, new_P7_RECIPIENT_INFOS, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P7_RECIPIENT_INFOS, (P7_RECIPIENT_INFOS *recipientInfos), (recipientInfos) );
INI_RET_LOADLIB_PKI(P7_ENCRYPTED_CONTENT_INFO*, new_P7_ENCRYPTED_CONTENT_INFO, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P7_ENCRYPTED_CONTENT_INFO, (P7_ENCRYPTED_CONTENT_INFO *encryptedContentInfo), (encryptedContentInfo) );
INI_RET_LOADLIB_PKI(P7_ENVELOPED_DATA*, new_P7_ENVELOPED_DATA, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P7_ENVELOPED_DATA, (P7_ENVELOPED_DATA *pkcs7EnvelopedData), (pkcs7EnvelopedData) );
INI_RET_LOADLIB_PKI(P7_SIGNED_AND_ENVELOPED_DATA*, new_P7_SIGNED_AND_ENVELOPED_DATA, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P7_SIGNED_AND_ENVELOPED_DATA, (P7_SIGNED_AND_ENVELOPED_DATA *pkcs7SignedAndEnvelopedData), (pkcs7SignedAndEnvelopedData) );
INI_RET_LOADLIB_PKI(P7_DIGESTED_DATA*, new_P7_DIGESTED_DATA, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P7_DIGESTED_DATA, (P7_DIGESTED_DATA *pkcs7DigestedData), (pkcs7DigestedData) );
INI_RET_LOADLIB_PKI(P7_ENCRYPTED_DATA*, new_P7_ENCRYPTED_DATA, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P7_ENCRYPTED_DATA, (P7_ENCRYPTED_DATA *pkcs7EncryptedData), (pkcs7EncryptedData) );
INI_RET_LOADLIB_PKI(P7_CONTENT_INFO*, new_P7_CONTENT_INFO, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P7_CONTENT_INFO, (P7_CONTENT_INFO *pkcs7ContentInfo), (pkcs7ContentInfo) );
INI_RET_LOADLIB_PKI(ISC_STATUS, new_PKCS7_Content, (P7_CONTENT_INFO *p7, int type), (p7,type), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_PKCS7_Type, (P7_CONTENT_INFO *p7, int type), (p7,type), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_PKCS7_Content, (P7_CONTENT_INFO *p7, P7_CONTENT_INFO *p7_data), (p7,p7_data), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_PKCS7_P7_RECIPIENT_INFO, (P7_RECIPIENT_INFO *p7i, X509_CERT *x509, int pk_encode, void *alg_param), (p7i,x509,pk_encode,alg_param), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_PKCS7_Cipher, (P7_CONTENT_INFO *p7, ISC_BLOCK_CIPHER_UNIT* cipher), (p7,cipher), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_PKCS7_P7_ENCRYPTED_CONTENT_INFO, (P7_ENCRYPTED_CONTENT_INFO *enc_inf, int type_oid, X509_ALGO_IDENTIFIER *algorithm, uint8* encData, int encDataLen), (enc_inf,type_oid,algorithm,encData,encDataLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_PKCS7_ENCRYPTED_CONTENT_length, (P7_CONTENT_INFO *p7), (p7), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, gen_PKCS7_DATA_from_Binary, (P7_CONTENT_INFO **p7_data, uint8* data, int dataLen), (p7_data,data,dataLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_PKCS7_P7_SIGNER_INFO, (P7_SIGNER_INFO *p7i, X509_CERT *x509, ASYMMETRIC_KEY *pkey, int digestOID, int pk_encode, void *alg_param), (p7i,x509,pkey,digestOID,pk_encode,alg_param), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_PKCS7_Signer, (P7_CONTENT_INFO *p7, P7_SIGNER_INFO *p7i), (p7,p7i), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_PKCS7_Certificate, (P7_CONTENT_INFO *p7, X509_CERT *x509), (p7,x509), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_PKCS7_Crl, (P7_CONTENT_INFO *p7, X509_CRL *crl), (p7,crl), ISC_FAIL);
INI_RET_LOADLIB_PKI(P7_SIGNER_INFO*, add_PKCS7_Signature, (P7_CONTENT_INFO *p7, X509_CERT *x509, ASYMMETRIC_KEY *pkey, int digestOID), (p7,x509,pkey,digestOID), NULL);
INI_RET_LOADLIB_PKI(P7_SIGNER_INFO*, add_PKCS7_Signature_withEncryptedAlgorithm, (P7_CONTENT_INFO *p7, X509_CERT *x509, ASYMMETRIC_KEY *pkey, int digestOID, int pk_encode, void *alg_param), (p7,x509,pkey,digestOID,pk_encode,alg_param), NULL);
INI_RET_LOADLIB_PKI(P7_RECIPIENT_INFO*, add_PKCS7_Recipient, (P7_CONTENT_INFO *p7, X509_CERT *x509), (p7,x509), NULL);
INI_RET_LOADLIB_PKI(P7_RECIPIENT_INFO*, add_PKCS7_Recipient_withEncryptedAlgorithm, (P7_CONTENT_INFO *p7, X509_CERT *x509, int pk_encode, void *alg_param), (p7,x509,pk_encode,alg_param), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_PKCS7_P7_RECIPIENT_INFO, (P7_CONTENT_INFO *p7, P7_RECIPIENT_INFO *ri), (p7,ri), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_PKCS7_Signed_Attribute, (P7_SIGNER_INFO *p7si, int oid, int atrtype, uint8 *value, int valueLen), (p7si,oid,atrtype,value,valueLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_PKCS7_Unauthenticated_Attribute, (P7_SIGNER_INFO *p7si, int oid, int atrtype, uint8 *value, int valueLen), (p7si,oid,atrtype,value,valueLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, find_PKCS7_Signed_Attribute, (P7_SIGNER_INFO *p7si, int oid, int atrtype, void** found_not_free), (p7si,oid,atrtype,found_not_free), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, find_PKCS7_Unauthenticated_Attribute, (P7_SIGNER_INFO *p7si, int oid, int atrtype, void** found_not_free), (p7si,oid,atrtype,found_not_free), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, init_PKCS7_Sign, (P7_CONTENT_INFO *p7,int detached), (p7,detached), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, init_PKCS7_Sign_cb, (P7_CONTENT_INFO *p7,int detached, PF_SIGN_CB pf_sign_cb), (p7,detached,pf_sign_cb), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, update_PKCS7_Sign, (P7_CONTENT_INFO *p7, uint8* data, int dataLen), (p7,data,dataLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, final_PKCS7_Sign, (P7_CONTENT_INFO *p7), (p7), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, final_PKCS7_Sign_cb, (P7_CONTENT_INFO *p7, PF_SIGN_CB pf_sign_cb), (p7, pf_sign_cb), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, sign_PKCS7, (P7_CONTENT_INFO *p7, uint8 *data, int dataLen, int detached), (p7,data,dataLen,detached), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, sign_PKCS7_CB, (P7_CONTENT_INFO *p7, uint8 *data, int dataLen, int detached, PF_SIGN_CB pf_sign_cb), (p7,data,dataLen,detached,pf_sign_cb), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, verify_PKCS7, (P7_CONTENT_INFO *p7,X509_CERT *x509, uint8 *data, int dataLen), (p7,x509,data,dataLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, verify_PKCS7_CB, (P7_CONTENT_INFO *p7,X509_CERT *x509, uint8 *data, int dataLen, PF_VERIFY_CB pf_verify_cb), (p7,x509,data,dataLen, pf_verify_cb), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, sign_encrypt_PKCS7, (P7_CONTENT_INFO *p7, int type_oid, X509_ALGO_IDENTIFIER *identifier, uint8 *data, int dataLen, int pk_encode), (p7,type_oid,identifier,data,dataLen,pk_encode), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, sign_encrypt_PKCS7_userKEY, (P7_CONTENT_INFO *p7, int type_oid, X509_ALGO_IDENTIFIER *identifier, uint8 *in, int inLen, uint8 *secretKey, uint8 *iv, int pk_encode), (p7,type_oid,identifier,in,inLen,secretKey,iv,pk_encode), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, sign_encrypt_PKCS7_SP, (P7_CONTENT_INFO *p7, int type_oid, X509_ALGO_IDENTIFIER *identifier, uint8 *data, int dataLen,int pk_encode), (p7,type_oid,identifier,data,dataLen,pk_encode), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, sign_encrypt_PKCS7_userKEY_SP, (P7_CONTENT_INFO *p7, int type_oid, X509_ALGO_IDENTIFIER *identifier, uint8 *in, int inLen, uint8 *secretKey, uint8 *iv, int pk_encode), (p7,type_oid,identifier,in,inLen,secretKey,iv,pk_encode), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, verify_decrypt_PKCS7, (P7_CONTENT_INFO *p7, X509_CERT* cert, uint8 *cek, uint8 *out, int *outLen), (p7,cert,cek,out,outLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, decrypt_PKCS7_enveloped_CEK, (P7_CONTENT_INFO *p7, X509_CERT *cert, ASYMMETRIC_KEY* priKey, uint8* cek, int *cekLen, int pk_decode), (p7,cert,priKey,cek,cekLen,pk_decode), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, init_PKCS7_Encrypt, (P7_CONTENT_INFO *p7, int type_oid, X509_ALGO_IDENTIFIER *identifier, int detached, uint8 *secretKey, uint8 *iv, int pk_encode), (p7,type_oid,identifier,detached,secretKey,iv,pk_encode), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, update_PKCS7_encrypt, (P7_CONTENT_INFO *p7, uint8* in, int inLen, uint8 *out, int *outLen), (p7,in,inLen,out,outLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, final_PKCS7_Encrypt, (P7_CONTENT_INFO *p7, uint8 *out, int *outLen), (p7,out,outLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encrypt_PKCS7, (P7_CONTENT_INFO *p7, int type_oid, X509_ALGO_IDENTIFIER *identifier,uint8 *in, int inLen, int pk_encode), (p7,type_oid,identifier,in,inLen,pk_encode), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encrypt_PKCS7_userKEY, (P7_CONTENT_INFO *p7, int type_oid, X509_ALGO_IDENTIFIER *identifier,uint8 *in, int inLen, uint8 *secretKey, uint8 *iv, int pk_encode), (p7,type_oid,identifier,in,inLen,secretKey,iv,pk_encode), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, decrypt_PKCS7, (P7_CONTENT_INFO *p7, uint8 *key, uint8 *iv, uint8 *out, int *outLen), (p7,key,iv,out,outLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, digest_PKCS7, (P7_CONTENT_INFO *p7, int DigestID, uint8 *data, int dataLen), (p7,DigestID,data,dataLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, cmp_P7_ISSUER_AND_SERIAL_NUMBER, (X509_CERT *x509, ISSUER_AND_SERIAL_NUMBER *ias), (x509,ias), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P7_ISSUER_AND_SERIAL_NUMBER_to_Seq, (ISSUER_AND_SERIAL_NUMBER *isAndSeNum, SEQUENCE **seq), (isAndSeNum,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P7_ISSUER_AND_SERIAL_NUMBER, (SEQUENCE *seq, ISSUER_AND_SERIAL_NUMBER **isAndSeNum), (seq,isAndSeNum), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P7_SIGNER_INFO_to_Seq, (P7_SIGNER_INFO *signerInfo, SEQUENCE **seq), (signerInfo,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P7_SIGNER_INFO, (SEQUENCE *seq, P7_SIGNER_INFO **signerInfo), (seq,signerInfo), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P7_DIGEST_INFO_to_Seq, (P7_DIGEST_INFO *digestInfo, SEQUENCE **seq), (digestInfo,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P7_DIGEST_INFO, (SEQUENCE *seq, P7_DIGEST_INFO **digestInfo), (seq,digestInfo), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P7_SIGNER_INFOS_to_Seq, (P7_SIGNER_INFOS *signerInfos, SET_OF **setOf), (signerInfos,setOf), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P7_SIGNER_INFOS, (SET_OF *setOf, P7_SIGNER_INFOS **signerInfos), (setOf,signerInfos), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P7_SIGNED_DATA_to_Seq, (P7_SIGNED_DATA *p7SignedData, SEQUENCE **seq), (p7SignedData,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P7_SIGNED_DATA, (SEQUENCE *seq, P7_SIGNED_DATA **p7SignedData), (seq,p7SignedData), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P7_RECIPIENT_INFO_to_Seq, (P7_RECIPIENT_INFO *recipientInfo, SEQUENCE **seq), (recipientInfo,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P7_RECIPIENT_INFO, (SEQUENCE *seq, P7_RECIPIENT_INFO **recipientInfo), (seq,recipientInfo), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P7_RECIPIENT_INFOS_to_Seq, (P7_RECIPIENT_INFOS *recipientInfos, SET_OF **setOf), (recipientInfos,setOf), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P7_RECIPIENT_INFOS, (SET_OF *setOf, P7_RECIPIENT_INFOS **recipientInfos), (setOf,recipientInfos), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P7_ENCRYPTED_CONTENT_INFO_to_Seq, (P7_ENCRYPTED_CONTENT_INFO *encContentInfo, SEQUENCE **seq), (encContentInfo,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P7_ENCRYPTED_CONTENT_INFO, (SEQUENCE *seq, P7_ENCRYPTED_CONTENT_INFO **encContentInfo), (seq,encContentInfo), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P7_ENVELOPED_DATA_to_Seq, (P7_ENVELOPED_DATA *p7EnvelopedData, SEQUENCE **seq), (p7EnvelopedData,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P7_ENVELOPED_DATA, (SEQUENCE *seq, P7_ENVELOPED_DATA **p7EnvelopedData), (seq,p7EnvelopedData), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P7_SIGNED_AND_ENVELOPED_DATA_to_Seq, (P7_SIGNED_AND_ENVELOPED_DATA *p7SnEData, SEQUENCE **seq), (p7SnEData,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P7_SIGNED_AND_ENVELOPED_DATA, (SEQUENCE *seq, P7_SIGNED_AND_ENVELOPED_DATA **p7SnEData), (seq,p7SnEData), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P7_DIGESTED_DATA_to_Seq, (P7_DIGESTED_DATA *p7DigestedData, SEQUENCE **seq), (p7DigestedData,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P7_DIGESTED_DATA, (SEQUENCE *seq, P7_DIGESTED_DATA **p7DigestedData), (seq,p7DigestedData), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P7_ENCRYPTED_DATA_to_Seq, (P7_ENCRYPTED_DATA *p7EncryptedData, SEQUENCE **seq), (p7EncryptedData,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P7_ENCRYPTED_DATA, (SEQUENCE *seq, P7_ENCRYPTED_DATA **p7EncryptedData), (seq,p7EncryptedData), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P7_CONTENT_INFO_to_Seq, (P7_CONTENT_INFO *p7ContentInfo, SEQUENCE **seq), (p7ContentInfo,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P7_CONTENT_INFO, (SEQUENCE *seq, P7_CONTENT_INFO **p7ContentInfo), (seq,p7ContentInfo), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_P7_version, (P7_CONTENT_INFO *p7, uint32 version), (p7,version), ISC_FAIL);

#endif

#ifdef  __cplusplus
}
#endif
#endif /* HEADER_PKCS7_H */

