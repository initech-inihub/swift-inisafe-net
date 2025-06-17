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
* PKCS7 SIGNER INFO�� ������ �����ϴ� ����ü
*/
typedef struct P7_SIGNER_INFO_st {
	INTEGER 					*version;					/*!< Version = 1*/			
	ISSUER_AND_SERIAL_NUMBER	*issuerAndSerialNumber;		/*!< ISSUER_AND_SERIAL_NUMBER ����ü�� ������*/	
	X509_ALGO_IDENTIFIER		*digestAlgorithm;			/*!< �ؽ� �˰���*/		
	X509_ATTRIBUTES				*authenticatedAttributes;	/*!< ������ �Ӽ�����(IMPLICIT SET OF Context Specific 0 OPTIONAL)*/
	X509_ALGO_IDENTIFIER		*digestEncryptionAlgorithm;	/*!< �ؽ�-��ȣȭ �˰���*/
	OCTET_STRING				*encryptedDigest;			/*!< ��ȣȭ�� �ؽ� ��*/
	X509_ATTRIBUTES				*unauthenticatedAttributes;	/*!< �������� ���� �Ӽ�����(IMPLICIT SET OF Context Specific 1 OPTIONAL)*/	
	ASYMMETRIC_KEY				*signKey;					/*!< ���ο� ���Ǵ� Ű*/
} P7_SIGNER_INFO;



/*!
* \brief
* ISC_DIGEST-Encryption�� ��� ���� �����ϴ� ����ü
*/
typedef struct pkcs7_P7_DIGEST_INFO_st {
	X509_ALGO_IDENTIFIER		*digestAlgorithm;	/*!< �ؽ� �˰���*/
	OCTET_STRING				*digest;			/*!< �ؽ� ��*/
} P7_DIGEST_INFO;

/*!
* \brief
* SIGNER_INFO ����ü ����(SET OF)�� ������
*/
typedef STK(P7_SIGNER_INFO) P7_SIGNER_INFOS;

/*!
* \brief
* PKCS7 SIGNED DATA�� ������ �����ϴ� ����ü
*/
typedef struct P7_SIGNED_DATA_st {
	INTEGER							*version;			/*!< Version = 1*/
	X509_ALGO_IDENTIFIERS			*digestAlgorithms;	/*!< �ؽ� �˰����(SET OF) */
	struct P7_CONTENT_INFO_st		*contentInfo;		/*!< P7_CONTENT_INFO ����ü�� ������*/
	X509_CERTS						*certificates;		/*!< X509 ��������(IMPLICIT SET OF Context Specific 0 OPTIONAL)*/
	X509_CRLS						*crls;				/*!< X509 CRL��(IMPLICIT SET OF Context Specific 1 OPTIONAL)*/
	P7_SIGNER_INFOS					*signerInfos;	    /*!< P7_SIGNER_INFOS ����ü ������ ������(SET OF)*/
	int								detached;			/*!< 0:DER�� ���ڵ��� �� ����, 1:�� �� ���� */
} P7_SIGNED_DATA;

/*!
* \brief
* PKCS7 RECIPIENT INFO�� ������ �����ϴ� ����ü
*/
typedef struct P7_RECIPIENT_INFO_st {
	INTEGER						*version;					/*!< Version = 0 */
	ISSUER_AND_SERIAL_NUMBER	*issuerAndSerialNumber;		/*!< ISSUER_AND_SERIAL_NUMBER ����ü�� ������*/
	X509_ALGO_IDENTIFIER		*keyEncryptionAlgorithm;	/*!< Ű ��ȣȭ �˰���*/
	OCTET_STRING				*encryptedKey;				/*!< ��ȣȭ�� Ű�� ��*/
	ASYMMETRIC_KEY				*pubKey;					/*!< ��ȣȭ�� ���Ǵ� ����Ű*/
} P7_RECIPIENT_INFO;

/*!
* \brief
* RECIPIENT_INFO ����ü ����(SET OF)�� ������
*/
typedef STK(P7_RECIPIENT_INFO) P7_RECIPIENT_INFOS;

/*!
* \brief
* PKCS7 ENCRYPTED CONTENT INFO�� ������ �����ϴ� ����ü
*/
typedef struct P7_ENCRYPTED_CONTENT_INFO_st {
	OBJECT_IDENTIFIER		*contentType;					/*!< Content�� Ÿ��(OID)*/
	X509_ALGO_IDENTIFIER	*contentEncryptionAlgorithm;	/*!< Content ��ȣȭ �˰���*/
	OCTET_STRING			*encryptedContent;				/*!< ��ȣȭ�� Content(IMPLICIT Context Specific 0 OPTIONAL)*/
	ISC_BLOCK_CIPHER_UNIT		*cipher;						/*!< ISC_BLOCK_CIPHER_UNIT ����ü�� ������*/
} P7_ENCRYPTED_CONTENT_INFO;

/*!
* \brief
* PKCS7 ENVELOPED DATA�� ������ �����ϴ� ����ü
*/
typedef struct P7_ENVELOPED_DATA_st {
	INTEGER						*version;					/*!< Version = 0 */
	P7_RECIPIENT_INFOS			*recipientInfos;			/*!< P7_RECIPIENT_INFOS ����ü ������ ������(SET OF)*/
	P7_ENCRYPTED_CONTENT_INFO	*encryptedContentInfo;		/*!< P7_ENCRYPTED_CONTENT_INFO ����ü�� ������*/
	int							detached;					/*!< 0:DER�� ���ڵ��� ��ȣ�� ����, 1:��ȣ�� �� ����*/
} P7_ENVELOPED_DATA;

/*!
* \brief
* PKCS7 SIGNED AND ENVELOPED DATA�� ������ �����ϴ� ����ü
*/
typedef struct P7_SIGNED_AND_ENVELOPED_DATA_st {
	INTEGER						*version;				/*!< Version = 1 */
	P7_RECIPIENT_INFOS			*recipientInfos;		/*!< P7_RECIPIENT_INFOS ����ü ������ ������(SET OF)*/
	X509_ALGO_IDENTIFIERS		*digestAlgorithms;		/*!< �ؽ� �˰����(SET OF)*/
	P7_ENCRYPTED_CONTENT_INFO	*encryptedContentInfo;	/*!< P7_ENCRYPTED_CONTENT_INFO ����ü�� ������*/
	X509_CERTS					*certificates;			/*!< X509 ��������(IMPLICIT SET OF Context Specific 0 OPTIONAL)*/
	X509_CRLS					*crls;					/*!< X509 CRL��(IMPLICIT SET OF Context Specific 1 OPTIONAL)*/
	P7_SIGNER_INFOS				*signerInfos;			/*!< P7_SIGNER_INFOS ����ü ������ ������(SET OF)*/
} P7_SIGNED_AND_ENVELOPED_DATA;

/*!
* \brief
* PKCS7 DIGESTED DATA�� ������ �����ϴ� ����ü
*/
typedef struct P7_DIGESTED_DATA_st {
	INTEGER							*version;			/*!< Version = 0 */
	X509_ALGO_IDENTIFIER			*digestAlgorithm;	/*!< �ؽ� �˰���*/
	struct P7_CONTENT_INFO_st		*contentInfo;		/*!< P7_CONTENT_INFO ����ü�� ������*/
	OCTET_STRING					*digest;			/*!< �ؽ� ��*/
} P7_DIGESTED_DATA;

/*!
* \brief
* PKCS7 ENCRYPTED DATA�� ������ �����ϴ� ����ü
*/
typedef struct P7_ENCRYPTED_DATA_st {
	INTEGER						*version;				/*!< Version  = 0 */
	P7_ENCRYPTED_CONTENT_INFO	*encryptedContentInfo;	/*!< P7_ENCRYPTED_CONTENT_INFO ����ü�� ������*/
	int							detached;				/*!< 0:DER�� ���ڵ��� ��ȣ�� ����, 1:��ȣ�� �� ����*/
} P7_ENCRYPTED_DATA;

/*!
* \brief
* PKCS7 CONTENT INFO�� ������ �����ϴ� ����ü
*/
typedef struct P7_CONTENT_INFO_st {
	OBJECT_IDENTIFIER					*contentType;				/*!< Content�� Ÿ��(OID)*/
	union {
		OCTET_STRING					*data;						/*!< OCTET_STRING ����ü�� ������*/
		P7_SIGNED_DATA					*signedData;				/*!< P7_SIGNED_DATA ����ü�� ������*/
		P7_ENVELOPED_DATA				*envelopedData;				/*!< P7_ENVELOPED_DATA ����ü�� ������*/
		P7_SIGNED_AND_ENVELOPED_DATA	*SignedAndEnvelopedData;	/*!< P7_SIGNED_AND_ENVELOPED_DATA ����ü�� ������*/
		P7_DIGESTED_DATA				*digestedData;				/*!< P7_DIGESTED_DATA ����ü�� ������*/
		P7_ENCRYPTED_DATA				*encryptedData;				/*!< P7_ENCRYPTED_DATA ����ü�� ������*/
		CERT_TRUST_LIST					*ctlData;					/*!< CTL DATA ����ü ������ �߰� (for CPV) */
	} content;														/*!< Content ����ü(EXLICIT Context Specific 0 OPTIONAL)*/
} P7_CONTENT_INFO;

/*!
* \brief
* P7_CONTENT_INFO����ü�� Content�� PKCS7 SIGNED DATA���� Ȯ���ϴ� ��ũ�� �Լ�
* \param a
* P7_CONTENT_INFO ����ü�� ������
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_PKCS7_signed(a)				(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_signedData)
/*!
* \brief
* P7_CONTENT_INFO����ü�� Content�� PKCS7 ENCRYPTED DATA���� Ȯ���ϴ� ��ũ�� �Լ�
* \param a
* P7_CONTENT_INFO ����ü�� ������
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_PKCS7_encrypted(a)			(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_encryptedData)
/*!
* \brief
* P7_CONTENT_INFO����ü�� Content�� PKCS7 ENVELOPED DATA���� Ȯ���ϴ� ��ũ�� �Լ�
* \param a
* P7_CONTENT_INFO ����ü�� ������
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_PKCS7_enveloped(a)			(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_envelopedData)
/*!
* \brief
* P7_CONTENT_INFO����ü�� Content�� PKCS7 SIGNED AND ENVELOPED DATA���� Ȯ���ϴ� ��ũ�� �Լ�
* \param a
* P7_CONTENT_INFO ����ü�� ������
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_PKCS7_signedAndEnveloped(a)	(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_signedAndEnvelopedData)
/*!
* \brief
* P7_CONTENT_INFO����ü�� Content�� PKCS7 DATA���� Ȯ���ϴ� ��ũ�� �Լ�
* \param a
* P7_CONTENT_INFO ����ü�� ������
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_PKCS7_data(a)				(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_data)
/*!
* \brief
* P7_CONTENT_INFO����ü�� Content�� PKCS7 DIGESTED DATA���� Ȯ���ϴ� ��ũ�� �Լ�
* \param a
* P7_CONTENT_INFO ����ü�� ������
* \return
* -# 1 : TRUE
* -# 0 : FALSE
*/
#define is_PKCS7_digest(a)				(index_from_OBJECT_IDENTIFIER((a)->contentType) == OID_pkcs7_digestData)

#define PKCS7_DETACHED		 1   /*!< */ /* �Է��� �� �������� ��� ������ ������ �������� �ʰ�, ��ȣȭ�� ��ȣ���� ����� der�� ���Խ�Ű�� ����*/
#define PKCS7_DEFAULT		 0	 /*!< */

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* ISSUER_AND_SERIAL_NUMBER ����ü�� �ʱ�ȭ �Լ�
* \returns
* ISSUER_AND_SERIAL_NUMBER ����ü ������
*/
ISC_API ISSUER_AND_SERIAL_NUMBER *new_P7_ISSUER_AND_SERIAL_NUMBER(void);

/*!
* \brief
* ISSUER_AND_SERIAL_NUMBER ����ü�� �޸� �Ҵ� ����
* \param issuerAndSerial
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P7_ISSUER_AND_SERIAL_NUMBER(ISSUER_AND_SERIAL_NUMBER *issuerAndSerial);

/*!
* \brief
* P7_SIGNER_INFO ����ü�� �ʱ�ȭ �Լ�
* \returns
* P7_SIGNER_INFO ����ü ������
*/
ISC_API P7_SIGNER_INFO *new_P7_SIGNER_INFO(void);

/*!
* \brief
* P7_SIGNER_INFO ����ü�� �޸� �Ҵ� ����
* \param signerInfo
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P7_SIGNER_INFO(P7_SIGNER_INFO *signerInfo);

/*!
* \brief
* P7_DIGEST_INFO ����ü�� �ʱ�ȭ �Լ�
* \returns
* P7_DIGEST_INFO ����ü ������
*/
ISC_API P7_DIGEST_INFO *new_P7_DIGEST_INFO(void);

/*!
* \brief
* P7_DIGEST_INFO ����ü�� �޸� �Ҵ� ����
* \param digestInfo
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P7_DIGEST_INFO(P7_DIGEST_INFO *digestInfo);

/*!
* \brief
* P7_SIGNER_INFOS ����ü�� �ʱ�ȭ �Լ�
* \returns
* P7_SIGNER_INFOS ����ü ������
*/
ISC_API P7_SIGNER_INFOS *new_P7_SIGNER_INFOS(void);
/*!
* \brief
* P7_SIGNER_INFOS ����ü�� �޸� �Ҵ� ����
* \param signerInfos
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P7_SIGNER_INFOS(P7_SIGNER_INFOS *signerInfos);

/*!
* \brief
* P7_SIGNED_DATA ����ü�� �ʱ�ȭ �Լ�
* \returns
* P7_SIGNED_DATA ����ü ������
*/
ISC_API P7_SIGNED_DATA *new_P7_SIGNED_DATA(void);

/*!
* \brief
* P7_SIGNED_DATA ����ü�� �޸� �Ҵ� ����
* \param pkcs7SignedData
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P7_SIGNED_DATA(P7_SIGNED_DATA *pkcs7SignedData);

/*!
* \brief
* P7_RECIPIENT_INFO ����ü�� �ʱ�ȭ �Լ�
* \returns
* P7_RECIPIENT_INFO ����ü ������
*/
ISC_API P7_RECIPIENT_INFO *new_P7_RECIPIENT_INFO(void);

/*!
* \brief
* P7_RECIPIENT_INFO ����ü�� �޸� �Ҵ� ����
* \param recipientInfo
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P7_RECIPIENT_INFO(P7_RECIPIENT_INFO *recipientInfo);

/*!
* \brief
* P7_RECIPIENT_INFOS ����ü�� �ʱ�ȭ �Լ�
* \returns
* P7_RECIPIENT_INFOS ����ü ������
*/
ISC_API P7_RECIPIENT_INFOS *new_P7_RECIPIENT_INFOS(void);

/*!
* \brief
* P7_RECIPIENT_INFOS ����ü�� �޸� �Ҵ� ����
* \param recipientInfos
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P7_RECIPIENT_INFOS(P7_RECIPIENT_INFOS *recipientInfos);

/*!
* \brief
* P7_ENCRYPTED_CONTENT_INFO ����ü�� �ʱ�ȭ �Լ�
* \returns
* P7_ENCRYPTED_CONTENT_INFO ����ü ������
*/
ISC_API P7_ENCRYPTED_CONTENT_INFO *new_P7_ENCRYPTED_CONTENT_INFO(void);

/*!
* \brief
* P7_ENCRYPTED_CONTENT_INFO ����ü�� �޸� �Ҵ� ����
* \param encryptedContentInfo
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P7_ENCRYPTED_CONTENT_INFO(P7_ENCRYPTED_CONTENT_INFO *encryptedContentInfo);

/*!
* \brief
* P7_ENVELOPED_DATA ����ü�� �ʱ�ȭ �Լ�
* \returns
* P7_ENVELOPED_DATA ����ü ������
*/
ISC_API P7_ENVELOPED_DATA *new_P7_ENVELOPED_DATA(void);

/*!
* \brief
* P7_ENVELOPED_DATA ����ü�� �޸� �Ҵ� ����
* \param pkcs7EnvelopedData
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P7_ENVELOPED_DATA(P7_ENVELOPED_DATA *pkcs7EnvelopedData);

/*!
* \brief
* P7_SIGNED_AND_ENVELOPED_DATA ����ü�� �ʱ�ȭ �Լ�
* \returns
* P7_SIGNED_AND_ENVELOPED_DATA ����ü ������
*/
ISC_API P7_SIGNED_AND_ENVELOPED_DATA *new_P7_SIGNED_AND_ENVELOPED_DATA(void);

/*!
* \brief
* P7_SIGNED_AND_ENVELOPED_DATA ����ü�� �޸� �Ҵ� ����
* \param pkcs7SignedAndEnvelopedData
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P7_SIGNED_AND_ENVELOPED_DATA(P7_SIGNED_AND_ENVELOPED_DATA *pkcs7SignedAndEnvelopedData);

/*!
* \brief
* P7_DIGESTED_DATA ����ü�� �ʱ�ȭ �Լ�
* \returns
* P7_DIGESTED_DATA ����ü ������
*/
ISC_API P7_DIGESTED_DATA *new_P7_DIGESTED_DATA(void);

/*!
* \brief
* P7_DIGESTED_DATA ����ü�� �޸� �Ҵ� ����
* \param pkcs7DigestedData
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P7_DIGESTED_DATA(P7_DIGESTED_DATA *pkcs7DigestedData);

/*!
* \brief
* P7_ENCRYPTED_DATA ����ü�� �ʱ�ȭ �Լ�
* \returns
* P7_ENCRYPTED_DATA ����ü ������
*/
ISC_API P7_ENCRYPTED_DATA *new_P7_ENCRYPTED_DATA(void);

/*!
* \brief
* P7_ENCRYPTED_DATA ����ü�� �޸� �Ҵ� ����
* \param pkcs7EncryptedData
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P7_ENCRYPTED_DATA(P7_ENCRYPTED_DATA *pkcs7EncryptedData);

/*!
* \brief
* P7_CONTENT_INFO ����ü�� �ʱ�ȭ �Լ�
* \returns
* P7_CONTENT_INFO ����ü ������
*/
ISC_API P7_CONTENT_INFO *new_P7_CONTENT_INFO(void);
/*!
* \brief
* P7_CONTENT_INFO ����ü�� �޸� �Ҵ� ����
* \param pkcs7ContentInfo
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P7_CONTENT_INFO(P7_CONTENT_INFO *pkcs7ContentInfo);

/*!
* \brief
* P7_CONTENT_INFO ����ü�� type���� ����
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param type
* pkcs7 type oid index
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS new_PKCS7_Content(P7_CONTENT_INFO *p7, int type);

/*!
* \brief
* P7_CONTENT_INFO ����ü�� type�� ����
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param type
* pkcs7 type oid index
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_PKCS7_Type(P7_CONTENT_INFO *p7, int type);

/*!
* \brief
* P7_CONTENT_INFO �� content�� ����
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param p7_data
* �����Ϸ��� P7_CONTENT_INFO ����ü ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_PKCS7_Content(P7_CONTENT_INFO *p7, P7_CONTENT_INFO *p7_data);

/*!
* \brief
* P7_RECIPIENT_INFO�� �������� �������κ��� ����
* \param p7i
* P7_RECIPIENT_INFO ����ü ������
* \param x509
* �����Ϸ��� X509_CERT ����ü ������
* \param pk_encode
* ��ȣ �˰��� id
* \param alg_param
* ��ȣ �˰��� �Ķ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_PKCS7_P7_RECIPIENT_INFO(P7_RECIPIENT_INFO *p7i, X509_CERT *x509, int pk_encode, void *alg_param);

/*!
* \brief
* P7_CONTENT_INFO�� ���Ǵ� ISC_BLOCK_CIPHER_UNIT�� ����
* (OID_pkcs7_signedAndEnvelopedData/OID_pkcs7_envelopedData/OID_pkcs7_encryptedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param cipher
* �����Ϸ��� ISC_BLOCK_CIPHER_UNIT ����ü ������ \n
* init �� ISC_BLOCK_CIPHER_UNIT�� ���޵�(�����Ͱ� ���޵ǹǷ� ISC_MEM_FREE ����)
* \return
* -# ISC_SUCCESS : ����
* -# L_PKCS7^ISC_ERR_NULL_INPUT : cipher�� ���� ���
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_PKCS7_Cipher(P7_CONTENT_INFO *p7, ISC_BLOCK_CIPHER_UNIT* cipher);

/*!
* \brief
* P7_ENCRYPTED_CONTENT_INFO�� ��ȣȭ�� ����� ������(encData�� NULL�� ��쿡 ��ȣ���� �ܺο� �ִ� �����)
* \param enc_inf
* P7_ENCRYPTED_CONTENT_INFO ����ü ������
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
* -# L_PKCS7^ISC_ERR_NULL_INPUT : �˰���� P7_ENCRYPTED_CONTENT_INFO ����ü �����Ͱ� ���� ���
* -# L_PKCS7^ISC_ERR_INVALID_INPUT : type_oid��	undefined type ��
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_PKCS7_P7_ENCRYPTED_CONTENT_INFO(P7_ENCRYPTED_CONTENT_INFO *enc_inf, int type_oid, X509_ALGO_IDENTIFIER *algorithm, uint8* encData, int encDataLen);

/*!
* \brief
* P7_CONTENT_INFO�� ��ȣȭ�� �������� ���� ��ȯ
* \param p7
* P7_CONTENT_INFO ����ü ������
* \return
* -# P7_CONTENT_INFO�� ��ȣȭ�� �������� ����
* -# -1 : ����
*/
ISC_API int get_PKCS7_ENCRYPTED_CONTENT_length(P7_CONTENT_INFO *p7);

/*!
* \brief
* ���̳ʸ��� Pkcs7 Data type���� ����
* \param p7_data
* P7_CONTENT_INFO ����ü ������
* \param data
* ������
* \param dataLen
* �������� ����
* \return
* -# ISC_SUCCESS : ����
* -# L_PKCS7^F_GET_PKCS7_DATA^ISC_ERR_NULL_INPUT : �Է� �Ķ���Ͱ� NULL�� ���
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS gen_PKCS7_DATA_from_Binary(P7_CONTENT_INFO **p7_data, uint8* data, int dataLen);

/*!
* \brief
* P7_SIGNER_INFO�� ������ �������� ������, ����Ű, �ؽþ˰��� �������� ����
* \param p7i
* P7_SIGNER_INFO ����ü ������
* \param x509
* ������
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
ISC_API ISC_STATUS set_PKCS7_P7_SIGNER_INFO(P7_SIGNER_INFO *p7i, X509_CERT *x509, ASYMMETRIC_KEY *pkey, int digestOID, int pk_encode, void *alg_param);

/*!
* \brief
* P7_SIGNER_INFO�� ������ �������� ������, ����Ű, �ؽþ˰��� �������� ����
* \param p7i
* P7_SIGNER_INFO ����ü ������
* \param x509
* ������
* \param pkey
* ����Ű
* \param digestOID
* �ؽ� �˰��� id
* \param pk_encode
* ��ȣ �˰��� id
* \param alg_param
* ��ȣ �˰��� �Ķ����
* \param option 
* IGNORE_X509_ALGO_IDENTIFER_PARAM = 1, 0 �ΰ�� ���� �Լ��� ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_PKCS7_P7_SIGNER_INFO_Ex(P7_SIGNER_INFO *p7i, X509_CERT *x509, ASYMMETRIC_KEY *pkey, int digestOID, int pk_encode, void *alg_param, int option);


/*!
* \brief
* P7_CONTENT_INFO�� �����ڸ� �߰�(P7_SIGNER_INFO�� ������ �����Ǿ� �־�� ��) \n
* (OID_pkcs7_signedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param p7i
* P7_SIGNER_INFO ����ü ������(������)
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_PKCS7_Signer(P7_CONTENT_INFO *p7, P7_SIGNER_INFO *p7i);

/*!
* \brief
* P7_CONTENT_INFO�� ���� �������� �߰� \n
* (OID_pkcs7_signedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param x509
* ���� ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_PKCS7_Certificate(P7_CONTENT_INFO *p7, X509_CERT *x509);

/*!
* \brief
* P7_CONTENT_INFO�� ���� CRL�� �߰� \n
* (OID_pkcs7_signedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param crl
* ���� CRL
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_PKCS7_Crl(P7_CONTENT_INFO *p7, X509_CRL *crl);

/*!
* \brief
* P7_CONTENT_INFO�� �����ڸ� �߰� \n
* (OID_pkcs7_signedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param x509
* ������
* \param pkey
* ����Ű
* \param digestOID
* �ؽ� �˰��� id
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API P7_SIGNER_INFO *add_PKCS7_Signature(P7_CONTENT_INFO *p7, X509_CERT *x509, ASYMMETRIC_KEY *pkey, int digestOID);

/*!
* \brief
* P7_CONTENT_INFO�� �����ڸ� �߰� \n
* (OID_pkcs7_signedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param x509
* ������
* \param pkey
* ����Ű
* \param digestOID
* �ؽ� �˰��� id
* \param option 
* IGNORE_X509_ALGO_IDENTIFER_PARAM = 1, 0 �ΰ�� ���� �Լ��� ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API P7_SIGNER_INFO *add_PKCS7_Signature_Ex(P7_CONTENT_INFO *p7, X509_CERT *x509, ASYMMETRIC_KEY *pkey, int digestOID, int option);

/*!
* \brief
* P7_CONTENT_INFO�� �����ڸ� �߰� \n
* (OID_pkcs7_signedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* \param pk_encode
* ��ȣ �˰��� id
* \param alg_param
* ��ȣ �Ķ�����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API P7_SIGNER_INFO *add_PKCS7_Signature_withEncryptedAlgorithm(P7_CONTENT_INFO *p7, X509_CERT *x509, ASYMMETRIC_KEY *pkey, int digestOID, int pk_encode, void *alg_param);

/*!
* \brief
* P7_CONTENT_INFO�� �����ڸ� �߰� \n
* (OID_pkcs7_signedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param x509
* ������
* \param pkey
* ����Ű
* \param digestOID
* �ؽ� �˰��� id
* \param pk_encode
* ��ȣ �˰��� id
* \param alg_param
* ��ȣ �Ķ�����
* \param option 
* IGNORE_X509_ALGO_IDENTIFER_PARAM = 1, 0 �ΰ�� ���� �Լ��� ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API P7_SIGNER_INFO *add_PKCS7_Signature_withEncryptedAlgorithm_Ex(P7_CONTENT_INFO *p7, X509_CERT *x509, ASYMMETRIC_KEY *pkey, int digestOID, int pk_encode, void *alg_param, int option);


/*!
* \brief
* P7_CONTENT_INFO�� �������� �ش��ϴ� �����ڸ� �߰� \n
* (OID_pkcs7_signedAndEnvelopedData/OID_pkcs7_envelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param x509
* ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API P7_RECIPIENT_INFO *add_PKCS7_Recipient(P7_CONTENT_INFO *p7, X509_CERT *x509);

/*!
* \brief
* P7_CONTENT_INFO�� �������� �ش��ϴ� �����ڸ� �߰� \n
* (OID_pkcs7_signedAndEnvelopedData/OID_pkcs7_envelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param x509
* ������
* \param pk_encode
* ��ȣ �˰��� id
* \param alg_param
* ��ȣ �Ķ�����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API P7_RECIPIENT_INFO *add_PKCS7_Recipient_withEncryptedAlgorithm(P7_CONTENT_INFO *p7, X509_CERT *x509, 
															  int pk_encode, void *alg_param);

/*!
* \brief
* P7_CONTENT_INFO�� �����ڸ� �߰� \n
* (OID_pkcs7_signedAndEnvelopedData/OID_pkcs7_envelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param ri
* ������ (�������� ����Ͽ� ������ �����Ǿ�� ��)
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_PKCS7_P7_RECIPIENT_INFO(P7_CONTENT_INFO *p7, P7_RECIPIENT_INFO *ri);

/*!
* \brief
* P7_SIGNER_INFO�� Authenticated Attribute�� �߰� \n
* \param p7si
* P7_SIGNER_INFO ����ü ������
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
ISC_API ISC_STATUS add_PKCS7_Signed_Attribute(P7_SIGNER_INFO *p7si, int oid, int atrtype, uint8 *value, int valueLen);

/*!
* \brief
* P7_SIGNER_INFO�� Unauthenticated Attribute�� �߰� \n
* \param p7si
* P7_SIGNER_INFO ����ü ������
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
ISC_API ISC_STATUS add_PKCS7_Unauthenticated_Attribute(P7_SIGNER_INFO *p7si, int oid, int atrtype, uint8 *value, int valueLen); 

/*!
* \brief
* P7_SIGNER_INFO�� Signed Attribute ���� ������ oid �� type �� Attribute �� ã�� ù��° data�� ��ȯ�Ѵ�. \n
* \param p7si
* P7_SIGNER_INFO ����ü ������
* \param oid
* attribute�� OID
* \param atrtype
* ã�� attribute �� asn1 type
* \param found_not_free 
* ã�� attribute �� ù��° ������ (�ܺο��� free �ϸ� �ȵ�)
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS find_PKCS7_Signed_Attribute(P7_SIGNER_INFO *p7si, int oid, int atrtype, void** found_not_free);

/*!
* \brief
* P7_SIGNER_INFO�� Unauthenticated Attribute ���� ������ oid �� type �� Attribute �� ã�� ù��° data�� ��ȯ�Ѵ�. \n
* \param p7si
* P7_SIGNER_INFO ����ü ������
* \param oid
* attribute�� OID
* \param atrtype
* ã�� attribute �� asn1 type
* \param found_not_free
* ã�� attribute�� ù��° ������ (�ܺο��� free �ϸ� �ȵ�)
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS find_PKCS7_Unauthenticated_Attribute(P7_SIGNER_INFO *p7si, int oid, int atrtype, void** found_not_free);
/*!
* \brief
* P7_CONTENT_INFO�� ���� �ʱ�ȭ
* (OID_pkcs7_signedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param detached
* detached�� 0�ϰ�� ����Ǵ� �����Ͱ� p7�� ���Ե�\n
* detached�� 1�ϰ�� ����Ǵ� �����Ͱ� p7�� �ܺο� ������ ����
* \return
* -# ISC_SUCCESS : ����
* -# L_PKCS7^F_P7_SIGN^ISC_ERR_NULL_INPUT : p7�� NULL�� ���
* -# L_PKCS7^F_P7_SIGN^ISC_ERR_INVALID_INPUT : signer�� ���ų� digestAlg, encAlg�� NULL�� ���
* -# ISC_FAIL : �������� �ʴ� Ÿ���̰ų� ISC_Init_RSASSA()�� ������ ���
*/
ISC_API ISC_STATUS init_PKCS7_Sign(P7_CONTENT_INFO *p7,int detached);

/*!
* \brief
* P7_CONTENT_INFO�� ���� �ʱ�ȭ
* (OID_pkcs7_signedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param detached
* detached�� 0�ϰ�� ����Ǵ� �����Ͱ� p7�� ���Ե�\n
* detached�� 1�ϰ�� ����Ǵ� �����Ͱ� p7�� �ܺο� ������ ����
* \param pf_sign_cb 
* ������ ������ �����ϴ� �ݹ��Լ� (PKCS#11, PACCEL ������ ����)
* \return
* -# ISC_SUCCESS : ����
* -# L_PKCS7^F_P7_SIGN^ISC_ERR_NULL_INPUT : p7�� NULL�� ���
* -# L_PKCS7^F_P7_SIGN^ISC_ERR_INVALID_INPUT : signer�� ���ų� digestAlg, encAlg�� NULL�� ���
* -# ISC_FAIL : �������� �ʴ� Ÿ���̰ų� ISC_Init_RSASSA()�� ������ ���
*/
ISC_API ISC_STATUS init_PKCS7_Sign_cb(P7_CONTENT_INFO *p7,int detached, PF_SIGN_CB pf_sign_cb);

/*!
* \brief
* P7_CONTENT_INFO�� ���� ���� (update)
* (OID_pkcs7_signedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param data
* �����Ϸ��� ������
* \param dataLen
* �������� ����
* \return
* -# ISC_SUCCESS : ����
* -# L_PKCS7^F_P7_SIGN^ISC_ERR_NULL_INPUT : p7�� NULL�� ���
* -# L_PKCS7^F_P7_SIGN^ISC_ERR_INVALID_INPUT : data�� dataLen�� ��ȿ���� �ʰų�, signer�� ���� ���
* -# ISC_FAIL : �������� �ʴ� Ÿ���� ���
*/
ISC_API ISC_STATUS update_PKCS7_Sign(P7_CONTENT_INFO *p7, uint8* data, int dataLen);

/*!
* \brief
* P7_CONTENT_INFO�� ���� ���� ���� ���� ����
* (OID_pkcs7_signedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \return
* -# ISC_SUCCESS : ����
* -# L_PKCS7^F_P7_SIGN^ISC_ERR_NULL_INPUT : p7�� NULL�� ���
* -# ISC_FAIL : �������� �ʴ� ��쳪 ISC_Update_RSASSA(), ISC_Final_RSASSA()�� ������ ���
*/
ISC_API ISC_STATUS final_PKCS7_Sign(P7_CONTENT_INFO *p7);

/*!
* \brief
* P7_CONTENT_INFO�� ���� ���� ���� ���� ����
* (OID_pkcs7_signedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param pf_sign_cb 
* ������ ������ ������ �ݹ��Լ� (PKCS#11, PACCEL ������ ����)
* \return
* -# ISC_SUCCESS : ����
* -# L_PKCS7^F_P7_SIGN^ISC_ERR_NULL_INPUT : p7�� NULL�� ���
* -# ISC_FAIL : �������� �ʴ� ��쳪 ISC_Update_RSASSA(), ISC_Final_RSASSA()�� ������ ���
*/
ISC_API ISC_STATUS final_PKCS7_Sign_cb(P7_CONTENT_INFO *p7, PF_SIGN_CB pf_sign_cb);

/*!
* \brief
* P7_CONTENT_INFO�� ���� ����
* (OID_pkcs7_signedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param data
* �����Ϸ��� ������
* \param dataLen
* �������� ����
* \param detached
* detached�� 0�ϰ�� ����Ǵ� �����Ͱ� p7�� ���Ե�\n
* detached�� 1�ϰ�� ����Ǵ� �����Ͱ� p7�� �ܺο� ������ ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS sign_PKCS7(P7_CONTENT_INFO *p7, uint8 *data, int dataLen, int detached);



/*!
* \brief
* P7_CONTENT_INFO�� ���� ����
* (OID_pkcs7_signedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param data
* �����Ϸ��� ������
* \param dataLen
* �������� ����
* \param detached
* detached�� 0�ϰ�� ����Ǵ� �����Ͱ� p7�� ���Ե�\n
* detached�� 1�ϰ�� ����Ǵ� �����Ͱ� p7�� �ܺο� ������ ����
* \param pf_sign_cb
* ������ ������ ������ �Լ��� �ݹ����� �����Ѵ�. (�ܺ� crypto, hsm ������ ���)
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS sign_PKCS7_CB(P7_CONTENT_INFO *p7, uint8 *data, int dataLen, int detached, PF_SIGN_CB pf_sign_cb);

/*!
* \brief
* P7_CONTENT_INFO�� ���� ����
* (OID_pkcs7_signedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param x509
* ������ ����Ű�� ���Ե� ������
* \param data
* �����Ϸ��� ������ (p7�� �ȿ� ���� �����͸� �����ϰ� ������ NULL)
* \param dataLen 
* �������� ����(p7�� �ȿ� ���� �����͸� �����ϰ� ������ 0)
* ������ authenticatedAttributes �񱳸� �ǳʶٰ� ������ -1
* \return
* -# ISC_SUCCESS : ���� ��� 
* -# L_PKCS7^F_P7_VERIFY^ISC_ERR_NULL_INPUT : data�� dataLen�� NULL�ΰ��
* -# L_PKCS7^F_P7_VERIFY^ISC_ERR_INVALID_INPUT : �ش��ϴ� �������� ���ų�, �������� �ִµ� Ű�� ���ų� signer info�� ���ų�, digestAlg, encAlg�� ���� ���
* -# L_PKCS7^F_P7_VERIFY^ISC_ERR_VERIFY_FAILURE : �������� �ƿ� ���� ���
* -# ISC_FAIL : ��������� �����߰ų� �� �̿��� ����
*/
ISC_API ISC_STATUS verify_PKCS7(P7_CONTENT_INFO *p7,X509_CERT *x509, uint8 *data, int dataLen);

/*!
* \brief
* P7_CONTENT_INFO�� ���� ����
* (OID_pkcs7_signedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param x509
* ������ ����Ű�� ���Ե� ������
* \param data
* �����Ϸ��� ������ (p7�� �ȿ� ���� �����͸� �����ϰ� ������ NULL)
* \param dataLen 
* �������� ����(p7�� �ȿ� ���� �����͸� �����ϰ� ������ 0)
* ������ authenticatedAttributes �񱳸� �ǳʶٰ� ������ -1
* \param pf_verify_cb
* ������ ���� ������ ������ �Լ��� �ݹ����� �����Ѵ�. (PKCS#11, PACCEL ����)
* \return
* -# ISC_SUCCESS : ���� ��� 
* -# L_PKCS7^F_P7_VERIFY^ISC_ERR_NULL_INPUT : data�� dataLen�� NULL�ΰ��
* -# L_PKCS7^F_P7_VERIFY^ISC_ERR_INVALID_INPUT : �ش��ϴ� �������� ���ų�, �������� �ִµ� Ű�� ���ų� signer info�� ���ų�, digestAlg, encAlg�� ���� ���
* -# L_PKCS7^F_P7_VERIFY^ISC_ERR_VERIFY_FAILURE : �������� �ƿ� ���� ���
* -# ISC_FAIL : ��������� �����߰ų� �� �̿��� ����
*/
ISC_API ISC_STATUS verify_PKCS7_CB(P7_CONTENT_INFO *p7,X509_CERT *x509, uint8 *data, int dataLen, PF_VERIFY_CB pf_verify_cb );

/*!
* \brief
* P7_CONTENT_INFO�� SignedAndEnveloped ����
* (OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param type_oid
* ��ȣȭ �Ǵ� Ÿ��
* \param identifier
* ��ȣȭ �˰����� ������ Identifier
* \param data
* ������
* \param dataLen
* �������� ����
* \param pk_encode
* ��ȣȭ�� ������ encoding �� ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS sign_encrypt_PKCS7(P7_CONTENT_INFO *p7,  int type_oid, X509_ALGO_IDENTIFIER *identifier, uint8 *data, int dataLen, int pk_encode);

/*!
* \brief
* P7_CONTENT_INFO�� SignedAndEnveloped ����
* (OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param type_oid
* ��ȣȭ �Ǵ� Ÿ��
* \param identifier
* ��ȣȭ �˰����� ������ Identifier
* \param data
* ������
* \param dataLen
* �������� ����
* \param secretKey
* ��ȣȭ�� ���� ���Ű(Password)
* \para, KeyLen
* ���Ű�� ����
* \param iv
* ��ȣȭ�� ���� �ʱ����(IV)
* \param pk_encode
* ��ȣȭ�� ����� encoding �� ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS sign_encrypt_PKCS7_userKEY(P7_CONTENT_INFO *p7,  int type_oid, X509_ALGO_IDENTIFIER *identifier, uint8 *in, int inLen, uint8 *secretKey, uint8 *iv, int pk_encode);

/*!
* \brief
* P7_CONTENT_INFO�� SignedAndEnveloped ����(�ݰ��������)
* (OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param type_oid
* ��ȣȭ �Ǵ� Ÿ��
* \param identifier
* ��ȣȭ �˰����� ������ Identifier
* \param data
* ������
* \param dataLen
* �������� ����
* \param pk_encode
* ��ȣȭ�� ����� encoding �� ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS sign_encrypt_PKCS7_SP(P7_CONTENT_INFO *p7,  int type_oid, X509_ALGO_IDENTIFIER *identifier, uint8 *data, int dataLen,int pk_encode);

/*!
* \brief
* P7_CONTENT_INFO�� SignedAndEnveloped ����(�ݰ��������)
* (OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param type_oid
* ��ȣȭ �Ǵ� Ÿ��
* \param identifier
* ��ȣȭ �˰����� ������ Identifier
* \param data
* ������
* \param dataLen
* �������� ����
* \param secretKey
* ��ȣȭ�� ���� ���Ű(Password)
* \para, KeyLen
* ���Ű�� ����
* \param iv
* ��ȣȭ�� ���� �ʱ����(IV)
* \param pk_encode
* ��ȣȭ�� ����� encoding �� ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS sign_encrypt_PKCS7_userKEY_SP(P7_CONTENT_INFO *p7,  int type_oid, X509_ALGO_IDENTIFIER *identifier, uint8 *in, int inLen, uint8 *secretKey, uint8 *iv, int pk_encode);

/*!
* \brief
* P7_CONTENT_INFO�� SignedAndEnveloped ��ȣȭ�ϰ� ������ ����
* (OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param cert
* ���� ������ ���� ������ (decrypt_PKCS7_enveloped_CEK �Լ� ����)
* \param cek
* ��ȣȭ�� ���� Content Encryption Key
* \param out
* ��ȭȭ�� ����
* \param outLen
* ��ȣȭ�� ���� ������ ������
* \return
* -# 1 : ���� ���
* -# -1 : ���� ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS verify_decrypt_PKCS7(P7_CONTENT_INFO *p7, X509_CERT* cert, uint8 *cek, uint8 *out, int *outLen);

/*!
* \brief
* P7_CONTENT_INFO - SignedAndEnveloped �� �����ڿ� �ش��ϴ� CEK�� ��ȣȭ
* (OID_pkcs7_envelopedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
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
ISC_API ISC_STATUS decrypt_PKCS7_enveloped_CEK(P7_CONTENT_INFO *p7, X509_CERT *cert, ASYMMETRIC_KEY* priKey, uint8* cek, int *cekLen, int pk_decode);

/*!
* \brief
* P7_CONTENT_INFO�� ��ȣȭ ��� �ʱ�ȭ\n
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
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
ISC_API ISC_STATUS init_PKCS7_Encrypt(P7_CONTENT_INFO *p7, int type_oid, X509_ALGO_IDENTIFIER *identifier, int detached, uint8 *secretKey, uint8 *iv, int pk_encode);

/*!
* \brief
* P7_CONTENT_INFO�� ��ȣȭ ����(Update)
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
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
ISC_API ISC_STATUS update_PKCS7_encrypt(P7_CONTENT_INFO *p7, uint8* in, int inLen, uint8 *out, int *outLen);

/*!
* \brief
* P7_CONTENT_INFO�� ��ȣȭ ���� ���� ����
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param out
* ��µǴ� ��ȣ���� ����
* \param outLen
* ������ ���� ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS final_PKCS7_Encrypt(P7_CONTENT_INFO *p7, uint8 *out, int *outLen);

/*!
* \brief
* P7_CONTENT_INFO�� ��ȣȭ ���� (Detached mode�� ���� �Ұ�)
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
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
ISC_API ISC_STATUS encrypt_PKCS7(P7_CONTENT_INFO *p7,  int type_oid, X509_ALGO_IDENTIFIER *identifier,uint8 *in, int inLen, int pk_encode);

/*!
* \brief
* P7_CONTENT_INFO�� ��ȣȭ ���� (Detached mode�� ���� �Ұ�)
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
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
ISC_API ISC_STATUS encrypt_PKCS7_userKEY(P7_CONTENT_INFO *p7,  int type_oid, X509_ALGO_IDENTIFIER *identifier,uint8 *in, int inLen, uint8 *secretKey, uint8 *iv, int pk_encode);

/*!
* \brief
* P7_CONTENT_INFO�� ��ȣȭ ���� (Detached mode�� ���� �Ұ�)
* (OID_pkcs7_encryptedData/OID_pkcs7_envelopedData/OID_pkcs7_signedAndEnvelopedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
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
ISC_API ISC_STATUS decrypt_PKCS7(P7_CONTENT_INFO *p7, uint8 *key, uint8 *iv, uint8 *out, int *outLen);

/*!
* \brief
* P7_CONTENT_INFO�� digestedData ����
* (OID_pkcs7_digestedData)
* \param p7
* P7_CONTENT_INFO ����ü ������
* \param DigestID
* ��������Ʈ �˰���
* \param data
* �Է�
* \param dataLen
* �Է��� ����
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS digest_PKCS7(P7_CONTENT_INFO *p7, int DigestID, uint8 *data, int dataLen);


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
ISC_API int cmp_P7_ISSUER_AND_SERIAL_NUMBER(X509_CERT *x509, ISSUER_AND_SERIAL_NUMBER *ias);

/*!
* \brief
* ISSUER_AND_SERIAL_NUMBER ����ü�� Sequence�� Encode �Լ�
* \param isAndSeNum
* ISSUER_AND_SERIAL_NUMBER ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P7_IS_AND_SN_TO_SEQ^ISC_ERR_NULL_INPUT : �Է� �Ķ���Ͱ� NULL��
* -# LOCATION^F_P7_IS_AND_SN_TO_SEQ^ERR_ASN1_ENCODING : ASN1 ����
* -# X509_NAME_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS P7_ISSUER_AND_SERIAL_NUMBER_to_Seq(ISSUER_AND_SERIAL_NUMBER *isAndSeNum, SEQUENCE **seq);

/*!
* \brief
* Sequence�� ISSUER_AND_SERIAL_NUMBER ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param isAndSeNum
* ISSUER_AND_SERIAL_NUMBER ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P7_IS_AND_SN^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_IS_AND_SN^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_IS_AND_SN^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_NAME()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P7_ISSUER_AND_SERIAL_NUMBER(SEQUENCE *seq, ISSUER_AND_SERIAL_NUMBER **isAndSeNum);

/*!
* \brief
* P7_SIGNER_INFO ����ü�� Sequence�� Encode �Լ�
* \param signerInfo
* P7_SIGNER_INFO ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P7_SIGNER_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_SIGNER_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P7_ISSUER_AND_SERIAL_NUMBER_to_Seq()�� ���� �ڵ�\n
* -# X509_ALGO_IDENTIFIER_to_Seq()�� ���� �ڵ�\n
* -# X509_ATTRIBUTES_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS P7_SIGNER_INFO_to_Seq(P7_SIGNER_INFO *signerInfo, SEQUENCE **seq);

/*!
* \brief
* Sequence�� P7_SIGNER_INFO ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param signerInfo
* P7_SIGNER_INFO ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P7_SIGNER_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_SIGNER_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_SIGNER_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P7_ISSUER_AND_SERIAL_NUMBER()�� ���� �ڵ�\n
* -# Seq_to_X509_ALGO_IDENTIFIER()�� ���� �ڵ�\n
* -# Seq_to_X509_ATTRIBUTES()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P7_SIGNER_INFO(SEQUENCE *seq, P7_SIGNER_INFO **signerInfo);

/*!
* \brief
* P7_DIGEST_INFO ����ü�� Sequence�� Encode �Լ�
* \param digestInfo
* P7_DIGEST_INFO ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P7_DIGEST_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_DIGEST_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_ALGO_IDENTIFIER_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS P7_DIGEST_INFO_to_Seq(P7_DIGEST_INFO *digestInfo, SEQUENCE **seq);

/*!
* \brief
* Sequence�� P7_DIGEST_INFO ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param digestInfo
* P7_DIGEST_INFO ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P7_DIGEST_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_DIGEST_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_DIGEST_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_ALGO_IDENTIFIER()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P7_DIGEST_INFO(SEQUENCE *seq, P7_DIGEST_INFO **digestInfo);

/*!
* \brief
* P7_SIGNER_INFOS ����ü�� Sequence�� Encode �Լ�
* \param signerInfos
* P7_SIGNER_INFOS ����ü
* \param setOf
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P7_SIGNER_INFOS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_SIGNER_INFOS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P7_SIGNER_INFO_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS P7_SIGNER_INFOS_to_Seq(P7_SIGNER_INFOS *signerInfos, SET_OF **setOf);

/*!
* \brief
* Sequence�� P7_SIGNER_INFOS ����ü�� Decode �Լ�
* \param setOf
* Decoding Sequence ����ü
* \param signerInfos
* P7_SIGNER_INFOS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P7_SIGNER_INFOS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_SIGNER_INFOS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_SIGNER_INFOS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P7_SIGNER_INFO()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P7_SIGNER_INFOS(SET_OF *setOf, P7_SIGNER_INFOS **signerInfos);

/*!
* \brief
* P7_SIGNED_DATA ����ü�� Sequence�� Encode �Լ�
* \param p7SignedData
* P7_SIGNED_DATA ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P7_SIGNED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_SIGNED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_ALGO_IDENTIFIERS_to_Seq()�� ���� �ڵ�\n
* -# P7_CONTENT_INFO_to_Seq()�� ���� �ڵ�\n
* -# X509_CERTIFICATES_to_Seq()�� ���� �ڵ�\n
* -# X509_CRLS_to_Seq()�� ���� �ڵ�\n
* -# P7_SIGNER_INFOS_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS P7_SIGNED_DATA_to_Seq(P7_SIGNED_DATA *p7SignedData, SEQUENCE **seq);

/*!
* \brief
* Sequence�� P7_SIGNED_DATA ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param p7SignedData
* P7_SIGNED_DATA ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P7_SIGNED_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_SIGNED_DATA^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_SIGNED_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_ALGO_IDENTIFIERS()�� ���� �ڵ�\n
* -# Seq_to_P7_CONTENT_INFO()�� ���� �ڵ�\n
* -# Seq_to_X509_CERTIFICATES()�� ���� �ڵ�\n
* -# Seq_to_X509_CRLS()�� ���� �ڵ�\n
* -# Seq_to_P7_SIGNER_INFOS()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P7_SIGNED_DATA(SEQUENCE *seq, P7_SIGNED_DATA **p7SignedData);

/*!
* \brief
* P7_RECIPIENT_INFO ����ü�� Sequence�� Encode �Լ�
* \param recipientInfo
* P7_RECIPIENT_INFO ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P7_RECIPIENT_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_RECIPIENT_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P7_ISSUER_AND_SERIAL_NUMBER_to_Seq()�� ���� �ڵ�\n
* -# X509_ALGO_IDENTIFIER_to_Seq()�� ���� �ڵ�\n

*/
ISC_API ISC_STATUS P7_RECIPIENT_INFO_to_Seq(P7_RECIPIENT_INFO *recipientInfo, SEQUENCE **seq);

/*!
* \brief
* Sequence�� P7_RECIPIENT_INFO ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param recipientInfo
* P7_RECIPIENT_INFO ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P7_RECIPIENT_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_RECIPIENT_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_RECIPIENT_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P7_ISSUER_AND_SERIAL_NUMBER()�� ���� �ڵ�\n
* -# Seq_to_X509_ALGO_IDENTIFIER()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P7_RECIPIENT_INFO(SEQUENCE *seq, P7_RECIPIENT_INFO **recipientInfo);

/*!
* \brief
* P7_RECIPIENT_INFOS ����ü�� Sequence�� Encode �Լ�
* \param recipientInfos
* P7_RECIPIENT_INFOS ����ü
* \param setOf
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P7_RECIPIENT_INFOS_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_RECIPIENT_INFOS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P7_RECIPIENT_INFO_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS P7_RECIPIENT_INFOS_to_Seq(P7_RECIPIENT_INFOS *recipientInfos, SET_OF **setOf);

/*!
* \brief
* Sequence�� P7_RECIPIENT_INFOS ����ü�� Decode �Լ�
* \param setOf
* Decoding Sequence ����ü
* \param recipientInfos
* P7_RECIPIENT_INFOS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P7_RECIPIENT_INFOS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_RECIPIENT_INFOS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P7_RECIPIENT_INFO()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P7_RECIPIENT_INFOS(SET_OF *setOf, P7_RECIPIENT_INFOS **recipientInfos);

/*!
* \brief
* P7_ENCRYPTED_CONTENT_INFO ����ü�� Sequence�� Encode �Լ�
* \param encContentInfo
* P7_ENCRYPTED_CONTENT_INFO ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P7_ENCRYPTED_CONTENT_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_ENCRYPTED_CONTENT_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_ALGO_IDENTIFIER_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS P7_ENCRYPTED_CONTENT_INFO_to_Seq(P7_ENCRYPTED_CONTENT_INFO *encContentInfo, SEQUENCE **seq);
/*!
 * \brief
 * P7_ENCRYPTED_CONTENT_INFO ����ü�� Sequence�� Encode �Լ�
 * \param encContentInfo
 * P7_ENCRYPTED_CONTENT_INFO ����ü
 * \param seq
 * Encoding Sequence ����ü
 * \returns
 * -# ISC_SUCCESS : ����
 * -# LOCATION^F_P7_ENCRYPTED_CONTENT_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
 * -# LOCATION^F_P7_ENCRYPTED_CONTENT_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
 * -# X509_ALGO_IDENTIFIER_to_Seq()�� ���� �ڵ�\n
 */
ISC_STATUS P7_ENCRYPTED_CONTENT_INFO_to_Seq_Scraping(P7_ENCRYPTED_CONTENT_INFO *encContentInfo, SEQUENCE **seq);
/*!
* \brief
* Sequence�� P7_ENCRYPTED_CONTENT_INFO ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param encContentInfo
* P7_ENCRYPTED_CONTENT_INFO ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P7_ENCRYPTED_CONTENT_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_ENCRYPTED_CONTENT_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_ENCRYPTED_CONTENT_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_ALGO_IDENTIFIER()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P7_ENCRYPTED_CONTENT_INFO(SEQUENCE *seq, P7_ENCRYPTED_CONTENT_INFO **encContentInfo);

/*!
* \brief
* P7_ENVELOPED_DATA ����ü�� Sequence�� Encode �Լ�
* \param p7EnvelopedData
* P7_ENVELOPED_DATA ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P7_ENVELOPED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_ENVELOPED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P7_RECIPIENT_INFOS_to_Seq()�� ���� �ڵ�\n
* -# P7_ENCRYPTED_CONTENT_INFO_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS P7_ENVELOPED_DATA_to_Seq(P7_ENVELOPED_DATA *p7EnvelopedData, SEQUENCE **seq);
/*!
 * \brief
 * P7_ENVELOPED_DATA ����ü�� Sequence�� Encode �Լ�
 * \param p7EnvelopedData
 * P7_ENVELOPED_DATA ����ü
 * \param seq
 * Encoding Sequence ����ü
 * \returns
 * -# ISC_SUCCESS : ����
 * -# LOCATION^F_P7_ENVELOPED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
 * -# LOCATION^F_P7_ENVELOPED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
 * -# P7_RECIPIENT_INFOS_to_Seq()�� ���� �ڵ�\n
 * -# P7_ENCRYPTED_CONTENT_INFO_to_Seq()�� ���� �ڵ�\n
 */
ISC_API ISC_STATUS P7_ENVELOPED_DATA_to_Seq_Scraping(P7_ENVELOPED_DATA *p7EnvelopedData, SEQUENCE **seq);

/*!
* \brief
* Sequence�� P7_ENVELOPED_DATA ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param p7EnvelopedData
* P7_ENVELOPED_DATA ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P7_ENVELOPED_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_ENVELOPED_DATA^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_ENVELOPED_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P7_RECIPIENT_INFOS()�� ���� �ڵ�\n
* -# Seq_to_P7_ENCRYPTED_CONTENT_INFO()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P7_ENVELOPED_DATA(SEQUENCE *seq, P7_ENVELOPED_DATA **p7EnvelopedData);

/*!
* \brief
* P7_SIGNED_AND_ENVELOPED_DATA ����ü�� Sequence�� Encode �Լ�
* \param p7SnEData
* P7_SIGNED_AND_ENVELOPED_DATA ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P7_SIG_AND_ENV_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_SIG_AND_ENV_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P7_RECIPIENT_INFOS_to_Seq()�� ���� �ڵ�\n
* -# X509_ALGO_IDENTIFIERS_to_Seq()�� ���� �ڵ�\n
* -# P7_ENCRYPTED_CONTENT_INFO_to_Seq()�� ���� �ڵ�\n
* -# X509_CERTIFICATES_to_Seq()�� ���� �ڵ�\n
* -# X509_CRLS_to_Seq()�� ���� �ڵ�\n
* -# P7_SIGNER_INFOS_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS P7_SIGNED_AND_ENVELOPED_DATA_to_Seq(P7_SIGNED_AND_ENVELOPED_DATA *p7SnEData, SEQUENCE **seq);

/*!
* \brief
* Sequence�� P7_SIGNED_AND_ENVELOPED_DATA ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param p7SnEData
* P7_SIGNED_AND_ENVELOPED_DATA ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P7_SIG_AND_ENV_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_SIG_AND_ENV_DATA^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_SIG_AND_ENV_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P7_RECIPIENT_INFOS()�� ���� �ڵ�\n
* -# Seq_to_X509_ALGO_IDENTIFIERS()�� ���� �ڵ�\n
* -# Seq_to_P7_ENCRYPTED_CONTENT_INFO()�� ���� �ڵ�\n
* -# Seq_to_X509_CERTIFICATES()�� ���� �ڵ�\n
* -# Seq_to_X509_CRLS()�� ���� �ڵ�\n
* -# Seq_to_P7_SIGNER_INFOS()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P7_SIGNED_AND_ENVELOPED_DATA(SEQUENCE *seq, P7_SIGNED_AND_ENVELOPED_DATA **p7SnEData);

/*!
* \brief
* P7_DIGESTED_DATA ����ü�� Sequence�� Encode �Լ�
* \param p7DigestedData
* P7_DIGESTED_DATA ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P7_DIGESTED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_DIGESTED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_ALGO_IDENTIFIER_to_Seq()�� ���� �ڵ�\n
* -# P7_CONTENT_INFO_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS P7_DIGESTED_DATA_to_Seq(P7_DIGESTED_DATA *p7DigestedData, SEQUENCE **seq);

/*!
* \brief
* Sequence�� P7_DIGESTED_DATA ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param p7DigestedData
* P7_DIGESTED_DATA ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P7_DIGESTED_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_DIGESTED_DATA^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_DIGESTED_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_ALGO_IDENTIFIER()�� ���� �ڵ�\n
* -# Seq_to_P7_CONTENT_INFO()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P7_DIGESTED_DATA(SEQUENCE *seq, P7_DIGESTED_DATA **p7DigestedData);

/*!
* \brief
* P7_ENCRYPTED_DATA ����ü�� Sequence�� Encode �Լ�
* \param p7EncryptedData
* P7_ENCRYPTED_DATA ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P7_ENCRYPTED_DATA_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_ENCRYPTED_DATA_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P7_ENCRYPTED_CONTENT_INFO_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS P7_ENCRYPTED_DATA_to_Seq(P7_ENCRYPTED_DATA *p7EncryptedData, SEQUENCE **seq);

/*!
* \brief
* Sequence�� P7_ENCRYPTED_DATA ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param p7EncryptedData
* P7_ENCRYPTED_DATA ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P7_ENCRYPTED_DATA^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_ENCRYPTED_DATA^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_ENCRYPTED_DATA^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P7_ENCRYPTED_CONTENT_INFO()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P7_ENCRYPTED_DATA(SEQUENCE *seq, P7_ENCRYPTED_DATA **p7EncryptedData);

/*!
* \brief
* P7_CONTENT_INFO ����ü�� Sequence�� Encode �Լ�
* \param p7ContentInfo
* P7_CONTENT_INFO ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P7_CONTENT_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_P7_CONTENT_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P7_SIGNED_DATA_to_Seq()�� ���� �ڵ�\n
* -# P7_ENVELOPED_DATA_to_Seq()�� ���� �ڵ�\n
* -# P7_SIGNED_AND_ENVELOPED_DATA_to_Seq()�� ���� �ڵ�\n
* -# P7_DIGESTED_DATA_to_Seq()�� ���� �ڵ�\n
* -# P7_ENCRYPTED_DATA_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS P7_CONTENT_INFO_to_Seq(P7_CONTENT_INFO *p7ContentInfo, SEQUENCE **seq);
/*!
 * \brief
 * P7_CONTENT_INFO ����ü�� Sequence�� Encode �Լ�
 * \param p7ContentInfo
 * P7_CONTENT_INFO ����ü
 * \param seq
 * Encoding Sequence ����ü
 * \returns
 * -# ISC_SUCCESS : ����
 * -# LOCATION^F_P7_CONTENT_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null input
 * -# LOCATION^F_P7_CONTENT_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
 * -# P7_SIGNED_DATA_to_Seq()�� ���� �ڵ�\n
 * -# P7_ENVELOPED_DATA_to_Seq()�� ���� �ڵ�\n
 * -# P7_SIGNED_AND_ENVELOPED_DATA_to_Seq()�� ���� �ڵ�\n
 * -# P7_DIGESTED_DATA_to_Seq()�� ���� �ڵ�\n
 * -# P7_ENCRYPTED_DATA_to_Seq()�� ���� �ڵ�\n
 */
ISC_API ISC_STATUS P7_CONTENT_INFO_to_Seq_Scraping(P7_CONTENT_INFO *p7ContentInfo, SEQUENCE **seq);

/*!
* \brief
* Sequence�� P7_CONTENT_INFO ����ü�� Decode �Լ�
* \param seq
* Decoding Sequence ����ü
* \param p7ContentInfo
* P7_CONTENT_INFO ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P7_CONTENT_INFO^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_P7_CONTENT_INFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P7_CONTENT_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P7_SIGNED_DATA()�� ���� �ڵ�\n
* -# Seq_to_P7_ENVELOPED_DATA()�� ���� �ڵ�\n
* -# Seq_to_P7_SIGNED_AND_ENVELOPED_DATA()�� ���� �ڵ�\n
* -# Seq_to_P7_DIGESTED_DATA()�� ���� �ڵ�\n
* -# Seq_to_P7_ENCRYPTED_DATA()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P7_CONTENT_INFO(SEQUENCE *seq, P7_CONTENT_INFO **p7ContentInfo);

/*!
* \brief
* P7_CONTENT_INFO ����ü�ǹ���������������
* \param p7
* P7_CONTENT_INFO ����ü
* \param version
* �����ҹ���
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
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

