/*!
* \file ocsp.h
* \brief OCSP Protocol
* \remarks
* RFC2560, Network Working Group
* \author
* Copyright (c) 2008 by \<INITech\> / Developed by Seon Jong. Kim.
*/

#ifndef HEADER_OCSP_H
#define HEADER_OCSP_H

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/digest.h>

#include "asn1.h"
#include "asn1_stack.h"
#include "asn1_objects.h"
#include "x509.h"
#include "x509v3.h"
#include "pkcs8.h"
#include "cid_dh.h"

#ifdef __cplusplus
extern "C" {
#endif

/* error.h �� �� ���� ------------------------------------- */
#define L_OCSP								0x50000000	/*!< */
#define F_GENERATE_SINGLE_OCSP_REQUEST		0x00010000  /*!< */
#define F_GENERATE_MULTI_OCSP_REQUEST		0x00020000  /*!< */
#define F_GET_OCSP_REQUEST_NONCE_LENGTH		0x00030000  /*!< */
#define F_GET_OCSP_REQUEST_NONCE			0x00040000  /*!< */
#define F_OCSP_SINGLE_REQUEST_TO_SEQ		0x00050000  /*!< */
#define F_OCSP_TBS_REQUEST_TO_SEQ			0x00060000  /*!< */
#define F_OCSP_REQUEST_TO_SEQ				0x00070000  /*!< */
#define F_SEQ_TO_OCSP_RESPONSE				0x00080000	/*!< */
#define F_SEQ_TO_OCSP_RESPONSE_BYTES		0x00090000	/*!< */
#define F_GET_BASIC_OCSP_RESPONSE			0x000A0000	/*!< */
#define F_SEQ_TO_OCSP_RESPONSE_DATA			0x000B0000	/*!< */
#define F_SEQ_TO_OCSP_SINGLE_RESPONSE		0x000C0000	/*!< */
#define F_SEQ_TO_OCSP_CERT_ID				0x000D0000	/*!< */
#define F_SEQ_TO_OCSP_REVOKED_INFO			0x000E0000	/*!< */
#define F_VERIFY_BASIC_OCSP_RESPONSE		0x000F0000	/*!< */
#define F_GET_CERT_STATUS_FROM_OCSP_RESPONSE	0x00100000	/*!< */
#define F_GET_CERT_STATUS_FROM_OCSP_RESPONSE_INDEX	0x00110000	/*!< */
#define F_SEQ_TO_OCSP_REQUEST				0x00120000	/*!< */
#define F_SEQ_TO_OCSP_TBS_REQUEST			0x00130000	/*!< */
#define F_VERIFY_OCSP_REQUEST				0x00140000	/*!< */
#define F_GENERATE_OCSP_RESPONSE_DATA		0x00150000	/*!< */
#define F_GET_OCSP_REQUEST_LIST				0x00160000	/*!< */
#define F_ADD_SINGLE_OCSP_RESPONSE			0x00170000  /*!< */
#define F_GENERATE_BASIC_OCSP_RESPONSE		0x00180000	/*!< */
#define F_OCSP_RESPONSE_DATA_TO_SEQ			0x00190000	/*!< */
#define F_GENERATE_OCSP_RESPONSE			0x001A0000	/*!< */
#define F_BASIC_OCSP_RESPONSE_TO_SEQ		0x001B0000	/*!< */
#define F_OCSP_RESPONSE_TO_SEQ				0x001C0000	/*!< */
#define F_OCSP_RESPONSE_BYTES_to_Seq		0x001D0000	/*!< */
#define F_OCSP_REVOKED_INFO_TO_SEQ			0x001E0000	/*!< */
#define F_OCSP_SINGLE_RESPONSE_TO_SEQ		0x001F0000	/*!< */
#define F_GENERATE_OCSP_RESPONSE_BYTES		0x00200000	/*!< */
#define F_GENERATE_OCSP_SINGLE_REQUEST      0x00210000
#define F_ADD_OCSP_SINGLE_REQUEST_EXTENSION		0x00220000
#define F_GENERATE_EMPTY_OCSP_REQUEST		0x00230000
#define F_ADD_OCSP_SINGLE_REQUEST			0x00230000
#define F_ADD_OCSP_REQUEST_EXTENSION				0x00250000
#define F_GENERATE_OCSP_SINGLE_REQUEST_EXTENSION   0x00260000
#define F_GENERATE_OCSP_REQUEST_EXTENSION   0x00270000
#define F_GENERATE_OCSP_SINGLE_RESPONSE_EXTENSION   0x00280000
#define F_ADD_OCSP_SINGLE_RESPONSE_EXTENSION 0x00290000
#define F_GET_OCSP_SINGLE_RESPONSE_EXTENSION   0x00300000
#define F_ADD_OCSP_RESPONSE_DATA_EXTENSION     0x00310000

#define ERR_OCSP_REQUEST_IS_NULL			0x00000010	/*!< */
#define ERR_USER_CERT_IS_NULL				0x00000011	/*!< */
#define ERR_OCSP_CERT_IS_NULL				0x00000012	/*!< */
#define ERR_OCSP_PRIVATE_KEY_IS_NULL		0x00000013	/*!< */
#define ERR_CA_CERT_IS_NULL					0x00000014	/*!< */
#define ERR_NONCE_BUFFER_IS_NULL			0x00000015	/*!< */
#define ERR_INVALID_OCSP_RESPONSE_TYPE		0x00000016	/*!< */
#define ERR_SIGNATURE_IS_NULL				0x00000017	/*!< */
#define ERR_TBS_DATA_IS_NULL				0x00000018	/*!< */
#define ERR_OCSP_NONCE_DOES_NOT_MATCH		0x00000019	/*!< */
#define ERR_OCSP_NONCE_NOT_EXISTS_IN_TBS_DATA	0x0000001A	/*!< */
#define ERR_INVALID_SIGNATURE_ALGORITHM		0x0000001B	/*!< */
#define ERR_FAILURE							0x0000001C  /*!< */
#define ERR_OCSP_SINGLE_REQUEST_IS_NULL			0x0000001D	/*!< */
#define ERR_OCSP_SINGLE_REQUEST_IS_INVALID 		0x0000001E	/*!< */
#define ERR_SINGLE_REQUEST_EXTENSION_IS_NULL	0x0000001F	/*!< */
#define ERR_OCSP_REQUEST_IS_INVALID				0x00000020 /*!< */
#define ERR_REQUEST_EXTENSION_IS_NULL			0x00000021 /*!< */
#define ERR_EXTENSION_IS_NULL					0x00000022 /*!< */
#define ERR_DH_CI_REQUEST						0x00000023 /*!< */
#define ERR_DH_CI_RESPONSE                      0x00000024 /*!< */
#define ERR_OCSP_SINGLE_RESPONSE_IS_NULL		0x00000025 /*!< */
#define ERR_OCSP_SINGLE_RESPONSE_IS_INVALID 	0x00000026 /*!< */
#define ERR_SINGLE_RESPONSE_EXTENSION_IS_NULL	0x00000027 /*!< */
#define ERR_INVALID_OBJECT_IDENTIFIER			0x00000028 /*!< */
#define ERR_INVALID_DHCIRES_EXTENSION			0x00000029 /*!< */
#define ERR_RESPONSE_DATA_IS_NULL				0x00000030
#define ERR_RESPONSE_DATA_IS_INVALID			0x00000031
#define ERR_RESPONSE_DATA_EXTENSION_DUPLICATED  0x00000032

#define ERR_EXECUTE_FAIL					0x000000FF	/*!< */
/* ------------------------------------------------------------ */

#define OCSP_RESPONSE_STATUS_SUCCESSFUL				0
#define	OCSP_RESPONSE_STATUS_MALFORMED_REQUEST		1
#define OCSP_RESPONSE_STATUS_INTERNAL_ERROR			2
#define OCSP_RESPONSE_STATUS_TRY_LATER				3
#define	OCSP_RESPONSE_STATUS_UNKNOWN					4
#define	OCSP_RESPONSE_STATUS_SIG_REQUIRED			5
#define OCSP_RESPONSE_STATUS_UNAUTHORIZED		    6


#define OCSP_CERT_STATUS_GOOD				0
#define OCSP_CERT_STATUS_REVOKED			1
#define OCSP_CERT_STATUS_UNKNOWN			2

#define OCSP_RESPONDER_ID_TYPE_NAME			0
#define OCSP_RESPONDER_ID_TYPE_KEYHASH		1

/*!
* \brief
* ������ ������ �����ϴ� ID
*/
typedef struct ocsp_cert_id_st{
	X509_ALGO_IDENTIFIER *hashAlgID;
	OCTET_STRING *issuerNameHash;
	OCTET_STRING *issuerKeyHash;
	INTEGER *CertificateSerialNumber;
} OCSP_CERT_ID;

/*!
* \brief
* ���� Request ����ü
*/
typedef struct ocsp_single_request_st{
	OCSP_CERT_ID *certID;
	X509_EXTENSIONS *singleRequestExtensions;
} OCSP_SINGLE_REQUEST;

/*!
* \brief
* ���� Request ����ü ����Ʈ
*/
#ifndef _INI_BADA_CPP
/*typedef struct STK(OCSP_SINGLE_REQUEST) OCSP_SINGLE_REQUESTS;*/
typedef STK(OCSP_SINGLE_REQUEST) OCSP_SINGLE_REQUESTS;
#endif

#define new_OCSP_SINGLE_REQUEST_STK() new_STK(OCSP_SINGLE_REQUEST)
#define free_OCSP_SINGLE_REQUEST_STK(st) free_STK(OCSP_SINGLE_REQUEST, (st))
#define get_OCSP_SINGLE_REQUEST_STK_count(st) get_STK_count(OCSP_SINGLE_REQUEST, (st))
#define get_OCSP_SINGLE_REQUEST_STK_value(st, i) get_STK_value(OCSP_SINGLE_REQUEST, (st), (i))
#define push_OCSP_SINGLE_REQUEST_STK_value(st, val) push_STK_value(OCSP_SINGLE_REQUEST, (st), (val))
#define find_OCSP_SINGLE_REQUEST_STK_value(st, val) find_STK_value(OCSP_SINGLE_REQUEST, (st), (val))
#define remove_OCSP_SINGLE_REQUEST_STK_value(st, i) remove_STK_value(OCSP_SINGLE_REQUEST, (st), (i))
#define insert_OCSP_SINGLE_REQUEST_STK_value(st, val, i) insert_STK_value(OCSP_SINGLE_REQUEST, (st), (val), (i))
#define dup_OCSP_SINGLE_REQUEST_STK(st) dup_STK(OCSP_SINGLE_REQUEST, st)
#define free_OCSP_SINGLE_REQUEST_STK_values(st, free_func) free_STK_values(OCSP_SINGLE_REQUEST, (st), (free_func))
#define pop_OCSP_SINGLE_REQUEST_STK_value(st) pop_STK_value(OCSP_SINGLE_REQUEST, (st))
#define sort_X509_OCSP_SINGLE_REQUEST(st) sort_STK(OCSP_SINGLE_REQUEST, (st))
#define is_OCSP_SINGLE_REQUEST_STK_sorted(st) is_STK_sorted(OCSP_SINGLE_REQUEST, (st))

/*!
* \brief
* OCSP ���ڼ��� ����ü
*/
typedef struct ocsp_signature_st{
	X509_ALGO_IDENTIFIER *algID;
	BIT_STRING *signature;
	X509_CERTS *certs;
} OCSP_SIGNATURE;

/*!
* \brief
* OCSP TBS Request ����ü
*/
typedef struct ocsp_tbs_request_st{
	int version;
	GENERAL_NAME *requestorName;
#ifdef _INI_BADA_CPP
	STK(OCSP_SINGLE_REQUEST) *requestList;
#else
	OCSP_SINGLE_REQUESTS *requestList;
#endif
	X509_EXTENSIONS *requestExtensions;
} OCSP_TBS_REQUEST;

/*!
* \brief
* OCSP Request ����ü
*/
typedef struct ocsp_request_st{
	OCSP_TBS_REQUEST *tbsRequest;
	OCSP_SIGNATURE *signature;
} OCSP_REQUEST;


/*!
* \brief
* OCSP Response Bytes ����ü
*/
typedef struct ocsp_response_bytes_st{
	OBJECT_IDENTIFIER *type;
	OCTET_STRING *response;
} OCSP_RESPONSE_BYTES;


/*!
* \brief
* OCSP Response ����ü
*/
typedef struct ocsp_response_st{
	int ocspResponseStatus;
	OCSP_RESPONSE_BYTES *responseBytes;
} OCSP_RESPONSE;


/*!
* \brief
* OCSP ResponderID ����ü
*/
typedef struct ocsp_responder_id_st{
	int type;		/* 0 : Name, 1 : KeyHash */
	union {
		X509_NAME *name;
		OCTET_STRING *keyHash;
	} id;
} OCSP_RESPONDER_ID;


/*!
* \brief
* OCSP RevokedInfo ����ü
*/
typedef struct ocsp_revoked_info_st{
	GENERALIZED_TIME *revocationTime;
	int revocationReason;		/* CRL Reason (0 : unspecified, 1 : keyCompromise, 2 : caCompromise, 3 : affiliationChanged ... 10 : aaCompromise */
} OCSP_REVOKED_INFO;

/*!
* \brief
* OCSP CertStatus ����ü
*/
typedef struct ocsp_cert_status_st{
	int type;	/* 0 : good, 1 : revoked,  2 : unknown */
	OCSP_REVOKED_INFO *revokedInfo;
} OCSP_CERT_STATUS;

/*!
* \brief
* OCSP SingleResponse ����ü
*/
typedef struct ocsp_single_response_st{
	OCSP_CERT_ID *certID;
	OCSP_CERT_STATUS *certStatus;
	GENERALIZED_TIME *thisUpdate;
	GENERALIZED_TIME *nextUpdate;
	X509_EXTENSIONS *singleExts;
} OCSP_SINGLE_RESPONSE;

/*!
* \brief
* ���� Response ����ü ����Ʈ
*/

#ifndef _INI_BADA_CPP
typedef STK(OCSP_SINGLE_RESPONSE) OCSP_SINGLE_RESPONSES;
#endif

#define new_OCSP_SINGLE_RESPONSE_STK() new_STK(OCSP_SINGLE_RESPONSE)
#define free_OCSP_SINGLE_RESPONSE_STK(st) free_STK(OCSP_SINGLE_RESPONSE, (st))
#define get_OCSP_SINGLE_RESPONSE_STK_count(st) get_STK_count(OCSP_SINGLE_RESPONSE, (st))
#define get_OCSP_SINGLE_RESPONSE_STK_value(st, i) get_STK_value(OCSP_SINGLE_RESPONSE, (st), (i))
#define push_OCSP_SINGLE_RESPONSE_STK_value(st, val) push_STK_value(OCSP_SINGLE_RESPONSE, (st), (val))
#define find_OCSP_SINGLE_RESPONSE_STK_value(st, val) find_STK_value(OCSP_SINGLE_RESPONSE, (st), (val))
#define remove_OCSP_SINGLE_RESPONSE_STK_value(st, i) remove_STK_value(OCSP_SINGLE_RESPONSE, (st), (i))
#define insert_OCSP_SINGLE_RESPONSE_STK_value(st, val, i) insert_STK_value(OCSP_SINGLE_RESPONSE, (st), (val), (i))
#define dup_OCSP_SINGLE_RESPONSE_STK(st) dup_STK(OCSP_SINGLE_RESPONSE, st)
#define free_OCSP_SINGLE_RESPONSE_STK_values(st, free_func) free_STK_values(OCSP_SINGLE_RESPONSE, (st), (free_func))
#define pop_OCSP_SINGLE_RESPONSE_STK_value(st) pop_STK_value(OCSP_SINGLE_RESPONSE, (st))
#define sort_X509_OCSP_SINGLE_RESPONSE(st) sort_STK(OCSP_SINGLE_RESPONSE, (st))
#define is_OCSP_SINGLE_RESPONSE_STK_sorted(st) is_STK_sorted(OCSP_SINGLE_RESPONSE, (st))

/*!
* \brief
* OCSP ResponseData ����ü
*/
typedef struct ocsp_response_data_st{
	int version;
	OCSP_RESPONDER_ID *responderID;
	GENERALIZED_TIME *productedAt;
#ifdef _INI_BADA_CPP
	STK(OCSP_SINGLE_RESPONSE) *singleResponses;
#else
	OCSP_SINGLE_RESPONSES *singleResponses;
#endif
	X509_EXTENSIONS *responseExts;
} OCSP_RESPONSE_DATA;

/*!
* \brief
* Basic OCSP Response ����ü
*/
typedef struct basic_ocsp_response_st{
	OCSP_RESPONSE_DATA *tbsResponseData;
	X509_ALGO_IDENTIFIER *algID;
	BIT_STRING *signature;
	X509_CERTS *certs;

	uint8 *rawTbsResponseData;		/* ���� ������ ���� raw ������ */
	int rawTbsResponseDataLen;
} BASIC_OCSP_RESPONSE;

#ifndef WIN_INI_LOADLIBRARY_PKI

/*------------------------- �Լ� ���� -------------------------------------------*/

/*!
* \brief
* OCSP_CERT_ID ����ü�� �ʱ�ȭ �Լ�
* \returns
* OCSP_CERT_ID ����ü ������
*/
ISC_API OCSP_CERT_ID* new_OCSP_CERT_ID(void);

/*!
* \brief
* OCSP_CERT_ID ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_CERT_ID(OCSP_CERT_ID *unit);

/*!
* \brief
* OCSP_CERT_ID ����ü�� ����
* \param unit
* ������ OCSP_CERT_ID ����ü
*/
ISC_API void clean_OCSP_CERT_ID(OCSP_CERT_ID *unit);

/*!
* \brief
* OCSP_CERT_ID ����ü�� �ʱ�ȭ �Լ�
* \returns
* OCSP_CERT_ID ����ü ������
*/
ISC_API OCSP_SINGLE_REQUEST* new_OCSP_SINGLE_REQUEST(void);

/*!
* \brief
* OCSP_SINGLE_REQUEST ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_SINGLE_REQUEST(OCSP_SINGLE_REQUEST *unit);

/*!
* \brief
* OCSP_SINGLE_REQUEST ����ü�� ����
* \param unit
* ������ OCSP_SINGLE_REQUEST ����ü
*/
ISC_API void clean_OCSP_SINGLE_REQUEST(OCSP_SINGLE_REQUEST *unit);

/*!
* \brief
* OCSP_TBS_REQUEST ����ü�� �ʱ�ȭ �Լ�
* \returns
* OCSP_TBS_REQUEST ����ü ������
*/
ISC_API OCSP_TBS_REQUEST* new_OCSP_TBS_REQUEST(void);

/*!
* \brief
* OCSP_TBS_REQUEST ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_TBS_REQUEST(OCSP_TBS_REQUEST *unit);

/*!
* \brief
* OCSP_TBS_REQUEST ����ü�� ����
* \param unit
* ������ OCSP_TBS_REQUEST ����ü
*/
ISC_API void clean_OCSP_TBS_REQUEST(OCSP_TBS_REQUEST *unit);

/*!
* \brief
* OCSP_SIGNATURE ����ü�� �ʱ�ȭ �Լ�
* \returns
* OCSP_SIGNATURE ����ü ������
*/
ISC_API OCSP_SIGNATURE* new_OCSP_SIGNATURE(void);

/*!
* \brief
* OCSP_SIGNATURE ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_SIGNATURE(OCSP_SIGNATURE *unit);

/*!
* \brief
* OCSP_SIGNATURE ����ü�� ����
* \param unit
* ������ OCSP_SIGNATURE ����ü
*/
ISC_API void clean_OCSP_SIGNATURE(OCSP_SIGNATURE *unit);

/*!
* \brief
* OCSP_REQUEST ����ü�� �ʱ�ȭ �Լ�
* \returns
* OCSP_REQUEST ����ü ������
*/
ISC_API OCSP_REQUEST* new_OCSP_REQUEST(void);

/*!
* \brief
* OCSP_REQUEST ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_REQUEST(OCSP_REQUEST *unit);

/*!
* \brief
* OCSP_REQUEST ����ü�� ����
* \param unit
* ������ OCSP_REQUEST ����ü
*/
ISC_API void clean_OCSP_REQUEST(OCSP_REQUEST *unit);

/*!
* \brief
* OCSP_RESPONSE_BYTES ����ü�� �ʱ�ȭ �Լ�
* \returns
* OCSP_RESPONSE_BYTES ����ü ������
*/
ISC_API OCSP_RESPONSE_BYTES* new_OCSP_RESPONSE_BYTES(void);

/*!
* \brief
* OCSP_RESPONSE_BYTES ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_RESPONSE_BYTES(OCSP_RESPONSE_BYTES *unit);

/*!
* \brief
* OCSP_RESPONSE_BYTES ����ü�� ����
* \param unit
* ������ OCSP_RESPONSE_BYTES ����ü
*/
ISC_API void clean_OCSP_RESPONSE_BYTES(OCSP_RESPONSE_BYTES *unit);

/*!
* \brief
* OCSP_RESPONSE ����ü�� �ʱ�ȭ �Լ�
* \returns
* OCSP_RESPONSE ����ü ������
*/
ISC_API OCSP_RESPONSE* new_OCSP_RESPONSE(void);

/*!
* \brief
* OCSP_RESPONSE ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_RESPONSE(OCSP_RESPONSE *unit);

/*!
* \brief
* OCSP_RESPONSE ����ü�� ����
* \param unit
* ������ OCSP_RESPONSE ����ü
*/
ISC_API void clean_OCSP_RESPONSE(OCSP_RESPONSE *unit);

/*!
* \brief
* OCSP_RESPONDER_ID ����ü�� �ʱ�ȭ �Լ�
* \returns
* OCSP_RESPONDER_ID ����ü ������
*/
ISC_API OCSP_RESPONDER_ID* new_OCSP_RESPONDER_ID(void);

/*!
* \brief
* OCSP_RESPONDER_ID ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_RESPONDER_ID(OCSP_RESPONDER_ID *unit);

/*!
* \brief
* OCSP_RESPONDER_ID ����ü�� ����
* \param unit
* ������ OCSP_RESPONDER_ID ����ü
*/
ISC_API void clean_OCSP_RESPONDER_ID(OCSP_RESPONDER_ID *unit);

/*!
* \brief
* OCSP_REVOKED_INFO ����ü�� �ʱ�ȭ �Լ�
* \returns
* OCSP_REVOKED_INFO ����ü ������
*/
ISC_API OCSP_REVOKED_INFO* new_OCSP_REVOKED_INFO(void);

/*!
* \brief
* OCSP_REVOKED_INFO ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_REVOKED_INFO(OCSP_REVOKED_INFO *unit);

/*!
* \brief
* OCSP_REVOKED_INFO ����ü�� ����
* \param unit
* ������ OCSP_REVOKED_INFO ����ü
*/
ISC_API void clean_OCSP_REVOKED_INFO(OCSP_REVOKED_INFO *unit);

/*!
* \brief
* OCSP_CERT_STATUS ����ü�� �ʱ�ȭ �Լ�
* \returns
* OCSP_CERT_STATUS ����ü ������
*/
ISC_API OCSP_CERT_STATUS* new_OCSP_CERT_STATUS(void);

/*!
* \brief
* OCSP_CERT_STATUS ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_CERT_STATUS(OCSP_CERT_STATUS *unit);

/*!
* \brief
* OCSP_CERT_STATUS ����ü�� ����
* \param unit
* ������ OCSP_CERT_STATUS ����ü
*/
ISC_API void clean_OCSP_CERT_STATUS(OCSP_CERT_STATUS *unit);


/*!
* \brief
* OCSP_SINGLE_RESPONSE ����ü�� �ʱ�ȭ �Լ�
* \returns
* OCSP_SINGLE_RESPONSE ����ü ������
*/
ISC_API OCSP_SINGLE_RESPONSE* new_OCSP_SINGLE_RESPONSE(void);

/*!
* \brief
* OCSP_SINGLE_RESPONSE ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_SINGLE_RESPONSE(OCSP_SINGLE_RESPONSE *unit);

/*!
* \brief
* OCSP_SINGLE_RESPONSE ����ü�� ����
* \param unit
* ������ OCSP_SINGLE_RESPONSE ����ü
*/
ISC_API void clean_OCSP_SINGLE_RESPONSE(OCSP_SINGLE_RESPONSE *unit);

/*!
* \brief
* OCSP_RESPONSE_DATA ����ü�� �ʱ�ȭ �Լ�
* \returns
* OCSP_RESPONSE_DATA ����ü ������
*/
ISC_API OCSP_RESPONSE_DATA* new_OCSP_RESPONSE_DATA(void);

/*!
* \brief
* OCSP_RESPONSE_DATA ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_RESPONSE_DATA(OCSP_RESPONSE_DATA *unit);

/*!
* \brief
* OCSP_RESPONSE_DATA ����ü�� ����
* \param unit
* ������ OCSP_RESPONSE_DATA ����ü
*/
ISC_API void clean_OCSP_RESPONSE_DATA(OCSP_RESPONSE_DATA *unit);

/*!
* \brief
* BASIC_OCSP_RESPONSE ����ü�� �ʱ�ȭ �Լ�
* \returns
* BASIC_OCSP_RESPONSE ����ü ������
*/
ISC_API BASIC_OCSP_RESPONSE* new_BASIC_OCSP_RESPONSE(void);

/*!
* \brief
* BASIC_OCSP_RESPONSE ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_BASIC_OCSP_RESPONSE(BASIC_OCSP_RESPONSE *unit);

/*!
* \brief
* BASIC_OCSP_RESPONSE ����ü�� ����
* \param unit
* ������ BASIC_OCSP_RESPONSE ����ü
*/
ISC_API void clean_BASIC_OCSP_RESPONSE(BASIC_OCSP_RESPONSE *unit);


/*!
* \brief
* �ϳ��� ����� �������� ���� OCSP_REQUEST �� ������
* \param ocsp_request
* �Ҵ�� OCSP_REQUEST ����ü
* \param user_cert
* OCSP�� ���� ��ȿ�� ������ ������
* \param ca_cert
* user_cert �� �߱��� CA ������(NULL �� �����, �� ����� ���������� CA�� ����ŰID �� IssuerID �� ���� �� ���� ��쿡 ����)
* \param nonce
* OCSP ���ѻ� Replay-Attack �� �����ϰ� Request/Response ���� Ȯ���ϴµ� ����.(NULL �� ��� �ڵ����� ����)
* \param nonce_size
* �ܺο��� �����Ǵ� nonce �� ����
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS generate_single_OCSP_REQUEST(OCSP_REQUEST *ocsp_request, X509_CERT *user_cert, X509_CERT *ca_cert, uint8 *nonce, int nonce_size);

ISC_API ISC_STATUS generate_single_OCSP_REQUEST_Ex(OCSP_REQUEST *ocsp_request, X509_CERT *user_cert, X509_CERT *ca_cert, int default_hash_id, uint8 *nonce, int nonce_size);

ISC_API ISC_STATUS generate_single_OCSP_REQUEST_Ex_With_CI(OCSP_REQUEST *ocsp_request, X509_CERT *user_cert, X509_CERT *ca_cert, int default_hash_id, uint8 *nonce, int nonce_size, ISC_DH_UNIT* dh);

/*!
* \brief
* ���� ����� �������� ���� OCSP_REQUEST �� ������
* \param ocsp_request
* �Ҵ�� OCSP_REQUEST ����ü
* \param user_certs
* OCSP�� ���� ��ȿ�� ������ ��������
* \param ca_cert
* user_cert �� �߱��� CA ������(NULL �� �����, �� ����� ���������� CA�� ����ŰID �� IssuerID �� ���� �� ���� ��쿡 ����)
* \param nonce
* OCSP ���ѻ� Replay-Attack �� �����ϰ� Request/Response ���� Ȯ���ϴµ� ����.(NULL �� ��� �ڵ����� ����)
* \param nonce_size
* �ܺο��� �����Ǵ� nonce �� ����
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS generate_multi_OCSP_REQUEST(OCSP_REQUEST *ocsp_request, X509_CERTS *user_certs, X509_CERT *ca_cert, uint8 *nonce, int nonce_size);

/**
 * @brief
 * generate_signle_OCSP_REQUEST�� �ϳ��� OCSP_SINGLE_REQUEST�� ������ OCS_TBS_REQUEST �� �����ϰ�
 * generate_multi_OCSP_REQUEST�� ������ �߱��ڰ� ������ �������� OCSP_SINGLE_REQUEST�� ������ OCSP_TBS_REQUEST�� �����ϴµ�
 * �� ���迡�� �Ʒ��� ���� ������ �ִ�.
 *   1. ���� �ٸ� �߱��ڰ� ������ �������鿡 ���� OCS_TBS_REQEST�� ������ �� ����.
 *   2. singleRequestExtension�� ������ OCSP_TBS_REQUEST�� ������ �� ����.
 * �̿� �ϱ�� ���� �Լ��� �߰��Ͽ� ������ �ذ��Ѵ�.
 *   1. OCSP_SINGLE_REQUEST�� ������ ������ �� �ִ� �Լ�
 *   2. OCSP_SINGLE_REQUEST�� singleRequestExtension�� �߰��� �� �ִ� �Լ�
 *   3. ����ִ� OCSP_TBS_REQUEST�� ������ �� �ִ� �Լ�
 *   4. OCSP_TBS_REQUEST�� OCSP_SINGLE_REQUEST�� �߰��� �� �ִ� �Լ�
 *   5. OCSP_TBS_REQUEST�� requestExtension�� �߰��� �� �ִ� �Լ�
 * @author kwangho.jung@initech.com
 * @date 2021/04/10
 */

/**
 * @brief �־��� user_cert, ca_cert ���� �ʿ��� ���� �����Ͽ� OCSP_SINGLE_REQUEST ����ü�� �����Ѵ�.
 *
 * @param ocsp_single_request singleRequestExtension�� ����ִ� OCSP_SINGLE_REQUEST ����ü (out)
 * @param user_cert ����� ������
 * @param ca_cert �߱��� ������
 * @param hash_id ����Ű�� digest�Ҷ� ����� �ؽ� �˰���
 * @return ISC_API 0:success, others:fail
 */
ISC_API ISC_STATUS generate_OCSP_SINGLE_REQUEST(OCSP_SINGLE_REQUEST** ocsp_single_request, X509_CERT* user_cert, X509_CERT* ca_cert, int hash_id);

/**
 * @brief OCSP_SINGLE_REQUEST �� singleRequestExtension �� �߰��Ѵ�.
 *
 * @param ocsp_single_request singleRequestExtension�� �߰��� ���
 * @param singleRequestExtension OCSP_SINGLE_REQUEST�� �߰��� singleRequestExtension
 * @return ISC_API 0:success, others:fail
 */
ISC_API ISC_STATUS add_OCSP_SINGLE_REQUEST_EXTENSION(OCSP_SINGLE_REQUEST* ocsp_single_request, X509_EXTENSION* singleRequestExtension);

/**
 * @brief CID ��û�� ���� OCSP_SINGLE_REQUEST�� �߰��� singleRequestExtension�� �����Ѵ�.
 *
 * @param extension CID ��û extension (out)
 * @param version CID ��û ����
 * @param cipherID CID ��ĪŰ ��ȣȭ �˰���
 * @param dh ����Ű�� ���� dh Ű��
 * @return ISC_API 0:success, others:fail
 */
ISC_API ISC_STATUS generate_OCSP_SINGLE_REQUEST_EXTENSION_dhcid(X509_EXTENSION** extension, short version, int cipherID, ISC_DH_UNIT* dh);

/**
 * @brief OCSP_SINGLE_REQUEST�� �������� ���� �� OCSP_TBS_REQUEST�� ������ OCSP_REQUEST�� �����Ѵ�.
 *
 * @param ocsp_request �� OCSP_TBS_REQUEST�� ������ OCSP_REQUEST (out)
 * @param version OCSP_TBS_REQUEST ����
 * @return ISC_API 0:success, others:fail
 */
ISC_API ISC_STATUS generate_empty_OCSP_REQUEST(OCSP_REQUEST **ocsp_request, int version);

/**
 * @brief OCSP_REQUEST ��OCSP_TBS_REQUEST�� OCSP_SINGLE_REQUEST�� �߰��Ѵ�.
 *
 * @param ocsp_request OCSP_SINGLE_REQUEST�� �߰��� OCSP_TBS_REQUEST�� ������ OCSP_REQUEST
 * @param ocsp_single_request OCSP_REQUEST�� OCSP_TBS_REQUEST�� �߰��� OCSP_SINGLE_REQUEST
 * @return ISC_API 0:success, others:fail
 */
ISC_API ISC_STATUS add_OCSP_SINGLE_REQUEST(OCSP_REQUEST* ocsp_request, OCSP_SINGLE_REQUEST* ocsp_single_request);

/**
 * @brief OCSP_REQUEST�� requestExtension�� �߰��Ѵ�.
 *
 * @param ocsp_request requestExtension�� �߰��� OCSP_REQUEST
 * @param requestExtension OCSP_REQUEST�� �߰��� requestExtension
 * @return ISC_API 0:success, others:fail
 */
ISC_API ISC_STATUS add_OCSP_REQUEST_EXTENSION(OCSP_REQUEST* ocsp_request, X509_EXTENSION* requestExtension);

/**
 * @brief replay attack�� �����ϴ� nonce �� ������ requestExtension�� �����Ѵ�.
 *
 * @param extension nonce Extension (out)
 * @param nonce nonce
 * @param nonce_size nonce ũ��
 * @return ISC_API 0:success, others:fail
 */
ISC_API ISC_STATUS generate_OCSP_REQUEST_EXTENSION_nonce(X509_EXTENSION** extension, uint8* nonce, int nonce_size);
/*!
* \brief
* OCSP_REQUEST �� nonce ���̸� ������.
* \param ocsp_request
* �Ҵ�� OCSP_REQUEST ����ü
* \return
* nonce ����
*/
ISC_API int get_OCSP_REQUEST_nonce_length(OCSP_REQUEST *ocsp_request);

/*!
* \brief
* OCSP_REQUEST �� nonce ���̸� ������.
* \param ocsp_request
* �Ҵ�� OCSP_REQUEST ����ü
* \param nonceBuf
* Nonce �� �� �Ҵ�� �޸� ����
* \returns
* -# 0 �̻� : nonce ����
* -# 0 �̸� : ���� (�����ڵ�)
*/

ISC_API int get_OCSP_REQUEST_nonce(OCSP_REQUEST *ocsp_request, uint8 **nonceBuf);
/*!
* \brief
* OCSP_REQUEST �� ���� ������ ������
* \param ocsp_request
* �Ҵ�� OCSP_REQUEST ����ü
* \param ocsp_cert
* �����ڿ� �ش��ϴ� OCSP ���� ������ ������
* \param ocsp_pvkey
* �������� ����Ű
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS sign_OCSP_REQUEST(OCSP_REQUEST *ocsp_request, X509_CERT *ocsp_cert, P8_PRIV_KEY_INFO *ocsp_pvkey);

/*!
* \brief
* OCSP_REQUEST �� ���� ������ ������
* \param ocsp_request
* �Ҵ�� OCSP_REQUEST ����ü
* \param ocsp_cert
* �����ڿ� �ش��ϴ� OCSP ���� ������ ������
* \param ocsp_pvkey
* �������� ����Ű
* \param sign_hash
* ����������ؽ�(ISC_SHA1, ISC_SHA256, ISC_MD5 .. )
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS sign_OCSP_REQUEST_ex(OCSP_REQUEST *ocsp_request, X509_CERT *ocsp_cert, P8_PRIV_KEY_INFO *ocsp_pvkey, int sign_hash);

ISC_API ISC_STATUS sign_OCSP_REQUEST_Ex(OCSP_REQUEST *ocsp_request, X509_CERT *ocsp_cert, P8_PRIV_KEY_INFO *ocsp_pvkey, int sign_hash, char pad_mode);

/*!
* \brief
* OCSP_SINGLE_REQUEST ����ü�� Sequence�� Encode �Լ�
* \param sreq
* OCSP_SINGLE_REQUEST ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS OCSP_SINGLE_REQUEST_to_Seq(OCSP_SINGLE_REQUEST *sreq, SEQUENCE **seq);

/*!
* \brief
* OCSP_TBS_REQUEST ����ü�� Sequence�� Encode �Լ�
* \param tbs
* OCSP_TBS_REQUEST ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS OCSP_TBS_REQUEST_to_Seq(OCSP_TBS_REQUEST *tbs, SEQUENCE **seq);

/*!
* \brief
* OCSP_REQUEST ����ü�� Sequence�� Encode �Լ�
* \param oscp_req
* OCSP_REQUEST ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS OCSP_REQUEST_to_Seq(OCSP_REQUEST *oscp_req, SEQUENCE **seq);

/*!
* \brief
* Sequence�� OCSP_RESPONSE �� ���ڵ� ��
* \param in
* Decoding Sequece ����ü
* \param out
* OCSP_RESPONSE ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS Seq_to_OCSP_RESPONSE(SEQUENCE *in, OCSP_RESPONSE **out);

/*!
* \brief
* Sequence�� OCSP_RESPONSE_BYTES �� ���ڵ� ��
* \param in
* Decoding Sequece ����ü
* \param out
* OCSP_RESPONSE_BYTES ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS Seq_to_OCSP_RESPONSE_BYTES(SEQUENCE *in, OCSP_RESPONSE_BYTES **out);

/*!
* \brief
* OCSP_RESPONSE_BYTES �κ��� BASIC_OCSP_RESPONSE �� ����
* \param in
* OCSP_RESPONSE_BYTES ����ü
* \returns
* BASIC_OCSP_RESPONSE ����ü
*/
ISC_API BASIC_OCSP_RESPONSE *get_BASIC_OCSP_RESPONSE(OCSP_RESPONSE_BYTES *in);

/*!
* \brief
* Sequence�� OCSP_RESPONSE_DATA �� ���ڵ� ��
* \param in
* Decoding Sequece ����ü
* \param out
* OCSP_RESPONSE_DATA ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS Seq_to_OCSP_RESPONSE_DATA(SEQUENCE *in, OCSP_RESPONSE_DATA **out);

/*!
* \brief
* Sequence�� OCSP_SINGLE_RESPONSE �� ���ڵ� ��
* \param in
* Decoding Sequece ����ü
* \param out
* OCSP_SINGLE_RESPONSE ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS Seq_to_OCSP_SINGLE_RESPONSE(SEQUENCE *in, OCSP_SINGLE_RESPONSE **out);

/*!
* \brief
* Sequence�� OCSP_CERT_ID �� ���ڵ� ��
* \param in
* Decoding Sequece ����ü
* \param out
* OCSP_CERT_ID ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS Seq_to_OCSP_CERT_ID(SEQUENCE *in, OCSP_CERT_ID **out);

/*!
* \brief
* Sequence�� OCSP_REVOKED_INFO �� ���ڵ� ��
* \param in
* Decoding Sequece ����ü
* \param out
* OCSP_REVOKED_INFO ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS Seq_to_OCSP_REVOKED_INFO(SEQUENCE *in, OCSP_REVOKED_INFO **out);

/*!
* \brief
* BASIC_OCSP_RESPONSE �� ������ �����ϰ�, NONCE �� �ùٸ��� üũ��.
* \param basicOcspRes
* ������ BASIC_OCSP_RESPONSE ����ü
* \param caCert
* ���� ������ ����� ocsp ����, �� CA ������(NULL �� ��� basicOcspRes ���ο��� ã��)
* \param nonce
* ��û�� ������ nonce �� Response ���� üũ �ϱ����� nonce ��(NULL �� ��� �˻� ���� ����.)
* \param nonceLen
* nonce �� ����
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS verify_BASIC_OCSP_RESPONSE(BASIC_OCSP_RESPONSE *basicOcspRes, X509_CERT *caCert, uint8 *nonce, int nonceLen);

ISC_API ISC_STATUS verify_BASIC_OCSP_RESPONSE_Ex(BASIC_OCSP_RESPONSE *basicOcspRes, X509_CERT *caCert, char pad_mode, uint8 *nonce, int nonceLen);

/*!
* \brief
* BASIC_OCSP_RESPONSE �� ������ �����ϰ�, NONCE �� �ùٸ��� üũ��.
* \param basicOcspRes
* ������ BASIC_OCSP_RESPONSE ����ü
* \param caCert
* ���� ������ ����� ocsp ����, �� CA ������(NULL �� ��� basicOcspRes ���ο��� ã��)
* \param nonce
* ��û�� ������ nonce �� Response ���� üũ �ϱ����� nonce ��(NULL �� ��� �˻� ���� ����.)
* \param nonceLen
* nonce �� ����
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS verfy_BASIC_OCSP_RESPONSE(BASIC_OCSP_RESPONSE *basicOcspRes, X509_CERT *caCert, uint8 *nonce, int nonceLen);

/*!
* \brief
* BASIC_OCSP_RESPONSE �� ���ο� �����ϴ� ������ ���� ���� ������ ������.
* \param basicOcspRes
* BASIC_OCSP_RESPONSE ����ü
* \returns
* OCSP_STATUS ����
*/
ISC_API int get_CERT_STATUS_count_from_OCSP_RESPONSE(BASIC_OCSP_RESPONSE *basicOcspRes);

/*!
* \brief
* BASIC_OCSP_RESPONSE �� ���� ����� �������� ��ȿ������ �˻���.
* \param basicOcspRes
* BASIC_OCSP_RESPONSE ����ü
* \param userCert
* ���� ������ ����� ������
* \param revokeReasonCode
* ��� �� ��� ��� ���� �ڵ带 ������ �ּ�
* \returns
* -# OCSP_CERT_STATUS_GOOD : ��ȿ
* -# OCSP_CERT_STATUS_REVOKED : ���
* -# OCSP_CERT_STATUS_UNKNOWN : �˼� ����.
*/
ISC_API ISC_STATUS get_CERT_STATUS_from_OCSP_RESPONSE(BASIC_OCSP_RESPONSE *basicOcspRes, X509_CERT *userCert, int *revokeReasonCode);

/*!
* \brief
* BASIC_OCSP_RESPONSE ���� ������ ���� �������� ������.
* \param basicOcspRes
* BASIC_OCSP_RESPONSE ����ü
* \param index
* BASIC_OCSP_RESPONSE ���� ���� ���� index ��
* \param revokeReasonCode
* ��� �� ��� ��� ���� �ڵ带 ������ �ּ�
* \returns
* -# OCSP_CERT_STATUS_GOOD : ��ȿ
* -# OCSP_CERT_STATUS_REVOKED : ���
* -# OCSP_CERT_STATUS_UNKNOWN : �˼� ����.
*/
ISC_API	ISC_STATUS get_CERT_STATUS_from_OCSP_RESPONSE_index(BASIC_OCSP_RESPONSE *basicOcspRes, int index, ISC_STATUS *revokeReasonCode);

/*!
* \brief
* BASIC_OCSP_RESPONSE ���� ������ ���� �������� ������.
* \param basicOcspRes
* BASIC_OCSP_RESPONSE ����ü
* \param index
* BASIC_OCSP_RESPONSE ���� ���� ���� index ��
* \param revokeReasonCode
* ��� �� ��� ��� ���� �ڵ带 ������ �ּ�
* \param dhci_res
* SINGLE_RESPONSE �� single response extension �� CI ������ ��ȯ�Ѵ�.
* \returns
* -# OCSP_CERT_STATUS_GOOD : ��ȿ
* -# OCSP_CERT_STATUS_REVOKED : ���
* -# OCSP_CERT_STATUS_UNKNOWN : �˼� ����.
*/
ISC_API	ISC_STATUS get_CERT_STATUS_from_OCSP_RESPONSE_index_ex(BASIC_OCSP_RESPONSE *basicOcspRes, int index, ISC_STATUS *revokeReasonCode, DHCIRES** dhci_res);

/*!
* \brief
* Sequence�� OCSP_REQUEST �� ���ڵ� ��
* \param in
* Decoding Sequece ����ü
* \param out
* OCSP_REQUEST ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS Seq_to_OCSP_REQUEST(SEQUENCE *in, OCSP_REQUEST **out);

/*!
* \brief
* Sequence�� OCSP_TBS_REQUEST �� ���ڵ� ��
* \param in
* Decoding Sequece ����ü
* \param out
* OCSP_TBS_REQUEST ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS Seq_to_OCSP_TBS_REQUEST(SEQUENCE *seq, OCSP_TBS_REQUEST **tbs);

/*!
* \brief
* Sequence�� OCSP_SINGLE_REQUEST �� ���ڵ� ��
* \param in
* Decoding Sequece ����ü
* \param out
* OCSP_SINGLE_REQUEST ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS Seq_to_OCSP_SINGLE_REQUEST(SEQUENCE* in, OCSP_SINGLE_REQUEST** out);

/*!
* \brief
* OCSP_REQUEST���� signature ���� ���θ� ������
* \param in
* OCSP_REQUEST ����ü
* \returns
* - 1 : ����
* - 0 : �������� ����
*/
ISC_API int is_OCSP_REQUEST_signature(OCSP_REQUEST *ocspReq);
ISC_API int is_OCSP_REQUEST_signature_cert(OCSP_REQUEST *ocspReq);

/*!
* \brief
* OCSP_REQUEST�� ������ �������� ������
* \param in
* OCSP_REQUEST ����ü
* \returns
* -# X509_CERT ������ : Success
* -# NULL : ���� (�����ڵ�)
*/
ISC_API X509_CERT *get_OCSP_REQUEST_signature_cert(OCSP_REQUEST *ocspReq);

/*!
* \brief
* OCSP_REQUEST�� ������
* \param in
* OCSP_REQUEST ����ü
* \param caCert
* ���� ������ ����� ocsp ����, �� CA ������(NULL �� ��� ocspReq ���ο��� ã��)
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS verify_OCSP_REQUEST(OCSP_REQUEST *ocspReq);

ISC_API ISC_STATUS verify_OCSP_REQUEST_Ex(OCSP_REQUEST *ocspReq, char pad_mode);

/*!
* \brief
* OCSP_SINGLE_REQUEST�� ������ ����.
* \param ocspReq
* ������ ���� OCSP_REQUEST ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API int get_OCSP_REQUEST_list_count(OCSP_REQUEST *ocspReq);

/*!
* \brief
* OCSP_SINGLE_REQUEST�� ����.
* \param ocspReq
* ������ ���� OCSP_REQUEST ����ü
* \param singleReq
* ���� ���� OCSP_SINGLE_REQUEST ����ü
* \param index
* OCSP_REQUEST�� OCSP_SINGLE_REQUEST index
* \returns
* -# OCSP_SINGLE_REQUEST�� ����
*/
ISC_API ISC_STATUS get_OCSP_REQUEST_list(OCSP_REQUEST *ocspReq, OCSP_SINGLE_REQUEST **singleReq, int index);

/*!
* \brief
* OCSP_RESPONSE�� ������.
* \param ocspResponse
* ���� ���� OCSP_RESPONSE ����ü
* \param ocspResBytes
* OCSP_RESPONSE ����ü�� ������ OCSP_RESPONSE_BYTES ����ü
* \param status
* OCSP_RESPONSE ���� ����(OCSP_RESPONSE_STATUS_SUCCESSFUL ~ OCSP_RESPONSE_STATUS_UNAUTHORIZED)
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS generate_OCSP_RESPONSE(OCSP_RESPONSE **ocspResponse, OCSP_RESPONSE_BYTES* ocspResBytes, int status);

/*!
* \brief
* OCSP_RESPONSE_BYTES�� ������.
* \param ocspResBytes
* ���� ���� OCSP_RESPONSE_BYTES ����ü
* \param ocspBasic
* OCSP_RESPONSE_BYTES ����ü�� ������ BASIC_OCSP_RESPONSE ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS generate_OCSP_RESPONSE_BYTES(OCSP_RESPONSE_BYTES** ocspResBytes, BASIC_OCSP_RESPONSE *ocspBasic);

/*!
* \brief
* BASIC_OCSP_RESPONSE�� ������.
* \param ocspBasic
* ���� ���� BASIC_OCSP_RESPONSE ����ü
* \param resData
* BASIC_OCSP_RESPONSE ����ü�� ������ OCSP_RESPONSE_DATA ����ü
* \param caCert
* ���� ������ ����� ocsp ����, �� CA ������
* \param ca_pvkey
* ���� ����� ocsp ����Ű
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS generate_BASIC_OCSP_RESPONSE(BASIC_OCSP_RESPONSE **ocspBasic, OCSP_RESPONSE_DATA *resData, X509_CERT *caCert, P8_PRIV_KEY_INFO *ca_pvkey);

/*!
* \brief
* BASIC_OCSP_RESPONSE�� ������.
* \param ocspBasic
* ���� ���� BASIC_OCSP_RESPONSE ����ü
* \param resData
* BASIC_OCSP_RESPONSE ����ü�� ������ OCSP_RESPONSE_DATA ����ü
* \param caCert
* ���� ������ ����� ocsp ����, �� CA ������
* \param ca_pvkey
* ���� ����� ocsp ����Ű
* \param sign_hash
* ����������ؽ�(ISC_SHA1, ISC_SHA256, ISC_MD5 .. )
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/

ISC_API ISC_STATUS generate_BASIC_OCSP_RESPONSE_ex(BASIC_OCSP_RESPONSE **ocspBasic, OCSP_RESPONSE_DATA *resData, X509_CERT *caCert, P8_PRIV_KEY_INFO *ca_pvkey, int sign_hash);

ISC_API ISC_STATUS generate_BASIC_OCSP_RESPONSE_Ex(BASIC_OCSP_RESPONSE **ocspBasic, OCSP_RESPONSE_DATA *resData, X509_CERT *caCert, P8_PRIV_KEY_INFO *ca_pvkey, int sign_hash, char pad_mode);

/*!
* \brief
* OCSP_RESPONSE_DATA�� ������.
* \param resData
* ���� ���� BASIC_OCSP_RESPONSE ����ü
* \param caCert
* responder id�� ������ ocsp ����, �� CA ������
* \param responseIDType
* response id type (OCSP_RESPONDER_ID_TYPE_NAME, OCSP_RESPONDER_ID_TYPE_KEYHASH)
* \param nonce
* ������ ���� ������ ���� nonce ��(NULL �� ��� ���� ����.)
* \param nonceLen
* nonce �� ����
* \param add_extended_revoke
* extended revoke Ȯ�� �߰� ����
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS generate_OCSP_RESPONSE_DATA(OCSP_RESPONSE_DATA **resData, X509_CERT *caCert, uint32 responseIDType, int version, uint8 *nonce, int nonceLen, int add_extended_revoke);

/*!
* \brief
* OCSP_RESPONSE_DATA�� ������Ʈ ��.
* \param resData
* ������Ʈ�� response data
* \param add_extended_revoke
* extended revoke Ȯ�� �߰� ����
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS update_OCSP_RESPONSE_DATA(OCSP_RESPONSE_DATA *resData, int add_extended_revoke);

/*!
* \brief
* OCSP_SINGLE_RESPONSE�� �����Ͽ� OCSP_RESPONSE_DATA�� �߰�
* \param resData
* ���� ���� BASIC_OCSP_RESPONSE ����ü
* \param singleReq
* OCSP_SINGLE_RESPONSE�� ����� �Ǵ� OCSP_SINGLE_REQUEST ����ü 
* \param certStatus
* ��û�� �������� ���� ����(OCSP_CERT_STATUS_GOOD ~ OCSP_CERT_STATUS_UNKNOWN)
* \param revokedInfo
* ���°� OCSP_CERT_STATUS_REVOKED �� ���, ���Ե� OCSP_REVOKED_INFO ����ü(OCSP_CERT_STATUS_GOOD, OCSP_CERT_STATUS_UNKNOWN �� ��� NULL)
* \param thisUpdate
* CRL�� thisUpdate �ð�
* \param nextUpdate
* CRL�� nextUpdate �ð�
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS add_single_OCSP_RESPONSE(OCSP_RESPONSE_DATA *resData, OCSP_SINGLE_REQUEST *singleReq, uint32 certStatus, OCSP_REVOKED_INFO* revokedInfo, GENERALIZED_TIME *thisUpdate, GENERALIZED_TIME *nextUpdate);

/*!
* \brief
* OCSP_SINGLE_RESPONSE�� �����Ͽ� OCSP_RESPONSE_DATA�� �߰�
* \param resData
* ���� ���� BASIC_OCSP_RESPONSE ����ü
* \param singleReq
* OCSP_SINGLE_RESPONSE�� ����� �Ǵ� OCSP_SINGLE_REQUEST ����ü 
* \param certStatus
* ��û�� �������� ���� ����(OCSP_CERT_STATUS_GOOD ~ OCSP_CERT_STATUS_UNKNOWN)
* \param revokedInfo
* ���°� OCSP_CERT_STATUS_REVOKED �� ���, ���Ե� OCSP_REVOKED_INFO ����ü(OCSP_CERT_STATUS_GOOD, OCSP_CERT_STATUS_UNKNOWN �� ��� NULL)
* \param thisUpdate
* CRL�� thisUpdate �ð�
* \param nextUpdate
* CRL�� nextUpdate �ð�
* \param dhci_res
* CI ��û�� ���� ����
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS add_single_OCSP_RESPONSE_ex(OCSP_RESPONSE_DATA *resData, OCSP_SINGLE_REQUEST *singleReq, uint32 certStatus, OCSP_REVOKED_INFO* revokedInfo, GENERALIZED_TIME *thisUpdate, GENERALIZED_TIME *nextUpdate, DHCIRES* dhci_res);

/**
 * @brief CID ������ ���� OCSP_SINGLE_RESPONSE �� �߰��� singleResponseExtension �� �����Ѵ�.
 *
 * @param extension CID ���� extension (out)
 * @param dhci extension ���� �߰��� DHCIRES ����
 * @return ISC_API 0:success, others:fail
 */
ISC_API ISC_STATUS generate_OCSP_SINGLE_RESPONSE_EXTENSION_dhcid(X509_EXTENSION** extension, DHCIRES* dhci);

/**
 * @brief CID ������ ������ singleResponseExtension ���� CID������ �����Ѵ�.
 *
 * @param dhci extension ���� ������ DHCIRES ���� (out)
 * @param extension CID ���� extension
 * @return ISC_API 0:success, others:fail
 */
ISC_API ISC_STATUS get_OCSP_SINGLE_RESPONSE_EXTENSION_dhcid(DHCIRES** dhci, X509_EXTENSION* extension);

/**
 * @brief �̱۸��������� extension�� �߰��Ѵ�.
 *
 * @param ocsp_single_response   �̱� ��������
 * @param singleResponseExtension  �̱� �������� Ȯ��
 * @return ISC_API  0:���� others: ����
 */
ISC_API ISC_STATUS add_OCSP_SINGLE_RESPONSE_EXTENSION(OCSP_SINGLE_RESPONSE* ocsp_single_response, X509_EXTENSION* singleResponseExtension);

/**
 * @brief RESPONSE_DATA �� extension�� �߰��Ѵ�.
 *
 * @param ocsp_response_data   ��������
 * @param responseExtension  �������� Ȯ��
 * @param check_duplicate	�ߺ� üũ
 * @return ISC_API  0:���� others: ����
 */
ISC_API ISC_STATUS add_OCSP_RESPONSE_DATA_EXTENSION(OCSP_RESPONSE_DATA* ocsp_response_data, X509_EXTENSION* responseExtension, int check_duplicate);

/*!
* \brief
* OCSP_CERT_ID�� ����
* \param resData
* ������ OCSP_CERT_ID ����ü
* \returns
* -# ����� OCSP_CERT_ID : Success
* -# NULL : ���� 
*/
ISC_API OCSP_CERT_ID *dup_OCSP_CERT_ID(OCSP_CERT_ID *certID);

/*!
* \brief
* OCSP_REVOKED_INFO�� ����
* \param resData
* ������ OCSP_REVOKED_INFO ����ü
* \returns
* -# ����� OCSP_REVOKED_INFO : Success
* -# NULL : ���� 
*/
ISC_API OCSP_REVOKED_INFO *dup_OCSP_REVOKED_INFO(OCSP_REVOKED_INFO *revokedInfo);

/*!
* \brief
* OCSP_SINGLE_RESPONSE ����ü�� Sequence�� Encode �Լ�
* \param sRes
* OCSP_SINGLE_RESPONSE ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS OCSP_SINGLE_RESPONSE_to_Seq(OCSP_SINGLE_RESPONSE *sRes, SEQUENCE **seq);

/*!
* \brief
* OCSP_REVOKED_INFO ����ü�� Sequence�� Encode �Լ�
* \param revokeInfo
* OCSP_REVOKED_INFO ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS OCSP_REVOKED_INFO_to_Seq(OCSP_REVOKED_INFO *revokeInfo, SEQUENCE **seq);

/*!
* \brief
* BASIC_OCSP_RESPONSE ����ü�� Sequence�� Encode �Լ�
* \param ocspBasic
* BASIC_OCSP_RESPONSE ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS BASIC_OCSP_RESPONSE_to_Seq(BASIC_OCSP_RESPONSE *ocspBasic, SEQUENCE **seq);

/*!
* \brief
* OCSP_RESPONSE ����ü�� Sequence�� Encode �Լ�
* \param ocspRes
* BASIC_OCSP_RESPONSE ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS OCSP_RESPONSE_to_Seq(OCSP_RESPONSE *ocspRes, SEQUENCE **seq);

/*!
* \brief
* OCSP_RESPONSE_DATA ����ü�� Sequence�� Encode �Լ�
* \param resData
* OCSP_RESPONSE_DATA ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS OCSP_RESPONSE_DATA_to_Seq(OCSP_RESPONSE_DATA *resData, SEQUENCE **seq);

/*!
* \brief
* OCSP_RESPONSE_BYTES ����ü�� Sequence�� Encode �Լ�
* \param resBytes
* OCSP_RESPONSE_BYTES ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS OCSP_RESPONSE_BYTES_to_Seq(OCSP_RESPONSE_BYTES *resBytes, SEQUENCE **seq);

#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(OCSP_CERT_ID*, new_OCSP_CERT_ID, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_OCSP_CERT_ID, (OCSP_CERT_ID *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_OCSP_CERT_ID, (OCSP_CERT_ID *unit), (unit) );
INI_RET_LOADLIB_PKI(OCSP_SINGLE_REQUEST*, new_OCSP_SINGLE_REQUEST, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_OCSP_SINGLE_REQUEST, (OCSP_SINGLE_REQUEST *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_OCSP_SINGLE_REQUEST, (OCSP_SINGLE_REQUEST *unit), (unit) );
INI_RET_LOADLIB_PKI(OCSP_TBS_REQUEST*, new_OCSP_TBS_REQUEST, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_OCSP_TBS_REQUEST, (OCSP_TBS_REQUEST *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_OCSP_TBS_REQUEST, (OCSP_TBS_REQUEST *unit), (unit) );
INI_RET_LOADLIB_PKI(OCSP_SIGNATURE*, new_OCSP_SIGNATURE, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_OCSP_SIGNATURE, (OCSP_SIGNATURE *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_OCSP_SIGNATURE, (OCSP_SIGNATURE *unit), (unit) );
INI_RET_LOADLIB_PKI(OCSP_REQUEST*, new_OCSP_REQUEST, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_OCSP_REQUEST, (OCSP_REQUEST *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_OCSP_REQUEST, (OCSP_REQUEST *unit), (unit) );
INI_RET_LOADLIB_PKI(OCSP_RESPONSE_BYTES*, new_OCSP_RESPONSE_BYTES, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_OCSP_RESPONSE_BYTES, (OCSP_RESPONSE_BYTES *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_OCSP_RESPONSE_BYTES, (OCSP_RESPONSE_BYTES *unit), (unit) );
INI_RET_LOADLIB_PKI(OCSP_RESPONSE*, new_OCSP_RESPONSE, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_OCSP_RESPONSE, (OCSP_RESPONSE *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_OCSP_RESPONSE, (OCSP_RESPONSE *unit), (unit) );
INI_RET_LOADLIB_PKI(OCSP_RESPONDER_ID*, new_OCSP_RESPONDER_ID, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_OCSP_RESPONDER_ID, (OCSP_RESPONDER_ID *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_OCSP_RESPONDER_ID, (OCSP_RESPONDER_ID *unit), (unit) );
INI_RET_LOADLIB_PKI(OCSP_REVOKED_INFO*, new_OCSP_REVOKED_INFO, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_OCSP_REVOKED_INFO, (OCSP_REVOKED_INFO *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_OCSP_REVOKED_INFO, (OCSP_REVOKED_INFO *unit), (unit) );
INI_RET_LOADLIB_PKI(OCSP_CERT_STATUS*, new_OCSP_CERT_STATUS, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_OCSP_CERT_STATUS, (OCSP_CERT_STATUS *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_OCSP_CERT_STATUS, (OCSP_CERT_STATUS *unit), (unit) );
INI_RET_LOADLIB_PKI(OCSP_SINGLE_RESPONSE*, new_OCSP_SINGLE_RESPONSE, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_OCSP_SINGLE_RESPONSE, (OCSP_SINGLE_RESPONSE *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_OCSP_SINGLE_RESPONSE, (OCSP_SINGLE_RESPONSE *unit), (unit) );
INI_RET_LOADLIB_PKI(OCSP_RESPONSE_DATA*, new_OCSP_RESPONSE_DATA, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_OCSP_RESPONSE_DATA, (OCSP_RESPONSE_DATA *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_OCSP_RESPONSE_DATA, (OCSP_RESPONSE_DATA *unit), (unit) );
INI_RET_LOADLIB_PKI(BASIC_OCSP_RESPONSE*, new_BASIC_OCSP_RESPONSE, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_BASIC_OCSP_RESPONSE, (BASIC_OCSP_RESPONSE *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_BASIC_OCSP_RESPONSE, (BASIC_OCSP_RESPONSE *unit), (unit) );
INI_RET_LOADLIB_PKI(ISC_STATUS, generate_single_OCSP_REQUEST, (OCSP_REQUEST *ocsp_request, X509_CERT *user_cert, X509_CERT *ca_cert, uint8 *nonce, int nonce_size), (ocsp_request,user_cert,ca_cert,nonce,nonce_size), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, generate_multi_OCSP_REQUEST, (OCSP_REQUEST *ocsp_request, X509_CERTS *user_certs, X509_CERT *ca_cert, uint8 *nonce, int nonce_size), (ocsp_request,user_certs,ca_cert,nonce,nonce_size), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_OCSP_REQUEST_nonce_length, (OCSP_REQUEST *ocsp_request), (ocsp_request), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_OCSP_REQUEST_nonce, (OCSP_REQUEST *ocsp_request, uint8 **nonceBuf), (ocsp_request,nonceBuf), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, sign_OCSP_REQUEST, (OCSP_REQUEST *ocsp_request, X509_CERT *ocsp_cert, P8_PRIV_KEY_INFO *ocsp_pvkey), (ocsp_request,ocsp_cert,ocsp_pvkey), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, OCSP_SINGLE_REQUEST_to_Seq, (OCSP_SINGLE_REQUEST *sreq, SEQUENCE **seq), (sreq,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, OCSP_TBS_REQUEST_to_Seq, (OCSP_TBS_REQUEST *tbs, SEQUENCE **seq), (tbs,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, OCSP_REQUEST_to_Seq, (OCSP_REQUEST *oscp_req, SEQUENCE **seq), (oscp_req,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_OCSP_RESPONSE, (SEQUENCE *in, OCSP_RESPONSE **out), (in,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_OCSP_RESPONSE_BYTES, (SEQUENCE *in, OCSP_RESPONSE_BYTES **out), (in,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(BASIC_OCSP_RESPONSE*, get_BASIC_OCSP_RESPONSE, (OCSP_RESPONSE_BYTES *in), (in), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_OCSP_RESPONSE_DATA, (SEQUENCE *in, OCSP_RESPONSE_DATA **out), (in,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_OCSP_SINGLE_RESPONSE, (SEQUENCE *in, OCSP_SINGLE_RESPONSE **out), (in,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_OCSP_CERT_ID, (SEQUENCE *in, OCSP_CERT_ID **out), (in,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_OCSP_REVOKED_INFO, (SEQUENCE *in, OCSP_REVOKED_INFO **out), (in,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, verify_BASIC_OCSP_RESPONSE, (BASIC_OCSP_RESPONSE *basicOcspRes, X509_CERT *caCert, uint8 *nonce, int nonceLen), (basicOcspRes,caCert,nonce,nonceLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, verfy_BASIC_OCSP_RESPONSE, (BASIC_OCSP_RESPONSE *basicOcspRes, X509_CERT *caCert, uint8 *nonce, int nonceLen), (basicOcspRes,caCert,nonce,nonceLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_CERT_STATUS_count_from_OCSP_RESPONSE, (BASIC_OCSP_RESPONSE *basicOcspRes), (basicOcspRes), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, get_CERT_STATUS_from_OCSP_RESPONSE, (BASIC_OCSP_RESPONSE *basicOcspRes, X509_CERT *userCert, int *revokeReasonCode), (basicOcspRes,userCert,revokeReasonCode), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, get_CERT_STATUS_from_OCSP_RESPONSE_index, (BASIC_OCSP_RESPONSE *basicOcspRes, int index, ISC_STATUS *revokeReasonCode), (basicOcspRes,index,revokeReasonCode), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_OCSP_REQUEST, (SEQUENCE *in, OCSP_REQUEST **out), (in,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_OCSP_TBS_REQUEST, (SEQUENCE *seq, OCSP_TBS_REQUEST **tbs), (seq,tbs), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_OCSP_SINGLE_REQUEST, (SEQUENCE* in, OCSP_SINGLE_REQUEST** out), (in,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, is_OCSP_REQUEST_signature, (OCSP_REQUEST *ocspReq), (ocspReq), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, is_OCSP_REQUEST_signature_cert, (OCSP_REQUEST *ocspReq), (ocspReq), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_CERT*, get_OCSP_REQUEST_signature_cert, (OCSP_REQUEST *ocspReq), (ocspReq), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, verify_OCSP_REQUEST, (OCSP_REQUEST *ocspReq), (ocspReq), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_OCSP_REQUEST_list_count, (OCSP_REQUEST *ocspReq), (ocspReq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, get_OCSP_REQUEST_list, (OCSP_REQUEST *ocspReq, OCSP_SINGLE_REQUEST **singleReq, int index), (ocspReq,singleReq,index), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, generate_OCSP_RESPONSE, (OCSP_RESPONSE **ocspResponse, OCSP_RESPONSE_BYTES** ocspResBytes, int status), (ocspResponse,ocspResBytes,status), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, generate_OCSP_RESPONSE_BYTES, (OCSP_RESPONSE_BYTES** ocspResBytes, BASIC_OCSP_RESPONSE *ocspBasic), (ocspResBytes,ocspBasic), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, generate_BASIC_OCSP_RESPONSE, (BASIC_OCSP_RESPONSE **ocspBasic, OCSP_RESPONSE_DATA *resData, X509_CERT *caCert, P8_PRIV_KEY_INFO *ca_pvkey), (ocspBasic,resData,caCert,ca_pvkey), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, generate_OCSP_RESPONSE_DATA, (OCSP_RESPONSE_DATA **resData, X509_CERT *caCert, uint32 responseIDType, int version, uint8 *nonce, int nonceLen, int add_extended_revoke), (resData,caCert,responseIDType,version,nonce,nonceLen,add_extended_revoke), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_single_OCSP_RESPONSE, (OCSP_RESPONSE_DATA *resData, OCSP_SINGLE_REQUEST *singleReq, uint32 certStatus, OCSP_REVOKED_INFO* revokedInfo, GENERALIZED_TIME *thisUpdate, GENERALIZED_TIME *nextUpdate), (resData,singleReq,certStatus,revokedInfo,thisUpdate,nextUpdate), ISC_FAIL);
INI_RET_LOADLIB_PKI(OCSP_CERT_ID*, dup_OCSP_CERT_ID, (OCSP_CERT_ID *certID), (certID), NULL);
INI_RET_LOADLIB_PKI(OCSP_REVOKED_INFO*, dup_OCSP_REVOKED_INFO, (OCSP_REVOKED_INFO *revokedInfo), (revokedInfo), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, OCSP_SINGLE_RESPONSE_to_Seq, (OCSP_SINGLE_RESPONSE *sRes, SEQUENCE **seq), (sRes,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, OCSP_REVOKED_INFO_to_Seq, (OCSP_REVOKED_INFO *revokeInfo, SEQUENCE **seq), (revokeInfo,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, BASIC_OCSP_RESPONSE_to_Seq, (BASIC_OCSP_RESPONSE *ocspBasic, SEQUENCE **seq), (ocspBasic,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, OCSP_RESPONSE_to_Seq, (OCSP_RESPONSE *ocspRes, SEQUENCE **seq), (ocspRes,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, OCSP_RESPONSE_DATA_to_Seq, (OCSP_RESPONSE_DATA *resData, SEQUENCE **seq), (resData,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, OCSP_RESPONSE_BYTES_to_Seq, (OCSP_RESPONSE_BYTES *resBytes, SEQUENCE **seq), (resBytes,seq), ISC_FAIL);

#endif

#ifdef __cplusplus
}
#endif

#endif
