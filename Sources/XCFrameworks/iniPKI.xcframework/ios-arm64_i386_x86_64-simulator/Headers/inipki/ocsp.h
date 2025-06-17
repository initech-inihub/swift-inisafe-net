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

/* error.h 에 들어갈 내용 ------------------------------------- */
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
* 인증서 정보를 구분하는 ID
*/
typedef struct ocsp_cert_id_st{
	X509_ALGO_IDENTIFIER *hashAlgID;
	OCTET_STRING *issuerNameHash;
	OCTET_STRING *issuerKeyHash;
	INTEGER *CertificateSerialNumber;
} OCSP_CERT_ID;

/*!
* \brief
* 단일 Request 구조체
*/
typedef struct ocsp_single_request_st{
	OCSP_CERT_ID *certID;
	X509_EXTENSIONS *singleRequestExtensions;
} OCSP_SINGLE_REQUEST;

/*!
* \brief
* 단일 Request 구조체 리스트
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
* OCSP 전자서명 구조체
*/
typedef struct ocsp_signature_st{
	X509_ALGO_IDENTIFIER *algID;
	BIT_STRING *signature;
	X509_CERTS *certs;
} OCSP_SIGNATURE;

/*!
* \brief
* OCSP TBS Request 구조체
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
* OCSP Request 구조체
*/
typedef struct ocsp_request_st{
	OCSP_TBS_REQUEST *tbsRequest;
	OCSP_SIGNATURE *signature;
} OCSP_REQUEST;


/*!
* \brief
* OCSP Response Bytes 구조체
*/
typedef struct ocsp_response_bytes_st{
	OBJECT_IDENTIFIER *type;
	OCTET_STRING *response;
} OCSP_RESPONSE_BYTES;


/*!
* \brief
* OCSP Response 구조체
*/
typedef struct ocsp_response_st{
	int ocspResponseStatus;
	OCSP_RESPONSE_BYTES *responseBytes;
} OCSP_RESPONSE;


/*!
* \brief
* OCSP ResponderID 구조체
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
* OCSP RevokedInfo 구조체
*/
typedef struct ocsp_revoked_info_st{
	GENERALIZED_TIME *revocationTime;
	int revocationReason;		/* CRL Reason (0 : unspecified, 1 : keyCompromise, 2 : caCompromise, 3 : affiliationChanged ... 10 : aaCompromise */
} OCSP_REVOKED_INFO;

/*!
* \brief
* OCSP CertStatus 구조체
*/
typedef struct ocsp_cert_status_st{
	int type;	/* 0 : good, 1 : revoked,  2 : unknown */
	OCSP_REVOKED_INFO *revokedInfo;
} OCSP_CERT_STATUS;

/*!
* \brief
* OCSP SingleResponse 구조체
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
* 단일 Response 구조체 리스트
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
* OCSP ResponseData 구조체
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
* Basic OCSP Response 구조체
*/
typedef struct basic_ocsp_response_st{
	OCSP_RESPONSE_DATA *tbsResponseData;
	X509_ALGO_IDENTIFIER *algID;
	BIT_STRING *signature;
	X509_CERTS *certs;

	uint8 *rawTbsResponseData;		/* 서명 검증을 위한 raw 데이터 */
	int rawTbsResponseDataLen;
} BASIC_OCSP_RESPONSE;

#ifndef WIN_INI_LOADLIBRARY_PKI

/*------------------------- 함수 시작 -------------------------------------------*/

/*!
* \brief
* OCSP_CERT_ID 구조체의 초기화 함수
* \returns
* OCSP_CERT_ID 구조체 포인터
*/
ISC_API OCSP_CERT_ID* new_OCSP_CERT_ID(void);

/*!
* \brief
* OCSP_CERT_ID 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_CERT_ID(OCSP_CERT_ID *unit);

/*!
* \brief
* OCSP_CERT_ID 구조체를 리셋
* \param unit
* 리셋할 OCSP_CERT_ID 구조체
*/
ISC_API void clean_OCSP_CERT_ID(OCSP_CERT_ID *unit);

/*!
* \brief
* OCSP_CERT_ID 구조체의 초기화 함수
* \returns
* OCSP_CERT_ID 구조체 포인터
*/
ISC_API OCSP_SINGLE_REQUEST* new_OCSP_SINGLE_REQUEST(void);

/*!
* \brief
* OCSP_SINGLE_REQUEST 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_SINGLE_REQUEST(OCSP_SINGLE_REQUEST *unit);

/*!
* \brief
* OCSP_SINGLE_REQUEST 구조체를 리셋
* \param unit
* 리셋할 OCSP_SINGLE_REQUEST 구조체
*/
ISC_API void clean_OCSP_SINGLE_REQUEST(OCSP_SINGLE_REQUEST *unit);

/*!
* \brief
* OCSP_TBS_REQUEST 구조체의 초기화 함수
* \returns
* OCSP_TBS_REQUEST 구조체 포인터
*/
ISC_API OCSP_TBS_REQUEST* new_OCSP_TBS_REQUEST(void);

/*!
* \brief
* OCSP_TBS_REQUEST 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_TBS_REQUEST(OCSP_TBS_REQUEST *unit);

/*!
* \brief
* OCSP_TBS_REQUEST 구조체를 리셋
* \param unit
* 리셋할 OCSP_TBS_REQUEST 구조체
*/
ISC_API void clean_OCSP_TBS_REQUEST(OCSP_TBS_REQUEST *unit);

/*!
* \brief
* OCSP_SIGNATURE 구조체의 초기화 함수
* \returns
* OCSP_SIGNATURE 구조체 포인터
*/
ISC_API OCSP_SIGNATURE* new_OCSP_SIGNATURE(void);

/*!
* \brief
* OCSP_SIGNATURE 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_SIGNATURE(OCSP_SIGNATURE *unit);

/*!
* \brief
* OCSP_SIGNATURE 구조체를 리셋
* \param unit
* 리셋할 OCSP_SIGNATURE 구조체
*/
ISC_API void clean_OCSP_SIGNATURE(OCSP_SIGNATURE *unit);

/*!
* \brief
* OCSP_REQUEST 구조체의 초기화 함수
* \returns
* OCSP_REQUEST 구조체 포인터
*/
ISC_API OCSP_REQUEST* new_OCSP_REQUEST(void);

/*!
* \brief
* OCSP_REQUEST 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_REQUEST(OCSP_REQUEST *unit);

/*!
* \brief
* OCSP_REQUEST 구조체를 리셋
* \param unit
* 리셋할 OCSP_REQUEST 구조체
*/
ISC_API void clean_OCSP_REQUEST(OCSP_REQUEST *unit);

/*!
* \brief
* OCSP_RESPONSE_BYTES 구조체의 초기화 함수
* \returns
* OCSP_RESPONSE_BYTES 구조체 포인터
*/
ISC_API OCSP_RESPONSE_BYTES* new_OCSP_RESPONSE_BYTES(void);

/*!
* \brief
* OCSP_RESPONSE_BYTES 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_RESPONSE_BYTES(OCSP_RESPONSE_BYTES *unit);

/*!
* \brief
* OCSP_RESPONSE_BYTES 구조체를 리셋
* \param unit
* 리셋할 OCSP_RESPONSE_BYTES 구조체
*/
ISC_API void clean_OCSP_RESPONSE_BYTES(OCSP_RESPONSE_BYTES *unit);

/*!
* \brief
* OCSP_RESPONSE 구조체의 초기화 함수
* \returns
* OCSP_RESPONSE 구조체 포인터
*/
ISC_API OCSP_RESPONSE* new_OCSP_RESPONSE(void);

/*!
* \brief
* OCSP_RESPONSE 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_RESPONSE(OCSP_RESPONSE *unit);

/*!
* \brief
* OCSP_RESPONSE 구조체를 리셋
* \param unit
* 리셋할 OCSP_RESPONSE 구조체
*/
ISC_API void clean_OCSP_RESPONSE(OCSP_RESPONSE *unit);

/*!
* \brief
* OCSP_RESPONDER_ID 구조체의 초기화 함수
* \returns
* OCSP_RESPONDER_ID 구조체 포인터
*/
ISC_API OCSP_RESPONDER_ID* new_OCSP_RESPONDER_ID(void);

/*!
* \brief
* OCSP_RESPONDER_ID 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_RESPONDER_ID(OCSP_RESPONDER_ID *unit);

/*!
* \brief
* OCSP_RESPONDER_ID 구조체를 리셋
* \param unit
* 리셋할 OCSP_RESPONDER_ID 구조체
*/
ISC_API void clean_OCSP_RESPONDER_ID(OCSP_RESPONDER_ID *unit);

/*!
* \brief
* OCSP_REVOKED_INFO 구조체의 초기화 함수
* \returns
* OCSP_REVOKED_INFO 구조체 포인터
*/
ISC_API OCSP_REVOKED_INFO* new_OCSP_REVOKED_INFO(void);

/*!
* \brief
* OCSP_REVOKED_INFO 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_REVOKED_INFO(OCSP_REVOKED_INFO *unit);

/*!
* \brief
* OCSP_REVOKED_INFO 구조체를 리셋
* \param unit
* 리셋할 OCSP_REVOKED_INFO 구조체
*/
ISC_API void clean_OCSP_REVOKED_INFO(OCSP_REVOKED_INFO *unit);

/*!
* \brief
* OCSP_CERT_STATUS 구조체의 초기화 함수
* \returns
* OCSP_CERT_STATUS 구조체 포인터
*/
ISC_API OCSP_CERT_STATUS* new_OCSP_CERT_STATUS(void);

/*!
* \brief
* OCSP_CERT_STATUS 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_CERT_STATUS(OCSP_CERT_STATUS *unit);

/*!
* \brief
* OCSP_CERT_STATUS 구조체를 리셋
* \param unit
* 리셋할 OCSP_CERT_STATUS 구조체
*/
ISC_API void clean_OCSP_CERT_STATUS(OCSP_CERT_STATUS *unit);


/*!
* \brief
* OCSP_SINGLE_RESPONSE 구조체의 초기화 함수
* \returns
* OCSP_SINGLE_RESPONSE 구조체 포인터
*/
ISC_API OCSP_SINGLE_RESPONSE* new_OCSP_SINGLE_RESPONSE(void);

/*!
* \brief
* OCSP_SINGLE_RESPONSE 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_SINGLE_RESPONSE(OCSP_SINGLE_RESPONSE *unit);

/*!
* \brief
* OCSP_SINGLE_RESPONSE 구조체를 리셋
* \param unit
* 리셋할 OCSP_SINGLE_RESPONSE 구조체
*/
ISC_API void clean_OCSP_SINGLE_RESPONSE(OCSP_SINGLE_RESPONSE *unit);

/*!
* \brief
* OCSP_RESPONSE_DATA 구조체의 초기화 함수
* \returns
* OCSP_RESPONSE_DATA 구조체 포인터
*/
ISC_API OCSP_RESPONSE_DATA* new_OCSP_RESPONSE_DATA(void);

/*!
* \brief
* OCSP_RESPONSE_DATA 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_OCSP_RESPONSE_DATA(OCSP_RESPONSE_DATA *unit);

/*!
* \brief
* OCSP_RESPONSE_DATA 구조체를 리셋
* \param unit
* 리셋할 OCSP_RESPONSE_DATA 구조체
*/
ISC_API void clean_OCSP_RESPONSE_DATA(OCSP_RESPONSE_DATA *unit);

/*!
* \brief
* BASIC_OCSP_RESPONSE 구조체의 초기화 함수
* \returns
* BASIC_OCSP_RESPONSE 구조체 포인터
*/
ISC_API BASIC_OCSP_RESPONSE* new_BASIC_OCSP_RESPONSE(void);

/*!
* \brief
* BASIC_OCSP_RESPONSE 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_BASIC_OCSP_RESPONSE(BASIC_OCSP_RESPONSE *unit);

/*!
* \brief
* BASIC_OCSP_RESPONSE 구조체를 리셋
* \param unit
* 리셋할 BASIC_OCSP_RESPONSE 구조체
*/
ISC_API void clean_BASIC_OCSP_RESPONSE(BASIC_OCSP_RESPONSE *unit);


/*!
* \brief
* 하나의 사용자 인증서에 대해 OCSP_REQUEST 를 생성함
* \param ocsp_request
* 할당된 OCSP_REQUEST 구조체
* \param user_cert
* OCSP를 통해 유효성 검증할 인증서
* \param ca_cert
* user_cert 를 발급한 CA 인증서(NULL 을 허용함, 단 사용자 인증서에서 CA의 공개키ID 와 IssuerID 를 얻을 수 있을 경우에 한함)
* \param nonce
* OCSP 스팩상 Replay-Attack 을 차단하고 Request/Response 쌍을 확인하는데 사용됨.(NULL 일 경우 자동으로 생성)
* \param nonce_size
* 외부에서 설정되는 nonce 의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS generate_single_OCSP_REQUEST(OCSP_REQUEST *ocsp_request, X509_CERT *user_cert, X509_CERT *ca_cert, uint8 *nonce, int nonce_size);

ISC_API ISC_STATUS generate_single_OCSP_REQUEST_Ex(OCSP_REQUEST *ocsp_request, X509_CERT *user_cert, X509_CERT *ca_cert, int default_hash_id, uint8 *nonce, int nonce_size);

ISC_API ISC_STATUS generate_single_OCSP_REQUEST_Ex_With_CI(OCSP_REQUEST *ocsp_request, X509_CERT *user_cert, X509_CERT *ca_cert, int default_hash_id, uint8 *nonce, int nonce_size, ISC_DH_UNIT* dh);

/*!
* \brief
* 여러 사용자 인증서에 대해 OCSP_REQUEST 를 생성함
* \param ocsp_request
* 할당된 OCSP_REQUEST 구조체
* \param user_certs
* OCSP를 통해 유효성 검증할 인증서들
* \param ca_cert
* user_cert 를 발급한 CA 인증서(NULL 을 허용함, 단 사용자 인증서에서 CA의 공개키ID 와 IssuerID 를 얻을 수 있을 경우에 한함)
* \param nonce
* OCSP 스팩상 Replay-Attack 을 차단하고 Request/Response 쌍을 확인하는데 사용됨.(NULL 일 경우 자동으로 생성)
* \param nonce_size
* 외부에서 설정되는 nonce 의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS generate_multi_OCSP_REQUEST(OCSP_REQUEST *ocsp_request, X509_CERTS *user_certs, X509_CERT *ca_cert, uint8 *nonce, int nonce_size);

/**
 * @brief
 * generate_signle_OCSP_REQUEST는 하나의 OCSP_SINGLE_REQUEST를 포함한 OCS_TBS_REQUEST 를 생성하고
 * generate_multi_OCSP_REQUEST는 동일한 발급자가 발행한 여러개의 OCSP_SINGLE_REQUEST를 포함한 OCSP_TBS_REQUEST를 생성하는데
 * 이 설계에는 아래와 같은 문제가 있다.
 *   1. 각각 다른 발급자가 생성한 인증서들에 대한 OCS_TBS_REQEST를 생성할 수 없다.
 *   2. singleRequestExtension을 포함한 OCSP_TBS_REQUEST를 생성할 수 없다.
 * 이에 하기와 같은 함수를 추가하여 문제를 해결한다.
 *   1. OCSP_SINGLE_REQUEST를 별도로 생성할 수 있는 함수
 *   2. OCSP_SINGLE_REQUEST에 singleRequestExtension을 추가할 수 있는 함수
 *   3. 비어있는 OCSP_TBS_REQUEST를 생성할 수 있는 함수
 *   4. OCSP_TBS_REQUEST에 OCSP_SINGLE_REQUEST를 추가할 수 있는 함수
 *   5. OCSP_TBS_REQUEST에 requestExtension을 추가할 수 있는 함수
 * @author kwangho.jung@initech.com
 * @date 2021/04/10
 */

/**
 * @brief 주어진 user_cert, ca_cert 에서 필요한 값을 추출하여 OCSP_SINGLE_REQUEST 구조체를 생성한다.
 *
 * @param ocsp_single_request singleRequestExtension이 비어있는 OCSP_SINGLE_REQUEST 구조체 (out)
 * @param user_cert 사용자 인증서
 * @param ca_cert 발급자 인증서
 * @param hash_id 공개키를 digest할때 사용할 해쉬 알고리즘
 * @return ISC_API 0:success, others:fail
 */
ISC_API ISC_STATUS generate_OCSP_SINGLE_REQUEST(OCSP_SINGLE_REQUEST** ocsp_single_request, X509_CERT* user_cert, X509_CERT* ca_cert, int hash_id);

/**
 * @brief OCSP_SINGLE_REQUEST 에 singleRequestExtension 을 추가한다.
 *
 * @param ocsp_single_request singleRequestExtension을 추가할 대상
 * @param singleRequestExtension OCSP_SINGLE_REQUEST에 추가할 singleRequestExtension
 * @return ISC_API 0:success, others:fail
 */
ISC_API ISC_STATUS add_OCSP_SINGLE_REQUEST_EXTENSION(OCSP_SINGLE_REQUEST* ocsp_single_request, X509_EXTENSION* singleRequestExtension);

/**
 * @brief CID 요청을 위해 OCSP_SINGLE_REQUEST에 추가할 singleRequestExtension을 생성한다.
 *
 * @param extension CID 요청 extension (out)
 * @param version CID 요청 버전
 * @param cipherID CID 대칭키 암호화 알고리즘
 * @param dh 공개키를 취할 dh 키쌍
 * @return ISC_API 0:success, others:fail
 */
ISC_API ISC_STATUS generate_OCSP_SINGLE_REQUEST_EXTENSION_dhcid(X509_EXTENSION** extension, short version, int cipherID, ISC_DH_UNIT* dh);

/**
 * @brief OCSP_SINGLE_REQUEST를 포함하지 않은 빈 OCSP_TBS_REQUEST를 포함한 OCSP_REQUEST를 생성한다.
 *
 * @param ocsp_request 빈 OCSP_TBS_REQUEST를 포함할 OCSP_REQUEST (out)
 * @param version OCSP_TBS_REQUEST 버전
 * @return ISC_API 0:success, others:fail
 */
ISC_API ISC_STATUS generate_empty_OCSP_REQUEST(OCSP_REQUEST **ocsp_request, int version);

/**
 * @brief OCSP_REQUEST 내OCSP_TBS_REQUEST에 OCSP_SINGLE_REQUEST를 추가한다.
 *
 * @param ocsp_request OCSP_SINGLE_REQUEST를 추가할 OCSP_TBS_REQUEST를 포함한 OCSP_REQUEST
 * @param ocsp_single_request OCSP_REQUEST내 OCSP_TBS_REQUEST에 추가할 OCSP_SINGLE_REQUEST
 * @return ISC_API 0:success, others:fail
 */
ISC_API ISC_STATUS add_OCSP_SINGLE_REQUEST(OCSP_REQUEST* ocsp_request, OCSP_SINGLE_REQUEST* ocsp_single_request);

/**
 * @brief OCSP_REQUEST에 requestExtension을 추가한다.
 *
 * @param ocsp_request requestExtension을 추가할 OCSP_REQUEST
 * @param requestExtension OCSP_REQUEST에 추가할 requestExtension
 * @return ISC_API 0:success, others:fail
 */
ISC_API ISC_STATUS add_OCSP_REQUEST_EXTENSION(OCSP_REQUEST* ocsp_request, X509_EXTENSION* requestExtension);

/**
 * @brief replay attack을 방지하는 nonce 를 포함한 requestExtension을 생성한다.
 *
 * @param extension nonce Extension (out)
 * @param nonce nonce
 * @param nonce_size nonce 크기
 * @return ISC_API 0:success, others:fail
 */
ISC_API ISC_STATUS generate_OCSP_REQUEST_EXTENSION_nonce(X509_EXTENSION** extension, uint8* nonce, int nonce_size);
/*!
* \brief
* OCSP_REQUEST 의 nonce 길이를 리턴함.
* \param ocsp_request
* 할당된 OCSP_REQUEST 구조체
* \return
* nonce 길이
*/
ISC_API int get_OCSP_REQUEST_nonce_length(OCSP_REQUEST *ocsp_request);

/*!
* \brief
* OCSP_REQUEST 의 nonce 길이를 리턴함.
* \param ocsp_request
* 할당된 OCSP_REQUEST 구조체
* \param nonceBuf
* Nonce 가 들어갈 할당된 메모리 공간
* \returns
* -# 0 이상 : nonce 길이
* -# 0 미만 : 실패 (오류코드)
*/

ISC_API int get_OCSP_REQUEST_nonce(OCSP_REQUEST *ocsp_request, uint8 **nonceBuf);
/*!
* \brief
* OCSP_REQUEST 에 대해 서명을 수행함
* \param ocsp_request
* 할당된 OCSP_REQUEST 구조체
* \param ocsp_cert
* 서명자에 해당하는 OCSP 서비스 가입자 인증서
* \param ocsp_pvkey
* 서명자의 개인키
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS sign_OCSP_REQUEST(OCSP_REQUEST *ocsp_request, X509_CERT *ocsp_cert, P8_PRIV_KEY_INFO *ocsp_pvkey);

/*!
* \brief
* OCSP_REQUEST 에 대해 서명을 수행함
* \param ocsp_request
* 할당된 OCSP_REQUEST 구조체
* \param ocsp_cert
* 서명자에 해당하는 OCSP 서비스 가입자 인증서
* \param ocsp_pvkey
* 서명자의 개인키
* \param sign_hash
* 서명에사용할해시(ISC_SHA1, ISC_SHA256, ISC_MD5 .. )
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS sign_OCSP_REQUEST_ex(OCSP_REQUEST *ocsp_request, X509_CERT *ocsp_cert, P8_PRIV_KEY_INFO *ocsp_pvkey, int sign_hash);

ISC_API ISC_STATUS sign_OCSP_REQUEST_Ex(OCSP_REQUEST *ocsp_request, X509_CERT *ocsp_cert, P8_PRIV_KEY_INFO *ocsp_pvkey, int sign_hash, char pad_mode);

/*!
* \brief
* OCSP_SINGLE_REQUEST 구조체를 Sequence로 Encode 함수
* \param sreq
* OCSP_SINGLE_REQUEST 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS OCSP_SINGLE_REQUEST_to_Seq(OCSP_SINGLE_REQUEST *sreq, SEQUENCE **seq);

/*!
* \brief
* OCSP_TBS_REQUEST 구조체를 Sequence로 Encode 함수
* \param tbs
* OCSP_TBS_REQUEST 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS OCSP_TBS_REQUEST_to_Seq(OCSP_TBS_REQUEST *tbs, SEQUENCE **seq);

/*!
* \brief
* OCSP_REQUEST 구조체를 Sequence로 Encode 함수
* \param oscp_req
* OCSP_REQUEST 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS OCSP_REQUEST_to_Seq(OCSP_REQUEST *oscp_req, SEQUENCE **seq);

/*!
* \brief
* Sequence를 OCSP_RESPONSE 로 디코딩 함
* \param in
* Decoding Sequece 구조체
* \param out
* OCSP_RESPONSE 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS Seq_to_OCSP_RESPONSE(SEQUENCE *in, OCSP_RESPONSE **out);

/*!
* \brief
* Sequence를 OCSP_RESPONSE_BYTES 로 디코딩 함
* \param in
* Decoding Sequece 구조체
* \param out
* OCSP_RESPONSE_BYTES 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS Seq_to_OCSP_RESPONSE_BYTES(SEQUENCE *in, OCSP_RESPONSE_BYTES **out);

/*!
* \brief
* OCSP_RESPONSE_BYTES 로부터 BASIC_OCSP_RESPONSE 를 얻음
* \param in
* OCSP_RESPONSE_BYTES 구조체
* \returns
* BASIC_OCSP_RESPONSE 구조체
*/
ISC_API BASIC_OCSP_RESPONSE *get_BASIC_OCSP_RESPONSE(OCSP_RESPONSE_BYTES *in);

/*!
* \brief
* Sequence를 OCSP_RESPONSE_DATA 로 디코딩 함
* \param in
* Decoding Sequece 구조체
* \param out
* OCSP_RESPONSE_DATA 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS Seq_to_OCSP_RESPONSE_DATA(SEQUENCE *in, OCSP_RESPONSE_DATA **out);

/*!
* \brief
* Sequence를 OCSP_SINGLE_RESPONSE 로 디코딩 함
* \param in
* Decoding Sequece 구조체
* \param out
* OCSP_SINGLE_RESPONSE 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS Seq_to_OCSP_SINGLE_RESPONSE(SEQUENCE *in, OCSP_SINGLE_RESPONSE **out);

/*!
* \brief
* Sequence를 OCSP_CERT_ID 로 디코딩 함
* \param in
* Decoding Sequece 구조체
* \param out
* OCSP_CERT_ID 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS Seq_to_OCSP_CERT_ID(SEQUENCE *in, OCSP_CERT_ID **out);

/*!
* \brief
* Sequence를 OCSP_REVOKED_INFO 로 디코딩 함
* \param in
* Decoding Sequece 구조체
* \param out
* OCSP_REVOKED_INFO 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS Seq_to_OCSP_REVOKED_INFO(SEQUENCE *in, OCSP_REVOKED_INFO **out);

/*!
* \brief
* BASIC_OCSP_RESPONSE 의 서명을 검증하고, NONCE 가 올바른지 체크함.
* \param basicOcspRes
* 검증할 BASIC_OCSP_RESPONSE 구조체
* \param caCert
* 서명 검증에 사용할 ocsp 서버, 즉 CA 인증서(NULL 인 경우 basicOcspRes 내부에서 찾음)
* \param nonce
* 요청과 동일한 nonce 의 Response 인지 체크 하기위한 nonce 값(NULL 인 경우 검사 하지 않음.)
* \param nonceLen
* nonce 의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS verify_BASIC_OCSP_RESPONSE(BASIC_OCSP_RESPONSE *basicOcspRes, X509_CERT *caCert, uint8 *nonce, int nonceLen);

ISC_API ISC_STATUS verify_BASIC_OCSP_RESPONSE_Ex(BASIC_OCSP_RESPONSE *basicOcspRes, X509_CERT *caCert, char pad_mode, uint8 *nonce, int nonceLen);

/*!
* \brief
* BASIC_OCSP_RESPONSE 의 서명을 검증하고, NONCE 가 올바른지 체크함.
* \param basicOcspRes
* 검증할 BASIC_OCSP_RESPONSE 구조체
* \param caCert
* 서명 검증에 사용할 ocsp 서버, 즉 CA 인증서(NULL 인 경우 basicOcspRes 내부에서 찾음)
* \param nonce
* 요청과 동일한 nonce 의 Response 인지 체크 하기위한 nonce 값(NULL 인 경우 검사 하지 않음.)
* \param nonceLen
* nonce 의 길이
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS verfy_BASIC_OCSP_RESPONSE(BASIC_OCSP_RESPONSE *basicOcspRes, X509_CERT *caCert, uint8 *nonce, int nonceLen);

/*!
* \brief
* BASIC_OCSP_RESPONSE 의 내부에 존재하는 인증서 상태 검증 개수를 리턴함.
* \param basicOcspRes
* BASIC_OCSP_RESPONSE 구조체
* \returns
* OCSP_STATUS 개수
*/
ISC_API int get_CERT_STATUS_count_from_OCSP_RESPONSE(BASIC_OCSP_RESPONSE *basicOcspRes);

/*!
* \brief
* BASIC_OCSP_RESPONSE 을 통해 사용자 인증서가 유효한지를 검사함.
* \param basicOcspRes
* BASIC_OCSP_RESPONSE 구조체
* \param userCert
* 상태 검증할 사용자 인증서
* \param revokeReasonCode
* 폐기 된 경우 폐기 사유 코드를 리턴할 주소
* \returns
* -# OCSP_CERT_STATUS_GOOD : 유효
* -# OCSP_CERT_STATUS_REVOKED : 폐기
* -# OCSP_CERT_STATUS_UNKNOWN : 알수 없음.
*/
ISC_API ISC_STATUS get_CERT_STATUS_from_OCSP_RESPONSE(BASIC_OCSP_RESPONSE *basicOcspRes, X509_CERT *userCert, int *revokeReasonCode);

/*!
* \brief
* BASIC_OCSP_RESPONSE 내의 인증서 상태 정보값을 리턴함.
* \param basicOcspRes
* BASIC_OCSP_RESPONSE 구조체
* \param index
* BASIC_OCSP_RESPONSE 내의 상태 정보 index 값
* \param revokeReasonCode
* 폐기 된 경우 폐기 사유 코드를 리턴할 주소
* \returns
* -# OCSP_CERT_STATUS_GOOD : 유효
* -# OCSP_CERT_STATUS_REVOKED : 폐기
* -# OCSP_CERT_STATUS_UNKNOWN : 알수 없음.
*/
ISC_API	ISC_STATUS get_CERT_STATUS_from_OCSP_RESPONSE_index(BASIC_OCSP_RESPONSE *basicOcspRes, int index, ISC_STATUS *revokeReasonCode);

/*!
* \brief
* BASIC_OCSP_RESPONSE 내의 인증서 상태 정보값을 리턴함.
* \param basicOcspRes
* BASIC_OCSP_RESPONSE 구조체
* \param index
* BASIC_OCSP_RESPONSE 내의 상태 정보 index 값
* \param revokeReasonCode
* 폐기 된 경우 폐기 사유 코드를 리턴할 주소
* \param dhci_res
* SINGLE_RESPONSE 의 single response extension 중 CI 응답을 반환한다.
* \returns
* -# OCSP_CERT_STATUS_GOOD : 유효
* -# OCSP_CERT_STATUS_REVOKED : 폐기
* -# OCSP_CERT_STATUS_UNKNOWN : 알수 없음.
*/
ISC_API	ISC_STATUS get_CERT_STATUS_from_OCSP_RESPONSE_index_ex(BASIC_OCSP_RESPONSE *basicOcspRes, int index, ISC_STATUS *revokeReasonCode, DHCIRES** dhci_res);

/*!
* \brief
* Sequence를 OCSP_REQUEST 로 디코딩 함
* \param in
* Decoding Sequece 구조체
* \param out
* OCSP_REQUEST 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS Seq_to_OCSP_REQUEST(SEQUENCE *in, OCSP_REQUEST **out);

/*!
* \brief
* Sequence를 OCSP_TBS_REQUEST 로 디코딩 함
* \param in
* Decoding Sequece 구조체
* \param out
* OCSP_TBS_REQUEST 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS Seq_to_OCSP_TBS_REQUEST(SEQUENCE *seq, OCSP_TBS_REQUEST **tbs);

/*!
* \brief
* Sequence를 OCSP_SINGLE_REQUEST 로 디코딩 함
* \param in
* Decoding Sequece 구조체
* \param out
* OCSP_SINGLE_REQUEST 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS Seq_to_OCSP_SINGLE_REQUEST(SEQUENCE* in, OCSP_SINGLE_REQUEST** out);

/*!
* \brief
* OCSP_REQUEST에서 signature 존재 여부를 리턴함
* \param in
* OCSP_REQUEST 구조체
* \returns
* - 1 : 존재
* - 0 : 존재하지 않음
*/
ISC_API int is_OCSP_REQUEST_signature(OCSP_REQUEST *ocspReq);
ISC_API int is_OCSP_REQUEST_signature_cert(OCSP_REQUEST *ocspReq);

/*!
* \brief
* OCSP_REQUEST를 서명한 인증서를 리턴함
* \param in
* OCSP_REQUEST 구조체
* \returns
* -# X509_CERT 인증서 : Success
* -# NULL : 실패 (에러코드)
*/
ISC_API X509_CERT *get_OCSP_REQUEST_signature_cert(OCSP_REQUEST *ocspReq);

/*!
* \brief
* OCSP_REQUEST를 검증함
* \param in
* OCSP_REQUEST 구조체
* \param caCert
* 서명 검증에 사용할 ocsp 서버, 즉 CA 인증서(NULL 인 경우 ocspReq 내부에서 찾음)
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS verify_OCSP_REQUEST(OCSP_REQUEST *ocspReq);

ISC_API ISC_STATUS verify_OCSP_REQUEST_Ex(OCSP_REQUEST *ocspReq, char pad_mode);

/*!
* \brief
* OCSP_SINGLE_REQUEST의 갯수를 구함.
* \param ocspReq
* 갯수를 구할 OCSP_REQUEST 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API int get_OCSP_REQUEST_list_count(OCSP_REQUEST *ocspReq);

/*!
* \brief
* OCSP_SINGLE_REQUEST를 구함.
* \param ocspReq
* 갯수를 구할 OCSP_REQUEST 구조체
* \param singleReq
* 리턴 받을 OCSP_SINGLE_REQUEST 구조체
* \param index
* OCSP_REQUEST의 OCSP_SINGLE_REQUEST index
* \returns
* -# OCSP_SINGLE_REQUEST의 갯수
*/
ISC_API ISC_STATUS get_OCSP_REQUEST_list(OCSP_REQUEST *ocspReq, OCSP_SINGLE_REQUEST **singleReq, int index);

/*!
* \brief
* OCSP_RESPONSE를 생성함.
* \param ocspResponse
* 리턴 받을 OCSP_RESPONSE 구조체
* \param ocspResBytes
* OCSP_RESPONSE 구조체에 복사할 OCSP_RESPONSE_BYTES 구조체
* \param status
* OCSP_RESPONSE 상태 정보(OCSP_RESPONSE_STATUS_SUCCESSFUL ~ OCSP_RESPONSE_STATUS_UNAUTHORIZED)
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS generate_OCSP_RESPONSE(OCSP_RESPONSE **ocspResponse, OCSP_RESPONSE_BYTES* ocspResBytes, int status);

/*!
* \brief
* OCSP_RESPONSE_BYTES를 생성함.
* \param ocspResBytes
* 리턴 받을 OCSP_RESPONSE_BYTES 구조체
* \param ocspBasic
* OCSP_RESPONSE_BYTES 구조체에 복사할 BASIC_OCSP_RESPONSE 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS generate_OCSP_RESPONSE_BYTES(OCSP_RESPONSE_BYTES** ocspResBytes, BASIC_OCSP_RESPONSE *ocspBasic);

/*!
* \brief
* BASIC_OCSP_RESPONSE을 생성함.
* \param ocspBasic
* 리턴 받을 BASIC_OCSP_RESPONSE 구조체
* \param resData
* BASIC_OCSP_RESPONSE 구조체에 복사할 OCSP_RESPONSE_DATA 구조체
* \param caCert
* 서명 검증에 사용할 ocsp 서버, 즉 CA 인증서
* \param ca_pvkey
* 서명에 사용할 ocsp 개인키
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS generate_BASIC_OCSP_RESPONSE(BASIC_OCSP_RESPONSE **ocspBasic, OCSP_RESPONSE_DATA *resData, X509_CERT *caCert, P8_PRIV_KEY_INFO *ca_pvkey);

/*!
* \brief
* BASIC_OCSP_RESPONSE을 생성함.
* \param ocspBasic
* 리턴 받을 BASIC_OCSP_RESPONSE 구조체
* \param resData
* BASIC_OCSP_RESPONSE 구조체에 복사할 OCSP_RESPONSE_DATA 구조체
* \param caCert
* 서명 검증에 사용할 ocsp 서버, 즉 CA 인증서
* \param ca_pvkey
* 서명에 사용할 ocsp 개인키
* \param sign_hash
* 서명에사용할해시(ISC_SHA1, ISC_SHA256, ISC_MD5 .. )
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/

ISC_API ISC_STATUS generate_BASIC_OCSP_RESPONSE_ex(BASIC_OCSP_RESPONSE **ocspBasic, OCSP_RESPONSE_DATA *resData, X509_CERT *caCert, P8_PRIV_KEY_INFO *ca_pvkey, int sign_hash);

ISC_API ISC_STATUS generate_BASIC_OCSP_RESPONSE_Ex(BASIC_OCSP_RESPONSE **ocspBasic, OCSP_RESPONSE_DATA *resData, X509_CERT *caCert, P8_PRIV_KEY_INFO *ca_pvkey, int sign_hash, char pad_mode);

/*!
* \brief
* OCSP_RESPONSE_DATA을 생성함.
* \param resData
* 리턴 받을 BASIC_OCSP_RESPONSE 구조체
* \param caCert
* responder id를 생성할 ocsp 서버, 즉 CA 인증서
* \param responseIDType
* response id type (OCSP_RESPONDER_ID_TYPE_NAME, OCSP_RESPONDER_ID_TYPE_KEYHASH)
* \param nonce
* 재전송 공격 차단을 위한 nonce 값(NULL 인 경우 넣지 않음.)
* \param nonceLen
* nonce 의 길이
* \param add_extended_revoke
* extended revoke 확장 추가 여부
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS generate_OCSP_RESPONSE_DATA(OCSP_RESPONSE_DATA **resData, X509_CERT *caCert, uint32 responseIDType, int version, uint8 *nonce, int nonceLen, int add_extended_revoke);

/*!
* \brief
* OCSP_RESPONSE_DATA을 업데이트 함.
* \param resData
* 업데이트할 response data
* \param add_extended_revoke
* extended revoke 확장 추가 여부
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS update_OCSP_RESPONSE_DATA(OCSP_RESPONSE_DATA *resData, int add_extended_revoke);

/*!
* \brief
* OCSP_SINGLE_RESPONSE를 생성하여 OCSP_RESPONSE_DATA에 추가
* \param resData
* 리턴 받을 BASIC_OCSP_RESPONSE 구조체
* \param singleReq
* OCSP_SINGLE_RESPONSE의 대상이 되는 OCSP_SINGLE_REQUEST 구조체 
* \param certStatus
* 요청한 인증서의 상태 정보(OCSP_CERT_STATUS_GOOD ~ OCSP_CERT_STATUS_UNKNOWN)
* \param revokedInfo
* 상태가 OCSP_CERT_STATUS_REVOKED 인 경우, 삽입될 OCSP_REVOKED_INFO 구조체(OCSP_CERT_STATUS_GOOD, OCSP_CERT_STATUS_UNKNOWN 인 경우 NULL)
* \param thisUpdate
* CRL의 thisUpdate 시간
* \param nextUpdate
* CRL의 nextUpdate 시간
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS add_single_OCSP_RESPONSE(OCSP_RESPONSE_DATA *resData, OCSP_SINGLE_REQUEST *singleReq, uint32 certStatus, OCSP_REVOKED_INFO* revokedInfo, GENERALIZED_TIME *thisUpdate, GENERALIZED_TIME *nextUpdate);

/*!
* \brief
* OCSP_SINGLE_RESPONSE를 생성하여 OCSP_RESPONSE_DATA에 추가
* \param resData
* 리턴 받을 BASIC_OCSP_RESPONSE 구조체
* \param singleReq
* OCSP_SINGLE_RESPONSE의 대상이 되는 OCSP_SINGLE_REQUEST 구조체 
* \param certStatus
* 요청한 인증서의 상태 정보(OCSP_CERT_STATUS_GOOD ~ OCSP_CERT_STATUS_UNKNOWN)
* \param revokedInfo
* 상태가 OCSP_CERT_STATUS_REVOKED 인 경우, 삽입될 OCSP_REVOKED_INFO 구조체(OCSP_CERT_STATUS_GOOD, OCSP_CERT_STATUS_UNKNOWN 인 경우 NULL)
* \param thisUpdate
* CRL의 thisUpdate 시간
* \param nextUpdate
* CRL의 nextUpdate 시간
* \param dhci_res
* CI 요청에 대한 응답
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS add_single_OCSP_RESPONSE_ex(OCSP_RESPONSE_DATA *resData, OCSP_SINGLE_REQUEST *singleReq, uint32 certStatus, OCSP_REVOKED_INFO* revokedInfo, GENERALIZED_TIME *thisUpdate, GENERALIZED_TIME *nextUpdate, DHCIRES* dhci_res);

/**
 * @brief CID 응답을 위해 OCSP_SINGLE_RESPONSE 에 추가할 singleResponseExtension 을 생성한다.
 *
 * @param extension CID 응답 extension (out)
 * @param dhci extension 으로 추가할 DHCIRES 응답
 * @return ISC_API 0:success, others:fail
 */
ISC_API ISC_STATUS generate_OCSP_SINGLE_RESPONSE_EXTENSION_dhcid(X509_EXTENSION** extension, DHCIRES* dhci);

/**
 * @brief CID 응답을 포함한 singleResponseExtension 에서 CID응답을 추출한다.
 *
 * @param dhci extension 에서 추출한 DHCIRES 응답 (out)
 * @param extension CID 응답 extension
 * @return ISC_API 0:success, others:fail
 */
ISC_API ISC_STATUS get_OCSP_SINGLE_RESPONSE_EXTENSION_dhcid(DHCIRES** dhci, X509_EXTENSION* extension);

/**
 * @brief 싱글리스폰스에 extension을 추가한다.
 *
 * @param ocsp_single_response   싱글 리스폰스
 * @param singleResponseExtension  싱글 리스폰스 확장
 * @return ISC_API  0:성공 others: 실패
 */
ISC_API ISC_STATUS add_OCSP_SINGLE_RESPONSE_EXTENSION(OCSP_SINGLE_RESPONSE* ocsp_single_response, X509_EXTENSION* singleResponseExtension);

/**
 * @brief RESPONSE_DATA 에 extension을 추가한다.
 *
 * @param ocsp_response_data   리스폰스
 * @param responseExtension  리스폰스 확장
 * @param check_duplicate	중복 체크
 * @return ISC_API  0:성공 others: 실패
 */
ISC_API ISC_STATUS add_OCSP_RESPONSE_DATA_EXTENSION(OCSP_RESPONSE_DATA* ocsp_response_data, X509_EXTENSION* responseExtension, int check_duplicate);

/*!
* \brief
* OCSP_CERT_ID를 복사
* \param resData
* 복사할 OCSP_CERT_ID 구조체
* \returns
* -# 복사된 OCSP_CERT_ID : Success
* -# NULL : 실패 
*/
ISC_API OCSP_CERT_ID *dup_OCSP_CERT_ID(OCSP_CERT_ID *certID);

/*!
* \brief
* OCSP_REVOKED_INFO를 복사
* \param resData
* 복사할 OCSP_REVOKED_INFO 구조체
* \returns
* -# 복사된 OCSP_REVOKED_INFO : Success
* -# NULL : 실패 
*/
ISC_API OCSP_REVOKED_INFO *dup_OCSP_REVOKED_INFO(OCSP_REVOKED_INFO *revokedInfo);

/*!
* \brief
* OCSP_SINGLE_RESPONSE 구조체를 Sequence로 Encode 함수
* \param sRes
* OCSP_SINGLE_RESPONSE 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS OCSP_SINGLE_RESPONSE_to_Seq(OCSP_SINGLE_RESPONSE *sRes, SEQUENCE **seq);

/*!
* \brief
* OCSP_REVOKED_INFO 구조체를 Sequence로 Encode 함수
* \param revokeInfo
* OCSP_REVOKED_INFO 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS OCSP_REVOKED_INFO_to_Seq(OCSP_REVOKED_INFO *revokeInfo, SEQUENCE **seq);

/*!
* \brief
* BASIC_OCSP_RESPONSE 구조체를 Sequence로 Encode 함수
* \param ocspBasic
* BASIC_OCSP_RESPONSE 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS BASIC_OCSP_RESPONSE_to_Seq(BASIC_OCSP_RESPONSE *ocspBasic, SEQUENCE **seq);

/*!
* \brief
* OCSP_RESPONSE 구조체를 Sequence로 Encode 함수
* \param ocspRes
* BASIC_OCSP_RESPONSE 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS OCSP_RESPONSE_to_Seq(OCSP_RESPONSE *ocspRes, SEQUENCE **seq);

/*!
* \brief
* OCSP_RESPONSE_DATA 구조체를 Sequence로 Encode 함수
* \param resData
* OCSP_RESPONSE_DATA 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS OCSP_RESPONSE_DATA_to_Seq(OCSP_RESPONSE_DATA *resData, SEQUENCE **seq);

/*!
* \brief
* OCSP_RESPONSE_BYTES 구조체를 Sequence로 Encode 함수
* \param resBytes
* OCSP_RESPONSE_BYTES 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
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
