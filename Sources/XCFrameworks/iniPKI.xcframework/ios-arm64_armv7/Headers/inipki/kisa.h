/*!
* \file kisa.h
* \brief KISA Standard
* \remarks
* KCAC.TS.HSMU - KISA
* \author
* Copyright (c) 2009 by \<INITech\> / Developed by Seon Jong. Kim.
*/

#ifndef HEADER_KISA_H
#define HEADER_KISA_H

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/foundation.h>

#include "asn1.h"
#include "asn1_stack.h"
#include "issuer_and_serial_number.h"
#include "pkcs7.h"
#include "x509.h"
#include "x509v3.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* 보안 토큰 정보
*/
typedef struct kisa_hsm_signature_token_st{
	PRINTABLE_STRING *driverName;		/*보안 토큰 구동프로그램 DLL 이름*/
	X509_ALGO_IDENTIFIER *hashAlgID;	/*해쉬 알고리즘 ID*/
	OCTET_STRING *hashValue;			/*해쉬 값*/
} KISA_HSM_SIGNATURE_TOKEN;

/*!
* \brief
* 단일 보안토큰 구조체 리스트
*/

typedef STK(KISA_HSM_SIGNATURE_TOKEN) KISA_HSM_SIGNATURE_TOKENS;

#define new_KISA_HSM_SIGNATURE_TOKEN_STK() new_STK(KISA_HSM_SIGNATURE_TOKEN)
#define free_KISA_HSM_SIGNATURE_TOKEN_STK(st) free_STK(KISA_HSM_SIGNATURE_TOKEN, (st))
#define get_KISA_HSM_SIGNATURE_TOKEN_STK_count(st) get_STK_count(KISA_HSM_SIGNATURE_TOKEN, (st))
#define get_KISA_HSM_SIGNATURE_TOKEN_STK_value(st, i) get_STK_value(KISA_HSM_SIGNATURE_TOKEN, (st), (i))
#define push_KISA_HSM_SIGNATURE_TOKEN_STK_value(st, val) push_STK_value(KISA_HSM_SIGNATURE_TOKEN, (st), (val))
#define find_KISA_HSM_SIGNATURE_TOKEN_STK_value(st, val) find_STK_value(KISA_HSM_SIGNATURE_TOKEN, (st), (val))
#define remove_KISA_HSM_SIGNATURE_TOKEN_STK_value(st, i) remove_STK_value(KISA_HSM_SIGNATURE_TOKEN, (st), (i))
#define insert_KISA_HSM_SIGNATURE_TOKEN_STK_value(st, val, i) insert_STK_value(KISA_HSM_SIGNATURE_TOKEN, (st), (val), (i))
#define dup_KISA_HSM_SIGNATURE_TOKEN_STK(st) dup_STK(KISA_HSM_SIGNATURE_TOKEN, st)
#define free_KISA_HSM_SIGNATURE_TOKEN_STK_values(st, free_func) free_STK_values(KISA_HSM_SIGNATURE_TOKEN, (st), (free_func))
#define pop_KISA_HSM_SIGNATURE_TOKEN_STK_value(st) pop_STK_value(KISA_HSM_SIGNATURE_TOKEN, (st))
#define sort_X509_KISA_HSM_SIGNATURE_TOKEN(st) sort_STK(KISA_HSM_SIGNATURE_TOKEN, (st))
#define is_KISA_HSM_SIGNATURE_TOKEN_STK_sorted(st) is_STK_sorted(KISA_HSM_SIGNATURE_TOKEN, (st))


/*!
* \brief
* 보안토큰 드라이버 정보
*/
typedef struct kisa_hsm_driver_info_st{
	PRINTABLE_STRING *supportedOSVersion;	/*지원되는 PC 운영체제 종류*/
	PRINTABLE_STRING *version;				/*보안토큰 구동프로그램 버전 정보*/
	GENERAL_NAME *name;						/*보안토큰 구동프로그램 배포위치(예 : IP 주소) */
	int	type;								/*타입 - USB형은 0, 스마트카드형은 1*/
	GENERAL_NAME *cp;						/*보안토큰 제작업체에 대한 정보(URL, 전화번호 등)*/
	PRINTABLE_STRING *info;					/*보안토큰 모델명*/
} KISA_HSM_DRIVER_INFO;

 /*!
* \brief
* 보안토큰 드라이버 구조체 리스트
*/

typedef STK(KISA_HSM_DRIVER_INFO) KISA_HSM_DRIVER_INFOS;

#define new_KISA_HSM_DRIVER_INFO_STK() new_STK(KISA_HSM_DRIVER_INFO)
#define free_KISA_HSM_DRIVER_INFO_STK(st) free_STK(KISA_HSM_DRIVER_INFO, (st))
#define get_KISA_HSM_DRIVER_INFO_STK_count(st) get_STK_count(KISA_HSM_DRIVER_INFO, (st))
#define get_KISA_HSM_DRIVER_INFO_STK_value(st, i) get_STK_value(KISA_HSM_DRIVER_INFO, (st), (i))
#define push_KISA_HSM_DRIVER_INFO_STK_value(st, val) push_STK_value(KISA_HSM_DRIVER_INFO, (st), (val))
#define find_KISA_HSM_DRIVER_INFO_STK_value(st, val) find_STK_value(KISA_HSM_DRIVER_INFO, (st), (val))
#define remove_KISA_HSM_DRIVER_INFO_STK_value(st, i) remove_STK_value(KISA_HSM_DRIVER_INFO, (st), (i))
#define insert_KISA_HSM_DRIVER_INFO_STK_value(st, val, i) insert_STK_value(KISA_HSM_DRIVER_INFO, (st), (val), (i))
#define dup_KISA_HSM_DRIVER_INFO_STK(st) dup_STK(KISA_HSM_DRIVER_INFO, st)
#define free_KISA_HSM_DRIVER_INFO_STK_values(st, free_func) free_STK_values(KISA_HSM_DRIVER_INFO, (st), (free_func))
#define pop_KISA_HSM_DRIVER_INFO_STK_value(st) pop_STK_value(KISA_HSM_DRIVER_INFO, (st))
#define sort_X509_KISA_HSM_DRIVER_INFO(st) sort_STK(KISA_HSM_DRIVER_INFO, (st))
#define is_KISA_HSM_DRIVER_INFO_STK_sorted(st) is_STK_sorted(KISA_HSM_DRIVER_INFO, (st))

/*!
* \brief
* 보안 토큰 정보
*/
typedef struct kisa_hsm_token_distribution_url_st{
	IA5_STRING *tokenID;					/*토큰ID*/
	KISA_HSM_DRIVER_INFOS *driverInfos;		/*드라이버 정보*/
} KISA_HSM_TOKEN_DISTRIBUTION_URL;

 /*!
* \brief
* 보안토큰 배포 URL 구조체 리스트
*/
typedef STK(KISA_HSM_TOKEN_DISTRIBUTION_URL) KISA_HSM_TOKEN_DISTRIBUTION_URLS;

#define new_KISA_HSM_TOKEN_DISTRIBUTION_URL_STK() new_STK(KISA_HSM_TOKEN_DISTRIBUTION_URL)
#define free_KISA_HSM_TOKEN_DISTRIBUTION_URL_STK(st) free_STK(KISA_HSM_TOKEN_DISTRIBUTION_URL, (st))
#define get_KISA_HSM_TOKEN_DISTRIBUTION_URL_STK_count(st) get_STK_count(KISA_HSM_TOKEN_DISTRIBUTION_URL, (st))
#define get_KISA_HSM_TOKEN_DISTRIBUTION_URL_STK_value(st, i) get_STK_value(KISA_HSM_TOKEN_DISTRIBUTION_URL, (st), (i))
#define push_KISA_HSM_TOKEN_DISTRIBUTION_URL_STK_value(st, val) push_STK_value(KISA_HSM_TOKEN_DISTRIBUTION_URL, (st), (val))
#define find_KISA_HSM_TOKEN_DISTRIBUTION_URL_STK_value(st, val) find_STK_value(KISA_HSM_TOKEN_DISTRIBUTION_URL, (st), (val))
#define remove_KISA_HSM_TOKEN_DISTRIBUTION_URL_STK_value(st, i) remove_STK_value(KISA_HSM_TOKEN_DISTRIBUTION_URL, (st), (i))
#define insert_KISA_HSM_TOKEN_DISTRIBUTION_URL_STK_value(st, val, i) insert_STK_value(KISA_HSM_TOKEN_DISTRIBUTION_URL, (st), (val), (i))
#define dup_KISA_HSM_TOKEN_DISTRIBUTION_URL_STK(st) dup_STK(KISA_HSM_TOKEN_DISTRIBUTION_URL, st)
#define free_KISA_HSM_TOKEN_DISTRIBUTION_URL_STK_values(st, free_func) free_STK_values(KISA_HSM_TOKEN_DISTRIBUTION_URL, (st), (free_func))
#define pop_KISA_HSM_TOKEN_DISTRIBUTION_URL_STK_value(st) pop_STK_value(KISA_HSM_TOKEN_DISTRIBUTION_URL, (st))
#define sort_X509_KISA_HSM_TOKEN_DISTRIBUTION_URL(st) sort_STK(KISA_HSM_TOKEN_DISTRIBUTION_URL, (st))
#define is_KISA_HSM_TOKEN_DISTRIBUTION_URL_STK_sorted(st) is_STK_sorted(KISA_HSM_TOKEN_DISTRIBUTION_URL, (st))

#define KISA_HSM_TOKEN_DISTRIBUTION_URL_TYPE 1
#define KISA_HSM_SIGNATURE_TOKEN_TYPE 2

/* error.h 에 들어갈 내용 ------------------------------------- */
#define L_KISA_HSM							0x30000000	/*!< */
#define F_SEQ_TO_KISA_HSM_SIGNATURE_VALUE   0x00010000  /*!< */
#define F_verify_KISA_HSM_SIGNATURE_VALUE   0x00020000  /*!< */
#define ERR_NOT_EXIST_TBSDATA				0x00000010	/*!< */
#define ERR_NOT_EXIST_SIGNATURE				0x00000011	/*!< */
/* ------------------------------------------------------------ */

/*!
* \brief
* 보안토큰 전자서명
*/
typedef struct kisa_hsm_signature_value_st{
	int toBeSignedType;		/* 1 : TokenDistributionURL, 2 : SignatureToken */
	union {
		KISA_HSM_TOKEN_DISTRIBUTION_URLS *tokenDistributionURLs;
		KISA_HSM_SIGNATURE_TOKENS *signatureTokens;
	} toBeSigned;
	uint8 *tobeSignedTBSdata;
	int tobeSignedTBSdataLength;
	X509_ALGO_IDENTIFIER *signatureAlgID;		/*전자서명 알고리즘*/
	ISSUER_AND_SERIAL_NUMBER *signerInfo;	/*전자서명 인증서*/
	ASN1_STRING *signature;					/*전자서명 값 OCTET_STRING or BIT_STRING*/
} KISA_HSM_SIGNATURE_VALUE;

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* KISA_HSM_SIGNATURE_TOKEN 구조체의 초기화 함수
* \returns
* KISA_HSM_SIGNATURE_TOKEN 구조체 포인터
*/
ISC_API KISA_HSM_SIGNATURE_TOKEN* new_KISA_HSM_SIGNATURE_TOKEN(void);

/*!
* \brief
* KISA_HSM_SIGNATURE_TOKEN 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_KISA_HSM_SIGNATURE_TOKEN(KISA_HSM_SIGNATURE_TOKEN *unit);

/*!
* \brief
* KISA_HSM_SIGNATURE_TOKEN 구조체를 리셋
* \param unit
* 리셋할 KISA_HSM_SIGNATURE_TOKEN 구조체
*/
ISC_API void clean_KISA_HSM_SIGNATURE_TOKEN(KISA_HSM_SIGNATURE_TOKEN *unit);

/*!
* \brief
* KISA_HSM_TOKEN_DISTRIBUTION_URL 구조체의 초기화 함수
* \returns
* KISA_HSM_TOKEN_DISTRIBUTION_URL 구조체 포인터
*/
ISC_API KISA_HSM_TOKEN_DISTRIBUTION_URL* new_KISA_HSM_TOKEN_DISTRIBUTION_URL(void);

/*!
* \brief
* KISA_HSM_TOKEN_DISTRIBUTION_URL 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_KISA_HSM_TOKEN_DISTRIBUTION_URL(KISA_HSM_TOKEN_DISTRIBUTION_URL *unit);

/*!
* \brief
* KISA_HSM_TOKEN_DISTRIBUTION_URL 구조체를 리셋
* \param unit
* 리셋할 KISA_HSM_TOKEN_DISTRIBUTION_URL 구조체
*/
ISC_API void clean_KISA_HSM_TOKEN_DISTRIBUTION_URL(KISA_HSM_TOKEN_DISTRIBUTION_URL *unit);


/*!
* \brief
* KISA_HSM_DRIVER_INFO 구조체의 초기화 함수
* \returns
* KISA_HSM_DRIVER_INFO 구조체 포인터
*/
ISC_API KISA_HSM_DRIVER_INFO* new_KISA_HSM_DRIVER_INFO(void);

/*!
* \brief
* KISA_HSM_DRIVER_INFO 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_KISA_HSM_DRIVER_INFO(KISA_HSM_DRIVER_INFO *unit);

/*!
* \brief
* KISA_HSM_DRIVER_INFO 구조체를 리셋
* \param unit
* 리셋할 KISA_HSM_DRIVER_INFO 구조체
*/
ISC_API void clean_KISA_HSM_DRIVER_INFO(KISA_HSM_DRIVER_INFO *unit);


/*!
* \brief
* KISA_HSM_SIGNATURE_VALUE 구조체의 초기화 함수
* \returns
* KISA_HSM_SIGNATURE_VALUE 구조체 포인터
*/
ISC_API KISA_HSM_SIGNATURE_VALUE* new_KISA_HSM_SIGNATURE_VALUE(void);

/*!
* \brief
* KISA_HSM_SIGNATURE_VALUE 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_KISA_HSM_SIGNATURE_VALUE(KISA_HSM_SIGNATURE_VALUE *unit);

/*!
* \brief
* KISA_HSM_SIGNATURE_VALUE 구조체를 리셋
* \param unit
* 리셋할 KISA_HSM_SIGNATURE_VALUE 구조체
*/
ISC_API void clean_KISA_HSM_SIGNATURE_VALUE(KISA_HSM_SIGNATURE_VALUE *unit);

/*!
* \brief
* Sequence를 KISA_HSM_SIGNATURE_VALUE 의 TokenDistributionURL 구조체로 Decode 함수
* \param in
* Decoding Sequece 구조체
* \param out
* KISA_HSM_SIGNATURE_VALUE 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_KISA_HSM_SIGNATURE_VALUE^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_SEQ_TO_KISA_HSM_SIGNATURE_VALUE^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_KISA_HSM_SIGNATURE_VALUE^ERR_ASN1_DECODING : ASN1 Err
* -# LOCATION^F_SEQ_TO_KISA_HSM_SIGNATURE_VALUE^ISC_ERR_MEM_ALLOC : ASN1 Err
* -# Seq_to_X509_ALGO_IDENTIFIER()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_KISA_HSM_SIGNATURE_VALUE (SEQUENCE* in, KISA_HSM_SIGNATURE_VALUE **out);

/*!
* \brief
* KISA_HSM_SIGNATURE_VALUE 의 서명이 올바른지 체크함.
* \param hsmSignature
* hsmSignature 구조체
* \param kisaCert
* hsmSignature 을 서명한 KISA ROOT 인증서
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_verify_KISA_HSM_SIGNATURE_VALUE^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_verify_KISA_HSM_SIGNATURE_VALUE^ERR_NOT_EXIST_TBSDATA : 서명 검을 위한 tbs data 가 없음.
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS verify_KISA_HSM_SIGNATURE_VALUE (KISA_HSM_SIGNATURE_VALUE *hsmSignature, X509_CERT *kisaCert);

#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(KISA_HSM_SIGNATURE_TOKEN*, new_KISA_HSM_SIGNATURE_TOKEN, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_KISA_HSM_SIGNATURE_TOKEN, (KISA_HSM_SIGNATURE_TOKEN *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_KISA_HSM_SIGNATURE_TOKEN, (KISA_HSM_SIGNATURE_TOKEN *unit), (unit) );
INI_RET_LOADLIB_PKI(KISA_HSM_TOKEN_DISTRIBUTION_URL*, new_KISA_HSM_TOKEN_DISTRIBUTION_URL, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_KISA_HSM_TOKEN_DISTRIBUTION_URL, (KISA_HSM_TOKEN_DISTRIBUTION_URL *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_KISA_HSM_TOKEN_DISTRIBUTION_URL, (KISA_HSM_TOKEN_DISTRIBUTION_URL *unit), (unit) );
INI_RET_LOADLIB_PKI(KISA_HSM_DRIVER_INFO*, new_KISA_HSM_DRIVER_INFO, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_KISA_HSM_DRIVER_INFO, (KISA_HSM_DRIVER_INFO *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_KISA_HSM_DRIVER_INFO, (KISA_HSM_DRIVER_INFO *unit), (unit) );
INI_RET_LOADLIB_PKI(KISA_HSM_SIGNATURE_VALUE*, new_KISA_HSM_SIGNATURE_VALUE, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_KISA_HSM_SIGNATURE_VALUE, (KISA_HSM_SIGNATURE_VALUE *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_KISA_HSM_SIGNATURE_VALUE, (KISA_HSM_SIGNATURE_VALUE *unit), (unit) );
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_KISA_HSM_SIGNATURE_VALUE, (SEQUENCE* in, KISA_HSM_SIGNATURE_VALUE **out), (in,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, verify_KISA_HSM_SIGNATURE_VALUE, (KISA_HSM_SIGNATURE_VALUE *hsmSignature, X509_CERT *kisaCert), (hsmSignature,kisaCert), ISC_FAIL);

#endif

#ifdef  __cplusplus
}
#endif

#endif
