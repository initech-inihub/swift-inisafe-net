/*!
* \file x509_crl.h
* \brief X509_CRL
* 전자서명 인증서 효력정지 및 폐지목록 프로파일
* \remarks
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_CRL_H
#define HEADER_CRL_H

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/foundation.h>

#include "asn1.h"
#include "x509.h"

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef WIN32
/* #define CP949 */
#undef X509_CRL
#endif


/*!
* \brief
* X509 폐기목록 정보를 담고 있는 구조체
*/
typedef struct X509_revoked_st
{
	INTEGER *userCert;			/*!< */
	X509_TIME *revocationDate;	/*!< */
	X509_EXTENSIONS *extensions;	/*!< */ /* optional */
	int sequence;			/*!< */
} X509_REVOKED;

/*!
* \brief
* X509_REVOKED의 스택 구조체
*/
typedef STK(X509_REVOKED) X509_REVOKED_LIST; 

/*!
* \brief
* X509_CRL의 기본필드
*/
typedef struct X509_crl_info_st
{
	uint8 version;			/*!< */
	OBJECT_IDENTIFIER *sig_alg;		/*!< */
	X509_NAME *issuer;			/*!< */
	X509_TIME *thisUpdate;		/*!< */
	X509_TIME *nextUpdate;		/*!< */
	X509_REVOKED_LIST *revoked;		/*!< */
	X509_EXTENSIONS *extensions; /*!< */ /* optional */
} X509_CRL_INFO;


/*!
* \brief
* 인증서 효력정지 및 폐기목록 프로파일 구조체
*/
typedef struct X509_crl_st
{
	X509_CRL_INFO *crl;			/*!< */
	OBJECT_IDENTIFIER *sig_alg;	/*!< */
	BIT_STRING *signature;		/*!< */
	int references;				/*!< */
} X509_CRL;

/*!
* \brief
* X509_CRL의 스택 구조체
*/
typedef STK(X509_CRL) X509_CRLS;

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* X509_CRL 구조체의 초기화 함수
* \returns
* X509_CRL 구조체 포인터
*/
ISC_API X509_CRL *new_X509_CRL(void);
/*!
* \brief
* X509_CRL 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_CRL(X509_CRL *unit);
/*!
* \brief
* X509_CRL 구조체를 리셋
* \param unit
* 리셋할 X509_CRL 구조체
*/
ISC_API void clean_X509_CRL(X509_CRL *unit);

/*!
* \brief
* X509_CRL_INFO 구조체의 초기화 함수
* \returns
* X509_CRL_INFO 구조체 포인터
*/
ISC_API X509_CRL_INFO *new_X509_CRL_INFO(void);
/*!
* \brief
* X509_CRL_INFO 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_CRL_INFO(X509_CRL_INFO *unit);

/*!
* \brief
* X509_CRL 구조체에 인증서 version을 저장하기 위한 함수
* \param unit
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \param version
* 인증서 버전
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_CRL_version(X509_CRL *unit, uint8 version);
/*!
* \brief
* X509_CRL 구조체에 인증서 OID를 저장하기 위한 함수
* \param unit
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \param oid
* 생성할때 사용되는 알고리즘 OID
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_CRL_signature(X509_CRL *unit, OBJECT_IDENTIFIER *oid);
/*!
* \brief
* X509_CRL 구조체에 발급자 정보를 저장하기 위한 함수
* \param unit
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \param name
* 발급자 정보를 담고 있는 X509_NAME 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_CRL_issuer (X509_CRL *unit, X509_NAME *name);
/*!
* \brief
* X509_CRL 구조체에 발급일자를 저장하기 위한 함수
* \param unit
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \param thisUpdate
* 발급일자를 담고 있는 X509_TIME 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_CRL_thisUpdate(X509_CRL *unit, X509_TIME *thisUpdate);
/*!
* \brief
* X509_CRL 구조체에 다음 발급일자를 저장하기 위한 함수
* \param unit
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \param nextUpdate
* 다음 발급일자를 담고 있는 X509_TIME 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_CRL_nextUpdate(X509_CRL *unit, X509_TIME *nextUpdate);

/*!
* \brief
* X509_CRL 구조체에 서명값을 저장하기 위한 함수
* \param unit
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \param sigValue
* 서명값을 담고 있는 BIT_STRING 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_CRL_sig_value(X509_CRL *unit, BIT_STRING* sigValue);
/*!
* \brief
* X509_CRL 구조체를 서명할 때 사용되는 알고리즘의 정보를 저장하기 위한 함수
* \param unit
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \param oid
* 서명 알고리즘 OID
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_CRL_sig_alg(X509_CRL *unit, OBJECT_IDENTIFIER* oid);

/*!
* \brief
* X509_CRL 구조체에서 version를 얻기 위한 함수
* \param unit
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \returns
* version
*/
ISC_API uint8 get_X509_CRL_version(X509_CRL *unit);
/*!
* \brief
* X509_CRL 구조체에서 서명 알고리즘 OID를 얻기 위한 함수
* \param unit
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \returns
* Signature OID
*/
ISC_API OBJECT_IDENTIFIER* get_X509_CRL_signature(X509_CRL *unit);
/*!
* \brief
* X509_CRL 구조체에서 발급자 정보를 얻기 위한 함수
* \param unit
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \returns
* X509_NAME 구조체
*/
ISC_API X509_NAME* get_X509_CRL_issuer(X509_CRL *unit);
/*!
* \brief
* X509_CRL 구조체에서 발급일자를 얻기 위한 함수
* \param unit
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \returns
* X509_TIME 구조체
*/
ISC_API X509_TIME* get_X509_CRL_thisUpdate(X509_CRL *unit);
/*!
* \brief
* X509_CRL 구조체에서 다음 발급일자를 얻기 위한 함수
* \param unit
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \returns
* X509_TIME 구조체
*/
ISC_API X509_TIME* get_X509_CRL_nextUpdate(X509_CRL *unit);
/*!
* \brief
* X509_CRL 구조체에서 폐기 목록 정보를 얻기 위한 함수
* \param unit
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \param loc
* 선택하고자 하는 폐기목록의 순번
* \returns
* X509_REVOKED 구조체
*/
ISC_API X509_REVOKED* get_X509_CRL_revoked(X509_CRL *unit, int loc);

/*!
* \brief
* X509_CRL 구조체의 서명에 사용된 알고리즘 정보를 얻기 위한 함수
* \param unit
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \returns
* OBJECT_IDENTIFIER 구조체
*/
ISC_API OBJECT_IDENTIFIER* get_X509_CRL_sig_alg(X509_CRL *unit);
/*!
* \brief
* X509_CRL 구조체의 서명값을 얻기 위한 함수
* \param unit
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \returns
* BIT_STRING 구조체
*/
ISC_API BIT_STRING* get_X509_CRL_sig_value(X509_CRL *unit);

/*!
* \brief
* X509_CRL 구조체의 X509 확장필드의 개수를 알기 위한 함수
* \param x
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \returns
* 확장필드의 개수
*/
ISC_API int	get_X509_CRL_ext_count(X509_CRL *x);
/*!
* \brief
* X509_CRL 구조체의 X509 확장필드에서 입력받은 OID값이 저장된 index를 알기 위한 함수
* \param x
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \param obj
* 찾고자 하는 OID
* \param lastpos
* 스택의 TOP
* \returns
* 해당 index
*/
ISC_API int get_X509_CRL_ext_by_OBJ(X509_CRL *x, OBJECT_IDENTIFIER *obj, int lastpos);
/*!
* \brief
* X509_CRL 구조체의 X509 확장필드에서 입력받은 OID값이 저장된 index를 알기 위한 함수
* \param x
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \param OID_index
* 찾고자 하는 OID의 index
* \param lastpos
* 스택의 TOP
* \returns
* 해당 index
*/
ISC_API int get_X509_CRL_ext_index_by_OID_index(X509_CRL *x, int OID_index, int lastpos);

/*!
* \brief
* X509_CRL 구조체의 한 X509 확장필드를 얻기 위한 함수
* \param x
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \param loc
* 해당 인덱스
* \returns
* X509_EXTENSION 구조체
*/
ISC_API X509_EXTENSION *get_X509_CRL_ext(X509_CRL *x, int loc);
/*!
* \brief
* X509_CRL 구조체의 한 X509 확장필드를 제거하기 위한 함수
* \param x
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \param loc
* 해당 인덱스
* \returns
* 제거된 X509_EXTENSION 구조체
*/
ISC_API X509_EXTENSION *remove_X509_CRL_ext(X509_CRL *x, int loc);
/*!
* \brief
* X509_CRL 구조체에 X509 확장필드를 추가하기 위한 함수
* \param x
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \param ex
* 추가하고자 하는 X509_EXTENSION 구조체
* \param loc
* 해당 인덱스
* \returns
* -# add_X509_EXTENSION의 에러코드\n
*/
ISC_API ISC_STATUS	add_X509_CRL_ext(X509_CRL *x, X509_EXTENSION *ex, int loc);
/*!
* \brief
* X509_CRL 구조체의 폐기목록을 정렬하기 위한 함수
* \param c
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS sort_X509_CRL_revoked(X509_CRL *c);

/*!
* \brief
* X509_CRL_INFO 구조체를 Sequence로 Encode 함수
* \param in
* X509_CRL_INFO 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_X509_CRLINFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_CRLINFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_NAME_to_Seq()의 에러 코드\n
* -# X509_EXTENSIONS_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS X509_CRL_INFO_to_Seq(X509_CRL_INFO *in, SEQUENCE **seq);
/*!
* \brief
* Sequence를 X509_CRL_INFO 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param crl_info
* X509_CRL_INFO 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_X509_CRLINFO^ISC_ERR_NULL_INPUT : Null input error
* -# LOCATION^F_SEQ_TO_X509_CRLINFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_X509_CRLINFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_ATTRIBUTES()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_X509_CRL_INFO(SEQUENCE *seq, X509_CRL_INFO **crl_info);

/*!
* \brief
* X509_CERT 구조체의 인증서가 정당한지 검증하는 함수
* \param crl
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \param x
* 확인할 인증서의 정보를 담고있는 X509_CERT 구조체
* \returns
* -# 0 : CRL 폐기목록에 존재하지 않는 인증서
* -# n : 폐기목록의 n번째 있는 인증서
*/
ISC_API int verify_CRL_X509_CERT(X509_CRL *crl, X509_CERT *x);

/*===================== X509_REVOKED ============================= */

/*!
* \brief
* X509_REVOKED 구조체의 초기화 함수
* \returns
* X509_REVOKED 구조체 포인터
*/
ISC_API X509_REVOKED* new_X509_REVOKED(void);
/*!
* \brief
* X509_REVOKED 구조체를 메모리 할당 해제
* \param revoked
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_REVOKED(X509_REVOKED* revoked);
/*!
* \brief
* X509_REVOKED_LIST 구조체를 메모리 할당 해제
* \param revoked_list
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_REVOKED_LIST (X509_REVOKED_LIST* revoked_list);

/*!
* \brief
* X509_REVOKED 구조체를 복사하는 함수
* \param in
* 복사 원본의 X509_REVOKED 구조체
* \returns
* 복사된 X509_REVOKED 구조체
*/
ISC_API X509_REVOKED* dup_X509_REVOKED(X509_REVOKED* in);
/*!
* \brief
* X509_CRL_INFO 구조체 내의 X509_REVOKED의 개수를 확인하는 함수
* \param unit
* X509_CRL_INFO 구조체
* \returns
* 포함된 X509_REVOKED의 개수
*/
ISC_API int get_X509_REVOKED_count(X509_CRL_INFO *unit);
/*!
* \brief
* X509_CRL_INFO 구조체 내의 X509_REVOKED를 리턴받기 위한 함수
* \param unit
* X509_CRL_INFO 구조체
* \param loc
* 리턴받기 위한 해당 스택의 인덱스
* \returns
* X509_REVOKED 구조체
*/
ISC_API X509_REVOKED *get_X509_REVOKED(X509_CRL_INFO *unit, int loc);

/*!
* \brief
* X509_REVOKED 구조체 내의 userCert를 리턴받기 위한 함수
* \param unit
* X509_REVOKED 구조체
* \returns
* version을 담고있는 INTEGER 구조체
*/
ISC_API INTEGER* get_X509_REVOKED_userCert(X509_REVOKED *unit);
/*!
* \brief
* X509_REVOKED 구조체 내의 폐기일자를 리턴받기 위한 함수
* \param unit
* X509_REVOKED 구조체
* \returns
* 폐기일자를 담고있는 X509_TIME 구조체
*/
ISC_API X509_TIME* get_X509_REVOKED_revocationDate(X509_REVOKED *unit);
/*!
* \brief
* X509_REVOKED 구조체 내의 CRL폐기 이유를 확인하기 위한 함수 
* \param revoked
* X509_REVOKED 구조체
* \param loc
* X509_REVOKED의 특정 X509_EXTENSION의 index
* \returns
* CRL 폐기 이유
*/
ISC_API int get_X509_REVOKED_CRLreason(X509_REVOKED* revoked, int loc);

/*!
* \brief
* X509_REVOKED 구조체에 userCert를 입력하기 위한 함수
* \param x
* X509_REVOKED 구조체
* \param serial
* user SerialNumber (userCert)
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_REVOKED_userCert(X509_REVOKED *x, INTEGER *serial);
/*!
* \brief
* X509_REVOKED 구조체에 폐기일자를 입력하기 위한 함수
* \param unit
* X509_REVOKED 구조체
* \param revocationDate
* 폐기일자를 담고있는 X509_TIME 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_REVOKED_revocationDate(X509_REVOKED *unit, X509_TIME *revocationDate);

/*!
* \brief
* X509_REVOKED 구조체를 생성하여 X509_CRL 구조체에 입력하기 위한 함수
* \param unit
* X509_CRL 구조체
* \param userCert
* user SerialNumber (userCert)
* \param revokeTime
* 폐기일자를 담고있는 X509_TIME 구조체
* \param extentions
* 해당 목록의 부가적인 내용을 담고 있는 X509_EXTENSIONS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_X509_REVOKED_child(X509_CRL *unit, INTEGER* userCert, X509_TIME* revokeTime, 
						   X509_EXTENSION* extention);
/*!
* \brief
* 생성된 X509_REVOKED 구조체를 X509_CRL_INFO 구조체에 입력하기 위한 함수
* \param crl
* X509_CRL_INFO 구조체
* \param rev
* X509_REVOKED 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_X509_CRL_revoked(X509_CRL_INFO **crl, X509_REVOKED *rev);

/*!
* \brief
* X509_CRL_INFO 구조체내의 X509_REVOKED를 Sequence로 Encode 함수
* \param in
* X509_CRL_INFO 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_X509_REVOKED_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_X509_REVOKED_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_EXTENSIONS_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS X509_REVOKED_to_Seq(X509_CRL_INFO *in, SEQUENCE **seq);
/*!
* \brief
* Sequence를 X509_CRL_INFO 구조체내의 X509_REVOKED로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param out
* X509_CRL_INFO 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_X509_REVOKED^ISC_ERR_NULL_INPUT : Null input error
* -# LOCATION^F_SEQ_TO_X509_REVOKED^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_EXTENSIONS()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_X509_REVOKED(SEQUENCE *seq, X509_CRL_INFO **out);


/* =====================REVOKED내의 EXT관련 함수======================== */
/*!
* \brief
* X509_REVOKED 구조체의 X509 확장필드의 개수를 알기 위한 함수
* \param x
* 폐기목록에 대한 정보가 담겨있는 X509_REVOKED 구조체
* \returns
* 확장필드의 개수
*/
ISC_API int	get_X509_REVOKED_ext_count(X509_REVOKED *x);
/*!
* \brief
* X509_REVOKED 구조체의 X509 확장필드에서 입력받은 OID값이 저장된 index를 알기 위한 함수
* \param x
* 폐기목록에 대한 정보가 담겨있는 X509_REVOKED 구조체
* \param obj
* 찾고자 하는 OID
* \param lastpos
* 스택의 TOP
* \returns
* 해당 index
*/
ISC_API int get_X509_REVOKED_ext_by_OID(X509_REVOKED *x, OBJECT_IDENTIFIER *obj, int lastpos);
/*!
* \brief
* X509_REVOKED 구조체의 X509 확장필드에서 입력받은 OID값이 저장된 index를 알기 위한 함수
* \param x
* 폐기목록에 대한 정보가 담겨있는 X509_REVOKED 구조체
* \param OID_index
* 찾고자 하는 OID의 index
* \param lastpos
* 스택의 TOP
* \returns
* 해당 index
*/
ISC_API int get_X509_REVOKED_ext_index_by_OID_index(X509_REVOKED *x, int OID_index, int lastpos);

/*!
* \brief
* X509_REVOKED 구조체의 한 X509 확장필드를 얻기 위한 함수
* \param x
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \param loc
* 해당 인덱스
* \returns
* X509_EXTENSION 구조체
*/
ISC_API X509_EXTENSION *get_X509_REVOKED_ext(X509_REVOKED *x, int loc);
/*!
* \brief
* X509_REVOKED 구조체의 한 X509 확장필드를 제거하기 위한 함수
* \param x
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \param loc
* 해당 인덱스
* \returns
* 제거된 X509_EXTENSION 구조체
*/
ISC_API X509_EXTENSION *remove_X509_REVOKED_ext(X509_REVOKED *x, int loc);
/*!
* \brief
* X509_REVOKED 구조체에 X509 확장필드를 추가하기 위한 함수
* \param x
* 폐기목록에 대한 정보가 담겨있는 X509_CRL 구조체
* \param ex
* 추가하고자 하는 X509_EXTENSION 구조체
* \param loc
* 해당 인덱스
* \returns
* -# add_X509_EXTENSION의 에러코드\n
*/
ISC_API ISC_STATUS	add_X509_REVOKED_ext(X509_REVOKED *x, X509_EXTENSION *ex, int loc);


/* =======================X509_CRL 전체적인 함수============================ */
/*!
* \brief
* X509_CRL 구조체를 Sequence로 Encode 함수
* \param in
* X509_CRL 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_X509_CRL_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_CRL_INFO_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS X509_CRL_to_Seq(X509_CRL *in, SEQUENCE **seq);
/*!
* \brief
* Sequence를 P8_PRIV_KEY_INFO 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param crl
* P8_PRIV_KEY_INFO 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_X509_CRL^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_X509_CRL^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_CRL_INFO()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_X509_CRL(SEQUENCE *seq, X509_CRL **crl);

/*!
* \brief
* X509_CRLS 구조체의 초기화 함수
* \returns
* X509_CRLS 구조체 포인터
*/
ISC_API X509_CRLS *new_X509_CRLS();
/*!
* \brief
* X509_CRLS 구조체를 메모리 할당 해제
* \param x509Crls
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_CRLS(X509_CRLS *x509Crls);

/*!
* \brief
* X509_CRLS 구조체를 Sequence로 Encode 함수
* \param crls
* X509_CRL 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_X509_CRLS_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_X509_CRLS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_CRL_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS X509_CRLS_to_Seq(X509_CRLS *crls, SEQUENCE **seq);
/*!
* \brief
* Sequence를 X509_CRLS 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param crls
* X509_CRLS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_X509_CRLS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_X509_CRLS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_X509_CRLS^ERR_ASN1_DECODING : ASN1 Err
* -# LOCATION^F_SEQ_TO_X509_CRLS^ERR_STK_ERROR : stack error
* -# Seq_to_X509_CRL()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_X509_CRLS(SEQUENCE *seq, X509_CRLS **crls);

/*!
* \brief
* X509_CRL 구조체의 ISC_RSA 서명을 하는 함수
* \param tbs
* X509_CRL 구조체
* \param rsa_signature
* ISC_RSA 서명값
* \param alg
* 서명 알고리즘 OID
* \param pri_params
* ISC_RSA 키
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_GEN_RSASIGN^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_GEN_RSASIGN^ISC_ERR_INVALID_INPUT : input error
* -# X509_CRL_INFO_to_Seq()의 에러 코드\n
* -# ISC_Init_RSASSA()의 에러 코드\n
* -# ISC_Update_RSASSA()의 에러 코드\n
* -# ISC_Final_RSASSA()의 에러 코드\n
*/
ISC_API ISC_STATUS gen_RSA_SIG_X509_CRL(X509_CRL* tbs, BIT_STRING** rsa_signature, OBJECT_IDENTIFIER *alg, ISC_RSA_UNIT* pri_params);
/*!
* \brief
* X509_CRL 구조체의 ISC_KCDSA 서명을 하는 함수
* \param crl
* X509_CRL 구조체
* \param signature
* ISC_KCDSA 서명값
* \param alg
* 서명 알고리즘 OID
* \param pri_params
* ISC_KCDSA 키
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_GEN_KCDSASIGN^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_GEN_KCDSASIGN^ISC_ERR_INVALID_INPUT : input error
* -# X509_CRL_INFO_to_Seq()의 에러 코드\n
* -# ISC_Init_KCDSA()의 에러 코드\n
* -# ISC_Update_KCDSA()의 에러 코드\n
* -# ISC_Final_KCDSA()의 에러 코드\n
*/
ISC_API ISC_STATUS gen_KCDSA_SIG_X509_CRL(X509_CRL* crl, BIT_STRING** signature, OBJECT_IDENTIFIER *alg, ISC_KCDSA_UNIT* pri_params);
/*!
* \brief
* X509_CRL 구조체의 ISC_ECDSA 서명을 하는 함수
* \param tbs
* X509_CRL 구조체
* \param ecdsa_signature
* ISC_ECDSA 서명값
* \param alg
* 서명 알고리즘 OID
* \param pri_params
* ISC_ECDSA 키
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_GEN_RSASIGN^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_GEN_RSASIGN^ISC_ERR_INVALID_INPUT : input error
* -# X509_CRL_INFO_to_Seq()의 에러 코드\n
* -# ISC_Init_ECDSA()의 에러 코드\n
* -# ISC_Update_ECDSA()의 에러 코드\n
* -# ISC_Final_ECDSA()의 에러 코드\n
*/
ISC_API ISC_STATUS gen_ECDSA_SIG_X509_CRL(X509_CRL* tbs, BIT_STRING** ecdsa_signature, OBJECT_IDENTIFIER *alg, ISC_ECDSA_UNIT* pri_params);

/*!
* \brief
* X509_CRL 구조체의 서명값(ISC_RSA)을 검증하는 함수
* \param cert
* X509_CRL 구조체
* \param pub_params
* ISC_RSA 키
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_VERIFY_RSASIGN^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_VERIFY_RSASIGN^ISC_ERR_INVALID_INPUT : input error
* -# X509_CRL_INFO_to_Seq()의 에러 코드\n
* -# ISC_Init_RSASSA()의 에러 코드\n
* -# ISC_Update_RSASSA()의 에러 코드\n
* -# ISC_Final_RSASSA()의 에러 코드\n
*/
ISC_API ISC_STATUS verify_RSA_SIG_X509_CRL(X509_CRL* cert, ISC_RSA_UNIT* pub_params);
/*!
* \brief
* X509_CRL 구조체의 서명값(ISC_KCDSA)을 검증하는 함수
* \param cert
* X509_CRL 구조체
* \param pub_params
* ISC_KCDSA 키
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_VERIFY_KCDSASIGN^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_VERIFY_KCDSASIGN^ISC_ERR_INVALID_INPUT : input error
* -# X509_CRL_INFO_to_Seq()의 에러 코드\n
* -# ISC_Init_KCDSA()의 에러 코드\n
* -# ISC_Update_KCDSA()의 에러 코드\n
* -# ISC_Final_KCDSA()의 에러 코드\n
*/
ISC_API ISC_STATUS verify_KCDSA_SIG_X509_CRL(X509_CRL* cert, ISC_KCDSA_UNIT* pub_params);
/*!
* \brief
* X509_CRL 구조체의 서명값을 검증하는 함수
* \param cert
* X509_CRL 구조체
* \param pubKey
* X509_PUBKEY 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
* -# verify_RSA_SIG_X509_CRL()의 에러 코드\n
* -# verify_KCDSA_SIG_X509_CRL()의 에러 코드\n
*/
ISC_API ISC_STATUS verify_SIG_X509_CRL(X509_CRL* cert, X509_PUBKEY* pubKey);

#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(X509_CRL*, new_X509_CRL, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_CRL, (X509_CRL *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_X509_CRL, (X509_CRL *unit), (unit) );
INI_RET_LOADLIB_PKI(X509_CRL_INFO*, new_X509_CRL_INFO, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_CRL_INFO, (X509_CRL_INFO *unit), (unit) );
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_CRL_version, (X509_CRL *unit, uint8 version), (unit,version), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_CRL_signature, (X509_CRL *unit, OBJECT_IDENTIFIER *oid), (unit,oid), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_CRL_issuer, (X509_CRL *unit, X509_NAME *name), (unit,name), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_CRL_thisUpdate, (X509_CRL *unit, X509_TIME *thisUpdate), (unit,thisUpdate), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_CRL_nextUpdate, (X509_CRL *unit, X509_TIME *nextUpdate), (unit,nextUpdate), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_CRL_sig_value, (X509_CRL *unit, BIT_STRING* sigValue), (unit,sigValue), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_CRL_sig_alg, (X509_CRL *unit, OBJECT_IDENTIFIER* oid), (unit,oid), ISC_FAIL);
INI_RET_LOADLIB_PKI(uint8, get_X509_CRL_version, (X509_CRL *unit), (unit), ISC_FAIL);
INI_RET_LOADLIB_PKI(OBJECT_IDENTIFIER*, get_X509_CRL_signature, (X509_CRL *unit), (unit), NULL);
INI_RET_LOADLIB_PKI(X509_NAME*, get_X509_CRL_issuer, (X509_CRL *unit), (unit), NULL);
INI_RET_LOADLIB_PKI(X509_TIME*, get_X509_CRL_thisUpdate, (X509_CRL *unit), (unit), NULL);
INI_RET_LOADLIB_PKI(X509_TIME*, get_X509_CRL_nextUpdate, (X509_CRL *unit), (unit), NULL);
INI_RET_LOADLIB_PKI(X509_REVOKED*, get_X509_CRL_revoked, (X509_CRL *unit, int loc), (unit,loc), NULL);
INI_RET_LOADLIB_PKI(OBJECT_IDENTIFIER*, get_X509_CRL_sig_alg, (X509_CRL *unit), (unit), NULL);
INI_RET_LOADLIB_PKI(BIT_STRING*, get_X509_CRL_sig_value, (X509_CRL *unit), (unit), NULL);
INI_RET_LOADLIB_PKI(int, get_X509_CRL_ext_count, (X509_CRL *x), (x), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_X509_CRL_ext_by_OBJ, (X509_CRL *x, OBJECT_IDENTIFIER *obj, int lastpos), (x,obj,lastpos), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_X509_CRL_ext_index_by_OID_index, (X509_CRL *x, int OID_index, int lastpos), (x,OID_index,lastpos), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_EXTENSION*, get_X509_CRL_ext, (X509_CRL *x, int loc), (x,loc), NULL);
INI_RET_LOADLIB_PKI(X509_EXTENSION*, remove_X509_CRL_ext, (X509_CRL *x, int loc), (x,loc), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_X509_CRL_ext, (X509_CRL *x, X509_EXTENSION *ex, int loc), (x,ex,loc), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, sort_X509_CRL_revoked, (X509_CRL *c), (c), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, X509_CRL_INFO_to_Seq, (X509_CRL_INFO *in, SEQUENCE **seq), (in,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_X509_CRL_INFO, (SEQUENCE *seq, X509_CRL_INFO **crl_info), (seq,crl_info), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, verify_CRL_X509_CERT, (X509_CRL *crl, X509_CERT *x), (crl,x), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_REVOKED*, new_X509_REVOKED, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_REVOKED, (X509_REVOKED* revoked), (revoked) );
INI_VOID_LOADLIB_PKI(void, free_X509_REVOKED_LIST, (X509_REVOKED_LIST* revoked_list), (revoked_list) );
INI_RET_LOADLIB_PKI(X509_REVOKED*, dup_X509_REVOKED, (X509_REVOKED* in), (in), NULL);
INI_RET_LOADLIB_PKI(int, get_X509_REVOKED_count, (X509_CRL_INFO *unit), (unit), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_REVOKED*, get_X509_REVOKED, (X509_CRL_INFO *unit, int loc), (unit,loc), NULL);
INI_RET_LOADLIB_PKI(INTEGER*, get_X509_REVOKED_userCert, (X509_REVOKED *unit), (unit), NULL);
INI_RET_LOADLIB_PKI(X509_TIME*, get_X509_REVOKED_revocationDate, (X509_REVOKED *unit), (unit), NULL);
INI_RET_LOADLIB_PKI(int, get_X509_REVOKED_CRLreason, (X509_REVOKED* revoked, int loc), (revoked,loc), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_REVOKED_userCert, (X509_REVOKED *x, INTEGER *serial), (x,serial), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_REVOKED_revocationDate, (X509_REVOKED *unit, X509_TIME *revocationDate), (unit,revocationDate), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_X509_REVOKED_child, (X509_CRL *unit, INTEGER* userCert, X509_TIME* revokeTime, X509_EXTENSION* extention), (unit,userCert,revokeTime,extention), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_X509_CRL_revoked, (X509_CRL_INFO **crl, X509_REVOKED *rev), (crl,rev), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, X509_REVOKED_to_Seq, (X509_CRL_INFO *in, SEQUENCE **seq), (in,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_X509_REVOKED, (SEQUENCE *seq, X509_CRL_INFO **out), (seq,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_X509_REVOKED_ext_count, (X509_REVOKED *x), (x), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_X509_REVOKED_ext_by_OID, (X509_REVOKED *x, OBJECT_IDENTIFIER *obj, int lastpos), (x,obj,lastpos), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_X509_REVOKED_ext_index_by_OID_index, (X509_REVOKED *x, int OID_index, int lastpos), (x,OID_index,lastpos), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_EXTENSION*, get_X509_REVOKED_ext, (X509_REVOKED *x, int loc), (x,loc), NULL);
INI_RET_LOADLIB_PKI(X509_EXTENSION*, remove_X509_REVOKED_ext, (X509_REVOKED *x, int loc), (x,loc), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_X509_REVOKED_ext, (X509_REVOKED *x, X509_EXTENSION *ex, int loc), (x,ex,loc), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, X509_CRL_to_Seq, (X509_CRL *in, SEQUENCE **seq), (in,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_X509_CRL, (SEQUENCE *seq, X509_CRL **crl), (seq,crl), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_CRLS*, new_X509_CRLS, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_CRLS, (X509_CRLS *x509Crls), (x509Crls) );
INI_RET_LOADLIB_PKI(ISC_STATUS, X509_CRLS_to_Seq, (X509_CRLS *crls, SEQUENCE **seq), (crls,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_X509_CRLS, (SEQUENCE *seq, X509_CRLS **crls), (seq,crls), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, gen_RSA_SIG_X509_CRL, (X509_CRL* tbs, BIT_STRING** rsa_signature, OBJECT_IDENTIFIER *alg, ISC_RSA_UNIT* pri_params), (tbs,rsa_signature,alg,pri_params), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, gen_KCDSA_SIG_X509_CRL, (X509_CRL* crl, BIT_STRING** signature, OBJECT_IDENTIFIER *alg, ISC_KCDSA_UNIT* pri_params), (crl,signature,alg,pri_params), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, gen_ECDSA_SIG_X509_CRL, (X509_CRL* crl, BIT_STRING** signature, OBJECT_IDENTIFIER *alg, ISC_ECDSA_UNIT* pri_params), (crl,signature,alg,pri_params), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, verify_RSA_SIG_X509_CRL, (X509_CRL* cert, ISC_RSA_UNIT* pub_params), (cert,pub_params), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, verify_KCDSA_SIG_X509_CRL, (X509_CRL* cert, ISC_KCDSA_UNIT* pub_params), (cert,pub_params), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, verify_SIG_X509_CRL, (X509_CRL* cert, X509_PUBKEY* pubKey), (cert,pubKey), ISC_FAIL);


#endif

#ifdef  __cplusplus
}
#endif
#endif
