/*!
* \file x509.h
* \brief X509 Certificate
* \remarks
* RFC5280, KCAC.TS.CERTPROF
* \author
* Copyright (c) 2008 by \<INITech\>
*/ 

#ifndef HEADER_X509_H
#define HEADER_X509_H

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/foundation.h>

#include "asn1.h"
#include "asn1_stack.h"

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef WIN32
#define CP949
#undef X509_CERT
#undef X509_NAME
#undef X509_PUBKEY
#undef X509_TBS_CERT
#undef X509_EXTENSIONS
#undef X509_CERT_PAIR
#endif

#define ASYMMETRIC_RSA_KEY	  1		/*!< ISC_RSA keytype*/
#define ASYMMETRIC_KCDSA_KEY  2		/*!< ISC_KCDSA keytype*/
#define ASYMMETRIC_ECDSA_KEY  3		/*!< ECDSA keytype*/
#define ASYMMETRIC_ECC_KEY    4		/*!< ECC keytype*/

/*!
 * \brief
 * X509 및 pkcs5/8에 사용되는 공개키를 포함한 구조체
 */
typedef struct asymmetric_key_parma_st{
	int keyType;		/*!< 키 정보*/
	union{		
		ISC_RSA_UNIT* rsa_key;		/*!< ISC_RSA 키 정보*/
		ISC_KCDSA_UNIT* kcdsa_key;	/*!< ISC_KCDSA 키 정보*/
		ISC_ECDSA_UNIT* ecdsa_key;	/*!< ECDSA 키 정보*/
		ISC_ECC_KEY_UNIT* ecc_key;	/*!< ECC 키 정보*/
	}keyData;	
}ASYMMETRIC_KEY;

/*!
* \brief
* X509 DN을 구성하는 요소
*/
typedef struct X509_NAME_CHILD_st
{
	OBJECT_IDENTIFIER *object;	/*!< */
	ASN1_STRING *value;		/*!< */
} X509_NAME_CHILD;

/*!
* \brief
* X509 Distinguished Name
*/
typedef STK(X509_NAME_CHILD) X509_NAME;

/*!
* \brief
* X509 TIME
* Time ::= CHOICE {
*				utcTime	UTCTime,
*				generalTime	GeneralizedTime
*			}
*/
typedef struct X509_time_st
{
	int type;		/* 0 : utcTime, 1 : generalTime */
	union {
		UTC_TIME *utcTime;
		GENERALIZED_TIME *generalTime;
	} time;
} X509_TIME;

/*!
* \brief
* X509 Validity
*/
typedef struct X509_valid_st
{
	X509_TIME *notBefore;	/*!< */
	X509_TIME *notAfter;	/*!< */
} X509_VALIDITY;

/*!
* \brief
* X509 Public Key
*/
typedef struct X509_pubkey_st
{
	OBJECT_IDENTIFIER *algorithm;	/*!< */
	BIT_STRING *public_key;	/*!< */
	ASYMMETRIC_KEY *akey;	/*!< */
} X509_PUBKEY;

/*!
* \brief
* X509 Extensions의 구성 요소
*/
typedef struct X509_extension_st
{
	OBJECT_IDENTIFIER *object;	/*!< */
	BOOLEAN critical;	/*!< */
	OCTET_STRING *value;	/*!< */
} X509_EXTENSION;

/*!
* \brief
* X509 Extensions
*/
typedef STK(X509_EXTENSION) X509_EXTENSIONS;

/*!
* \brief
* X509 Attribute Data 구조체
*/
typedef struct x509_attribute_data_st
{
	int type;
	void *data;
} X509_ATTRIBUTE_DATA;
    
/*!
* \brief
* X509 Attribute Data 구조체 리스트
*/
typedef STK(X509_ATTRIBUTE_DATA) X509_ATTRIBUTE_DATAS;

#define new_X509_ATTRIBUTE_DATA_STK() new_STK(X509_ATTRIBUTE_DATA)
#define free_X509_ATTRIBUTE_DATA_STK(st) free_STK(X509_ATTRIBUTE_DATA, (st))
#define get_X509_ATTRIBUTE_DATA_STK_count(st) get_STK_count(X509_ATTRIBUTE_DATA, (st))
#define get_X509_ATTRIBUTE_DATA_STK_value(st, i) get_STK_value(X509_ATTRIBUTE_DATA, (st), (i))
#define push_X509_ATTRIBUTE_DATA_STK_value(st, val) push_STK_value(X509_ATTRIBUTE_DATA, (st), (val))
#define find_X509_ATTRIBUTE_DATA_STK_value(st, val) find_STK_value(X509_ATTRIBUTE_DATA, (st), (val))
#define remove_X509_ATTRIBUTE_DATA_STK_value(st, i) remove_STK_value(X509_ATTRIBUTE_DATA, (st), (i))
#define insert_X509_ATTRIBUTE_DATA_STK_value(st, val, i) insert_STK_value(X509_ATTRIBUTE_DATA, (st), (val), (i))
#define dup_X509_ATTRIBUTE_DATA_STK(st) dup_STK(X509_ATTRIBUTE_DATA, st)
#define free_X509_ATTRIBUTE_DATA_STK_values(st, free_func) free_STK_values(X509_ATTRIBUTE_DATA, (st), (free_func))
#define pop_X509_ATTRIBUTE_DATA_STK_value(st) pop_STK_value(X509_ATTRIBUTE_DATA, (st))
#define sort_X509_X509_ATTRIBUTE_DATA(st) sort_STK(X509_ATTRIBUTE_DATA, (st))
#define is_X509_ATTRIBUTE_DATA_STK_sorted(st) is_STK_sorted(X509_ATTRIBUTE_DATA, (st))

/*!
* \brief
* X509 Attribute
*/
typedef struct x509_attribute_st
{
	OBJECT_IDENTIFIER *object;	/*!< attribute의 oid*/
	X509_ATTRIBUTE_DATAS *values;	/*!< attribute의 values*/
} X509_ATTRIBUTE;

/*!
* \brief
* X509 Attributes
*/
typedef STK(X509_ATTRIBUTE) X509_ATTRIBUTES;

/*!
* \brief
* X509 TBS Certificate 구조체
*/
typedef struct x509_tbs_st
{
	uint8 version;						/*!< 버젼 정보 */		
	ISC_BIGINT *serialnumber;				/*!< 시리얼 번호 */
	OBJECT_IDENTIFIER *signature;		/*!< 전자서명 알고리즘 */
	X509_NAME *issuer;					/*!< 발급자 정보 DN*/
	X509_VALIDITY *validity;			/*!< 유효기간 */
	X509_NAME *subject;					/*!< 주체자 정보 DN*/
	X509_PUBKEY *pubkey;				/*!< 주차자의 공개키 */
	BIT_STRING *issuerUniqueID;         /*!< 발급자 식별 ID */
	BIT_STRING *subjectUniqueID;        /*!< 주체자 식별 ID */ 
	X509_EXTENSIONS *exts;				/*!< x509v3 확장 필드 */
} X509_TBS_CERT;

/*!
* \brief
* X509 인증서 내의 PKCS12 friendly name / LKID의 캐쉬
*/
typedef struct x509_aux_st
{
	UTF8_STRING *friendly;
	OCTET_STRING *localkeyID;		
} X509_AUX;

/*!
* \brief
* X509 Certificate 구조체
*/
typedef struct x509_st
{
	X509_TBS_CERT *tbs;		/*!< X509 TBS 인증서 정보 */		
	OBJECT_IDENTIFIER *sig_alg;	 /*!< 인증서 서명 알고리즘 */		
	BIT_STRING *signature;		 /*!< 인증서 서명값 */		
	X509_AUX * aux_verify;		 /*!< PKCS12에서 사용되는 friendly name, LKID */
} X509_CERT;

/*!
* \brief
* X509 Certificate Pair 구조체
*/
typedef struct cert_pair_st
{
	X509_CERT* a;
	X509_CERT* b;
}X509_CERT_PAIR;

/*!
* \brief
* X509 Certificate STACK
*/
typedef STK(X509_CERT) X509_CERTS;

/*!
* \brief
* X509 및 pkcs 등에 사용되는 알고리즘 명세 구조체
*/
typedef struct X509_ALGO_IDENTIFIER_st {
	OBJECT_IDENTIFIER *algorithm;  /*!< 알고리즘의 OBJECT IDENTIFIER */
	ASN1_STRING *parameters; /*!< 알고리즘에 따른 Parameter */
} X509_ALGO_IDENTIFIER;

typedef STK(X509_ALGO_IDENTIFIER) X509_ALGO_IDENTIFIERS;

/*!
* \brief
* X509 Signature을 구성하는 요소
*/
typedef struct X509_SIGN_st
{
	X509_ALGO_IDENTIFIER *algorithm;	/*!< hash 알고리즘*/
	OCTET_STRING *hashedData;		/*!< h(m)값 */

} X509_SIGN;

    
#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* X509_CERT 구조체의 초기화 함수
* \returns
* X509_CERT 구조체 포인터
*/
ISC_API X509_CERT *new_X509_CERT(void);

/*!
* \brief
* X509_CERT 구조체를 메모리 할당 해제
* \param cert
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_CERT(X509_CERT *cert);

/*!
* \brief
* X509_CERT 구조체를 리셋
* \param cert
* 리셋할 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API void clean_X509_CERT(X509_CERT *cert);

/*!
* \brief
* X509_CERT의 version을 지정
* \param cert
* 지정될 인증서
* \param version
* 버젼 정보 (0x00, 0x01, 0x02)
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_version(X509_CERT *cert, uint8 version);

/*!
* \brief
* X509_CERT의 serialnumber 지정
* \param cert
* 지정될 인증서
* \param serialnumber
* 인증서 시리얼 번호
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_serial (X509_CERT *cert, INTEGER *serialnumber);

/*!
* \brief
* X509_CERT의 서명 알고리즘 지정
* \param cert
* 지정될 인증서
* \param oid
* 인증서 서명 알고리즘
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_signature(X509_CERT *cert, OBJECT_IDENTIFIER *oid);

/*!
* \brief
* X509_CERT의 발급자 DN 지정
* \param cert
* 지정될 인증서
* \param name
* 발급자 DN
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_issuer (X509_CERT *cert, X509_NAME *name);

/*!
* \brief
* X509_CERT의 주체자 DN 지정
* \param cert
* 지정될 인증서
* \param name
* 발급자 DN
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_subject (X509_CERT *cert, X509_NAME *name);

/*!
* \brief
* X509_CERT의 notBefore 지정
* \param cert
* 지정될 인증서
* \param notBefore
* notAfter의 X509_TIME 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_notBefore(X509_CERT *cert, X509_TIME *notBefore);

/*!
* \brief
* X509_CERT의 notAfter 지정
* \param cert
* 지정될 인증서
* \param notAfter
* notAfter의 X509_TIME 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_notAfter(X509_CERT *cert, X509_TIME *notAfter);

/*!
* \brief
* X509_CERT의 public key 지정
* \param cert
* 지정될 인증서
* \param key
* x509 pubic key 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_pub_key(X509_CERT *cert, X509_PUBKEY *key);

/*!
* \brief
* X509_CERT의 버젼정보 리턴
* \param cert
* 인증서 구조체 포인터
* \returns
* 버젼정보
*/
ISC_API uint8 get_X509_version(X509_CERT *cert);

/*!
* \brief
* X509_CERT의 시리얼 번호 리턴
* \param cert
* 인증서 구조체 포인터
* \returns
* 시리얼 번호
*/
ISC_API INTEGER* get_X509_serial(X509_CERT *cert);

/*!
* \brief
* X509_CERT의 서명알고리즘 리턴
* \param cert
* 인증서 구조체 포인터
* \returns
* 서명 알고리즘
*/
ISC_API OBJECT_IDENTIFIER* get_X509_signature(X509_CERT *cert);
/*!
* \brief
* X509_CERT의 발급자 DN 리턴
* \param cert
* 인증서 구조체 포인터
* \returns
* 발급자 DN
*/
ISC_API X509_NAME* get_X509_issuer(X509_CERT *cert);

/*!
* \brief
* X509_CERT의 주체자 DN 리턴
* \param cert
* 인증서 구조체 포인터
* \returns
* 주체자 DN
*/
ISC_API X509_NAME* get_X509_subject(X509_CERT *cert);

/*!
* \brief
* X509_CERT의 NotAfter 시간정보 리턴
* \param cert
* 인증서 구조체 포인터
* \returns
* NotAfter 시간정보
*/
ISC_API X509_TIME* get_X509_notAfter(X509_CERT *cert);

/*!
* \brief
* X509_CERT의 NotBefore 시간정보 리턴
* \param cert
* 인증서 구조체 포인터
* \returns
* NotBefore 시간정보
*/
ISC_API X509_TIME* get_X509_notBefore(X509_CERT *cert);

/*!
* \brief
* X509_CERT의 공개키 정보 리턴
* \param cert
* 인증서 구조체 포인터
* \returns
* X509 공개키 정보
*/
ISC_API X509_PUBKEY* get_X509_SPKI(X509_CERT *cert);

/*!
* \brief
* X509_CERT의 서명 알고리즘 리턴
* \param cert
* 인증서 구조체 포인터
* \returns
* 서명 알고리즘 정보
*/
ISC_API OBJECT_IDENTIFIER* get_X509_sig_alg(X509_CERT *cert);

/*!
* \brief
* X509_CERT의 서명값 리턴
* \param cert
* 인증서 구조체 포인터
* \returns
* 서명값 정보
*/
ISC_API BIT_STRING* get_X509_sig_value(X509_CERT *cert);



/*!
* \brief
* X509_CERT_PAIR 구조체의 초기화 함수
* \returns
* X509_CERT_PAIR 구조체 포인터
*/
ISC_API X509_CERT_PAIR *new_X509_CERT_PAIR();

/*!
* \brief
* X509_CERT_PAIR 구조체를 메모리 할당 해제
* \param x509_certPair
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_CERT_PAIR(X509_CERT_PAIR* x509_certPair);

/*!
* \brief
* X509_TIME 구조체의 초기화 함수
* \returns
* X509_TIME 구조체 포인터
*/
ISC_API X509_TIME* new_X509_TIME();

/*!
* \brief
* X509_TIME 구조체를 메모리 할당 해제
* \param name
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_TIME(X509_TIME *name);

/*!
* \brief
* X509_TIME 구조체를 복사하는 함수
* \param from
* 복사할 원본
* \param to
* 복사될 대상(메모리 할당해서 줄것.)
*/
ISC_API ISC_STATUS copy_X509_TIME(X509_TIME *from, X509_TIME *to);

/*!
* \brief
* X509_NAME 구조체의 초기화 함수
* \returns
* X509_NAME 구조체 포인터
*/
ISC_API X509_NAME* new_X509_NAME();

/*!
* \brief
* X509_NAME 구조체를 메모리 할당 해제
* \param name
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_NAME(X509_NAME* name);

/*!
* \brief
* X509_NAME_CHILD 구조체의 초기화 함수
* \returns
* X509_NAME_CHILD 구조체 포인터
*/
ISC_API X509_NAME_CHILD* new_X509_NAME_CHILD();

/*!
* \brief
* X509_NAME_CHILD 구조체를 메모리 할당 해제
* \param name
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_NAME_CHILD(X509_NAME_CHILD* name);

/*!
* \brief
* X509_NAME_CHILD 구조체를 복사
* \param name
* 복사할 구조체 포인터
* \return
* X509_NAME_CHILD 구조체 포인터
*/
ISC_API X509_NAME_CHILD* dup_X509_NAME_CHILD(X509_NAME_CHILD* name);

/*!
* \brief
* X509_NAME구조체에 X509_NAME_CHILD를 삽입
* \param name
* X509_NAME 구조체 포인터
* \param child
* X509_NAME_CHILD 구조체 포인터
* \param loc
* 저장될 위치 (default : -1)
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_X509_NAME_child(X509_NAME *name, X509_NAME_CHILD *child, int loc);

/*!
* \brief
* X509_NAME구조체에 X509_NAME_CHILD를 삽입 (OID index명에 의해)
* \param name
* X509_NAME 구조체 포인터
* \param index
* oid index (asn1_object.h 참조)
* \param type
* ans1 타입
* \param bytes
* value
* \param len
* value의 길이
* \param loc
* 저장될 위치 (default : -1)
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_X509_NAME_child_OID_index(X509_NAME *name, int index, int type, uint8 *bytes, int len, int loc);

/*!
* \brief
* X509_NAME구조체에 X509_NAME_CHILD를 삽입 (OID 에 의해)
* \param name
* X509_NAME 구조체 포인터
* \param oid
* oid 구조체(asn1_object.h 참조)
* \param type
* ans1 타입
* \param bytes
* value
* \param len
* value의 길이
* \param loc
* 저장될 위치 (default : -1)
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_X509_NAME_child_OID(X509_NAME *name, OBJECT_IDENTIFIER *oid, int type, uint8 *bytes, int len, int loc);

/*!
* \brief
* X509_NAME구조체내에 loc 의 위치에 있는 child 삭제
* \param name
* X509_NAME 구조체 포인터
* \param loc
* 삭제될 위치
* \return
* 삭제된 X509_NAME_CHILD구조체의 포인터
*/
ISC_API X509_NAME_CHILD *remove_X509_NAME_child(X509_NAME *name, int loc);

/*!
* \brief
* X509_NAME구조체가 담고 있는 Child의 개수 반환
* \param name
* X509_NAME 구조체 포인터
* \return
* child의 개수
*/
ISC_API int get_X509_NAME_count(X509_NAME *name);

/*!
* \brief
* X509_NAME_CHILD구조체가 담고 있는 데이터 반환
* \param child
* X509_NAME_CHILD 구조체 포인터
* \return
* ASN1_STRING 구조체 포인터
*/
ISC_API ASN1_STRING *get_X509_NAME_CHILD_data(X509_NAME_CHILD *child);

/*!
* \brief
* X509_NAME_CHILD구조체가 담고 있는 OBJECT_IDENTIFIER 반환
* \param child
* X509_NAME_CHILD 구조체 포인터
* \return
* OBJECT_IDENTIFIER 구조체 포인터
*/
ISC_API OBJECT_IDENTIFIER *get_X509_NAME_CHILD_OID(X509_NAME_CHILD *child);

/*!
* \brief
* X509_NAME구조체의 loc에 위치한 X509_NAME_CHILD의 포인터 반환
* \param name
* X509_NAME 구조체 포인터
* \param loc
* 인덱스
* \return
* X509_NAME_CHILD 구조체 포인터
*/
ISC_API X509_NAME_CHILD *get_X509_NAME_CHILD(X509_NAME *name, int loc);

/*!
* \brief
* X509_NAME구조체의 OBJECT_IDENTIFIER와 일치하는 인덱스를 lastpos부터 검색
* \param name
* X509_NAME 구조체 포인터
* \param oid
* OBJECT_IDENTIFIER 구조체 포인터
* \param lastpos
* 인덱스 (default = -1)
* \return
* -# oid와 일치하는 인덱스
* -# oid와 일치하는 인덱스가 없을경우 -1
*/
ISC_API int get_X509_NAME_index_by_OID(X509_NAME *name, OBJECT_IDENTIFIER *oid,int lastpos);

/*!
* \brief
* X509_NAME 구조체를 복사
* \param src
* 복사할 구조체 포인터
* \return
* X509_NAME 구조체 포인터
*/
ISC_API X509_NAME * dup_X509_NAME(X509_NAME * src);

/*!
* \brief
* X509_NAME 구조체를 비교
* \param n1
* X509_NAME 구조체 포인터
* \param n2
* X509_NAME 구조체 포인터
* \return
* -# 0 : 동일할 경우
* -# -1 : 같지 않을 경우
* -# ISC_FAIL : 실패
*/
ISC_API int cmp_X509_NAME(X509_NAME *n1, X509_NAME *n2);

/*!
* DN 비교룰에 따른 이름 비교 함수
* \brief
* X509_NAME 구조체를 비교
* \param n1
* X509_NAME 구조체 포인터
* \param n2
* X509_NAME 구조체 포인터
* \return
* -# 0 : 동일할 경우
* -# -1 : 같지 않을 경우
* -# ISC_FAIL : 실패
*/
ISC_API int cmp_X509_DN(X509_NAME *n1, X509_NAME *n2);

/*!
* \brief
* X509_NAME-der 인코딩의 해시값을 구함
* \param name
* X509_NAME 구조체 포인터
* \param digest_id
* 다이제스트 알고리즘 ID
* \param md
* 결과값이 저장될 포인터
* \return
* 결과값이 저장된 길이
*/
ISC_API int get_X509_NAME_hash(X509_NAME *name,int digest_id, uint8* md);



/*!
* \brief
* X509_PUBKEY 구조체의 초기화 함수
* \returns
* X509_PUBKEY 구조체 포인터
*/
ISC_API X509_PUBKEY* new_X509_PUBKEY();

/*!
* \brief
* X509_PUBKEY 구조체를 메모리 할당 해제
* \param pkey
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_PUBKEY(X509_PUBKEY* pkey);

/*!
* \brief
* X509_PUBKEY 구조체에 rsa 공개키를 입력
* \param pkey
* X509_PUBKEY 구조체 포인터
* \param rsa
* rsa 키
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_PUBKEY_rsa(X509_PUBKEY* pkey, ISC_RSA_UNIT* rsa);

/*!
* \brief
* X509_PUBKEY 구조체에 kcdsa 공개키를 입력
* \param pkey
* X509_PUBKEY 구조체 포인터
* \param kcdsa
* kcdsa 키
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_PUBKEY_kcdsa(X509_PUBKEY* pkey, ISC_KCDSA_UNIT* kcdsa);

/*!
 * \brief
 * X509_PUBKEY 구조체에 ecdsa 공개키를 입력
 * \param pkey
 * X509_PUBKEY 구조체 포인터
 * \param ecdsa
 * kcdsa 키
 * \return
 * -# ISC_SUCCESS : 성공
 * -# ISC_FAIL : 실패
 */
ISC_API ISC_STATUS set_X509_PUBKEY_ecdsa(X509_PUBKEY* pkey, ISC_ECDSA_UNIT* ecdsa);
    
/*!
* \brief
* X509 인증서가 포함하고 있는 공개키의 해시값을 구함
* \param cert
* X509_CERT 구조체 포인터
* \param digest_id
* 다이제스트 알고리즘 ID
* \param md
* 해시값이 저장될 버퍼(메모리 할당 되어 있어야 함)
* \return
* 버퍼에 저장된 길이
* 0 : 실패
*/
ISC_API int get_X509_PUBLIC_KEY_hash(X509_CERT *cert,int digest_id, uint8* md);


/*!
* \brief
* X509_TBS 인증서를 ISC_RSA알고리즘으로 서명
* \param tbs
* X509_CERT 구조체 포인터
* \param sig_value
* 서명값이 저장될 포인터
* \param alg
* 서명 알고리즘 oid
* \param pri_params
* ISC_RSA 개인키가 포함된 구조체 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_GEN_RSASIGN_TBS_CERT^ISC_ERR_NULL_INPUT : 입력이 NULL일 경우
* -# LOCATION^F_GEN_RSASIGN_TBS_CERT^ISC_ERR_INVALID_INPUT : alg의 알고리즘의 인식 불가, ISC_RSA계열이 아닐 경우
*/
ISC_API ISC_STATUS gen_RSA_SIG_X509_TBS_CERT(X509_TBS_CERT* tbs, BIT_STRING** sig_value, OBJECT_IDENTIFIER *alg, ISC_RSA_UNIT* pri_params);

/*!
* \brief
* X509_TBS 인증서를 ISC_KCDSA알고리즘으로 서명
* \param tbs
* X509_CERT 구조체 포인터
* \param signature
* 서명값이 저장될 포인터
* \param alg
* 서명 알고리즘 oid
* \param pri_params
* ISC_KCDSA 개인키가 포함된 구조체 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_GEN_KCDSASIGN_TBS_CERT^ISC_ERR_NULL_INPUT : 입력이 NULL일 경우
* -# LOCATION^F_GEN_KCDSASIGN_TBS_CERT^ISC_ERR_INVALID_INPUT : alg의 알고리즘의 인식 불가, ISC_KCDSA계열이 아닐 경우
*/
ISC_API ISC_STATUS gen_KCDSA_SIG_X509_TBS_CERT(X509_TBS_CERT* tbs, BIT_STRING** signature, OBJECT_IDENTIFIER *alg, ISC_KCDSA_UNIT* pri_params);

/*!
 * \brief
 * X509_TBS 인증서를 ISC_ECDSA알고리즘으로 서명
 * \param tbs
 * X509_CERT 구조체 포인터
 * \param signature
 * 서명값이 저장될 포인터
 * \param alg
 * 서명 알고리즘 oid
 * \param pri_params
 * ISC_ECDSA 개인키가 포함된 구조체 포인터
 * \return
 * -# ISC_SUCCESS : 성공
 * -# LOCATION^F_GEN_ECDSASIGN_TBS_CERT^ISC_ERR_NULL_INPUT : 입력이 NULL일 경우
 * -# LOCATION^F_GEN_ECDSASIGN_TBS_CERT^ISC_ERR_INVALID_INPUT : alg의 알고리즘의 인식 불가, ISC_KCDSA계열이 아닐 경우
 */
ISC_API ISC_STATUS gen_ECDSA_SIG_X509_TBS_CERT(X509_TBS_CERT* tbs, BIT_STRING** signature, OBJECT_IDENTIFIER *alg, ISC_ECDSA_UNIT* pri_params);
    
/*!
* \brief
* X509 인증서의 전자서명 절차를 처리하고 관련 정보를 x509 구조체에 입력함
* \param cert
* X509_CERT 구조체 포인터
* \param pkey
* 개인키 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# gen_RSA_SIG_X509_TBS_CERT() 의 결과
* -# gen_KCDSA_SIG_X509_TBS_CERT() 의 결과
*/
ISC_API ISC_STATUS gen_SIG_X509_Cert(X509_CERT* cert, ASYMMETRIC_KEY *pkey);


/*!
* \brief
* 인증서의 서명값을 검증함 (ISC_RSA)
* \param cert
* X509_CERT 구조체 포인터
* \param pub_params
* rsa 공개키
* \return
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_VERIFY_RSASIGN_TBS_CERT^ISC_ERR_NULL_INPUT : 입력이 NULL일 경우
* -# X509_TBS_CERT_to_Seq()의 에러 코드
* -# LOCATION^F_VERIFY_RSASIGN_TBS_CERT^ISC_ERR_INVALID_INPUT : 알고리즘 인식 불가
*/
ISC_API ISC_STATUS verify_RSA_SIG_X509_CERT(X509_CERT* cert, ISC_RSA_UNIT* pub_params);

/*!
* \brief
* 인증서의 서명값을 검증함 (ISC_KCDSA)
* \param cert
* X509_CERT 구조체 포인터
* \param pub_params
* kcdsa 공개키
* \return
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_VERIFY_KCDSASIGN_TBS_CERT^ISC_ERR_NULL_INPUT : 입력이 NULL일 경우
* -# X509_TBS_CERT_to_Seq() 의 결과
* -# LOCATION^F_VERIFY_KCDSASIGN_TBS_CERT^ISC_ERR_INVALID_INPUT : 알고리즘 인식 불가
*/
ISC_API ISC_STATUS verify_KCDSA_SIG_X509_CERT(X509_CERT* cert, ISC_KCDSA_UNIT* pub_params);

/*!
 * \brief
 * 인증서의 서명값을 검증함 (ISC_ECDSA)
 * \param cert
 * X509_CERT 구조체 포인터
 * \param pub_params
 * ecdsa 공개키
 * \return
 * -# ISC_SUCCESS : 성공
 * -# LOCATION^F_VERIFY_ECDSASIGN_TBS_CERT^ISC_ERR_NULL_INPUT : 입력이 NULL일 경우
 * -# X509_TBS_CERT_to_Seq() 의 결과
 * -# LOCATION^F_VERIFY_ECDSASIGN_TBS_CERT^ISC_ERR_INVALID_INPUT : 알고리즘 인식 불가
 */
ISC_API ISC_STATUS verify_ECDSA_SIG_X509_CERT(X509_CERT* cert, ISC_ECDSA_UNIT* pub_params);
    
/*!
* \brief
* 인증서의 서명값을 검증함
* \param cert
* X509_CERT 구조체 포인터
* \param pubKey
* 공개키
* \return
* -# ISC_SUCCESS : 성공
* -# verify_RSA_SIG_X509_CERT()의 에러 코드
* -# verify_KCDSA_SIG_X509_CERT()의 에러 코드
* -# LOCATION^F_VERIFY_KCDSASIGN_TBS_CERT^ISC_ERR_INVALID_INPUT : 알고리즘 인식 불가
*/
ISC_API ISC_STATUS verify_SIG_X509_CERT(X509_CERT* cert, X509_PUBKEY* pubKey);

/*!
* \brief
* 인증서의 유효기간을 검증함 (time을 NULL을 입력하면 현재시간이 기준)
* \param cert
* X509_CERT 구조체 포인터
* \param time
* time
* \return
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_VERIFY_X509_VALIDITY^ERR_CERT_NOT_BEFORE : 현재시간이 유효기간 이전
* -# LOCATION^F_VERIFY_X509_VALIDITY^ERR_CERT_NOT_AFTER : 현재 시간이 유효기간 이후
*/
/* time 인자가 NULL일 겨우 현재 시간과 비교 */
ISC_API ISC_STATUS verify_X509_validity(X509_CERT *cert, X509_TIME *time);


/*!
* \brief
* ASYMMETRIC_KEY 구조체의 초기화 함수
* \returns
* ASYMMETRIC_KEY 구조체 포인터
*/
ISC_API ASYMMETRIC_KEY* new_ASYMMETRIC_KEY();

/*!
* \brief
* ASYMMETRIC_KEY 구조체를 메모리 할당 해제
* \param akey
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_ASYMMETRIC_KEY(ASYMMETRIC_KEY* akey);

/*!
* \brief
* ASYMMETRIC_KEY 구조체를 복사
* \param src
* 복사할 구조체 포인터
* \return
* ASYMMETRIC_KEY 구조체 포인터
*/
ISC_API ASYMMETRIC_KEY* dup_ASYMMETRIC_KEY(ASYMMETRIC_KEY* src);

/*!
* \brief
* ASYMMETRIC_KEY 구조체를 비교
* \param a
* ASYMMETRIC_KEY 구조체 포인터
* \param b
* ASYMMETRIC_KEY 구조체 포인터
* \return
* -# 0 : 동일할 경우
* -# -1 : 같지 않을 경우
* -# ISC_FAIL : 실패
*/
ISC_API int cmp_ASYMMETRIC_KEY(ASYMMETRIC_KEY* a, ASYMMETRIC_KEY* b);

/*!
* \brief
* ASYMMETRIC_KEY 구조체에서 ISC_RSA_UNIT을 추출 (메모리가 duplicate 되므로 반드시 메모리 해지 필요)
* \param akey
* ASYMMETRIC_KEY 구조체 포인터
* \param rsa
* ISC_RSA 구조체 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS ASYMMETRIC_KEY_to_RSA_UNIT(ASYMMETRIC_KEY *akey, ISC_RSA_UNIT *rsa);

/*!
* \brief
* ASYMMETRIC_KEY 구조체에서 ISC_KCDSA_UNIT을 추출 (메모리가 duplicate 되므로 반드시 메모리 해지 필요)
* \param akey
* ASYMMETRIC_KEY 구조체 포인터
* \param kcdsa
* ISC_KCDSA_UNIT 구조체 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS ASYMMETRIC_KEY_to_KCDSA_UNIT(ASYMMETRIC_KEY *akey, ISC_KCDSA_UNIT *kcdsa);

/*!
 * \brief
 * ASYMMETRIC_KEY 구조체에서 ISC_ECDSA_UNIT을 추출 (메모리가 duplicate 되므로 반드시 메모리 해지 필요)
 * \param akey
 * ASYMMETRIC_KEY 구조체 포인터
 * \param ecdsa
 * ISC_ECDSA_UNIT 구조체 포인터
 * \return
 * -# ISC_SUCCESS : 성공
 * -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS ASYMMETRIC_KEY_to_ECDSA_UNIT(ASYMMETRIC_KEY *akey, ISC_ECDSA_UNIT *ecdsa);
    
/*!
* \brief
* ISC_RSA 키를 공개키 공용체인 ASYMMETRIC_KEY로 변환
* \param rsa
* ISC_RSA 키
* \param akey
* ASYMMETRIC_KEY 구조체 포인터 (메모리 할당 되어 있어야 함)
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS RSA_UNIT_to_ASYMMETRIC_KEY(ISC_RSA_UNIT *rsa, ASYMMETRIC_KEY *akey);

/*!
* \brief
* ISC_KCDSA 키를 공개키 공용체인 ASYMMETRIC_KEY로 변환
* \param kcdsa
* kcdsa 키
* \param akey
* ASYMMETRIC_KEY 구조체 포인터 (메모리 할당 되어 있어야 함)
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS KCDSA_UNIT_to_ASYMMETRIC_KEY(ISC_KCDSA_UNIT *kcdsa, ASYMMETRIC_KEY *akey);

/*!
 * \brief
 * ISC_ECDSA 키를 공개키 공용체인 ASYMMETRIC_KEY로 변환
 * \param ecdsa
 * ecdsa 키
 * \param akey
 * ASYMMETRIC_KEY 구조체 포인터 (메모리 할당 되어 있어야 함)
 * \return
 * -# ISC_SUCCESS : 성공
 * -# ISC_FAIL : 실패
 */
ISC_API ISC_STATUS ECDSA_UNIT_to_ASYMMETRIC_KEY(ISC_ECDSA_UNIT *ecdsa, ASYMMETRIC_KEY *akey);

/*!
 * \brief
 * ISC_ECC_KEY_UNIT 구조체를 공용체인 ASYMMETRIC_KEY로 변환
 * \param ec_key
 * ISC_ECC_KEY_UNIT 구조체
 * \param akey
 * ASYMMETRIC_KEY 구조체 포인터 (메모리 할당 되어 있어야 함)
 * \returns
 * -# ISC_SUCCESS : 성공
 * -# ISC_FAIL : 실패
 */
ISC_STATUS ECC_KEY_UNIT_to_ASYMMETRIC_KEY(ISC_ECC_KEY_UNIT *ec_key, ASYMMETRIC_KEY *akey);

/*!
* \brief
* 인증서의 공개키와 개인키의 키쌍 검증
* \param x509_pkey
* 공개키
* \param key
* ASYMMETRIC_KEY 구조체 포인터
* \return
* -# ISC_SUCCESS : 키페어 일치
* -# ISC_FAIL : 키페어 불일치
*/
ISC_API ISC_STATUS check_X509_keypair(X509_PUBKEY* x509_pkey, ASYMMETRIC_KEY* key);

/*!
* \brief
* 공개키와 비밀키의 키쌍 검증
* \param rsa1
* 키 1
* \param rsa2
* 키 2
* \return
* -# 1 : 키페어 일치
* -# ISC_FAIL : 키페어 불일치
*/
ISC_API ISC_STATUS check_X509_RSA_keypair(ISC_RSA_UNIT* rsa1, ISC_RSA_UNIT* rsa2);

/*!
* \brief
* 공개키와 비밀키의 키쌍 검증
* \param kcdsa1
* 키 1
* \param kcdsa2
* 키 2
* \return
* -# 1 : 키페어 일치
* -# ISC_FAIL : 키페어 불일치
*/
ISC_API ISC_STATUS check_X509_KCDSA_keypair(ISC_KCDSA_UNIT* kcdsa1, ISC_KCDSA_UNIT* kcdsa2);

/*!
 * \brief
 * 공개키와 비밀키의 키쌍 검증
 * \param ecdsa1
 * 키 1
 * \param ecdsa2
 * 키 2
 * \return
 * -# 1 : 키페어 일치
 * -# ISC_FAIL : 키페어 불일치
 */
ISC_API ISC_STATUS check_X509_ECDSA_keypair(ISC_ECDSA_UNIT* ecdsa1, ISC_ECDSA_UNIT* ecdsa2);

/*!
* \brief
* X509_EXTENSION 구조체의 초기화 함수
* \returns
* X509_EXTENSION 구조체 포인터
*/
ISC_API X509_EXTENSION* new_X509_EXTENSION();

/*!
* \brief
* X509_EXTENSION 구조체를 메모리 할당 해제
* \param ext
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_EXTENSION(X509_EXTENSION* ext);
/*!
* \brief
* X509_EXTENSION 구조체를 복사
* \param ext
* 복사할 구조체 포인터
* \return
* X509_EXTENSION 구조체 포인터
*/
ISC_API X509_EXTENSION* dup_X509_EXTENSION(X509_EXTENSION *ext);

/*!
* \brief
* X509_EXTENSIONS 구조체의 초기화 함수
* \returns
* X509_EXTENSIONS 구조체 포인터
*/
ISC_API X509_EXTENSIONS *new_X509_EXTENSIONS(void);

/*!
* \brief
* X509_EXTENSIONS 구조체를 메모리 할당 해제
* \param exts
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_EXTENSIONS(X509_EXTENSIONS *exts);

/*!
* \brief
* X509_EXTENSIONS가 담고 있는 X509_EXTENSION의 개수 반환
* \param exts
* X509_EXTENSIONS 구조체 포인터
* \return
* 개수
*/
ISC_API int get_X509_EXTENSION_count(const X509_EXTENSIONS *exts);

/*!
* \brief
* X509_EXTENSIONS구조체의 OBJECT_IDENTIFIER와 일치하는 인덱스를 lastpos부터 검색
* \param exts
* X509_EXTENSIONS 구조체 포인터
* \param *obj
* OBJECT_IDENTIFIER 구조체 포인터
* \param lastpos
* 인덱스 (default = -1)
* \return
* -# oid와 일치하는 인덱스
* -# oid와 일치하는 인덱스가 없을경우 -1
*/
ISC_API int get_X509_EXTENSION_index_by_OID(const X509_EXTENSIONS *exts, OBJECT_IDENTIFIER *obj, int lastpos);

/*!
* \brief
* X509_EXTENSIONS구조체의 oid_index와 일치하는 인덱스를 lastpos부터 검색
* \param exts
* X509_EXTENSIONS 구조체 포인터
* \param OID_index
* OID_index 값
* \param lastpos
* 인덱스 (default = -1)
* \return
* -# oid와 일치하는 인덱스
* -# oid와 일치하는 인덱스가 없을경우 -1
*/
ISC_API int get_X509_EXTENSION_index_by_OID_index(const X509_EXTENSIONS *exts, int OID_index, int lastpos);

/*!
* \brief
* X509_EXTENSIONS구조체의 loc에 위치한 X509_EXTENSION의 포인터 반환
* \param exts
* X509_EXTENSIONS 구조체 포인터
* \param loc
* 인덱스
* \return
* X509_EXTENSION 구조체 포인터
*/
ISC_API X509_EXTENSION *get_X509_EXTENSION(const X509_EXTENSIONS *exts, int loc);

/*!
* \brief
* X509_EXTENSIONS구조체의 loc에 위치한 X509_EXTENSION을 삭제
* \param exts
* X509_EXTENSIONS 구조체 포인터
* \param loc
* 인덱스
* \return
* 삭제된 X509_EXTENSION 구조체 포인터
*/
ISC_API X509_EXTENSION *remove_X509_EXTENSION(X509_EXTENSIONS *exts, int loc);

/*!
* \brief
* X509_EXTENSIONS구조체의 loc에 위치에 X509_EXTENSION을 삽입
* \param exts
* X509_EXTENSIONS 구조체 포인터
* \param ex
* X509_EXTENSION 구조체 포인터
* \param loc
* 인덱스
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_X509_EXTENSION(X509_EXTENSIONS **exts, X509_EXTENSION *ex, int loc);

/*!
* \brief
* X509_EXTENSION에 OID를 입력(dup)
* \param ex
* X509_EXTENSION 구조체 포인터
* \param obj
* OBJECT_IDENTIFIER 구조체 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_EXTENSION_object(X509_EXTENSION *ex, OBJECT_IDENTIFIER *obj);

/*!
* \brief
* X509_EXTENSION에 Critical 여부를 입력
* \param ex
* X509_EXTENSION 구조체 포인터
* \param crit
* critical : 0이 아닌 정수, non-critical : 0
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_EXTENSION_critical(X509_EXTENSION *ex, int crit);

/*!
* \brief
* X509_EXTENSION에 Value를 입력
* \param ex
* X509_EXTENSION 구조체 포인터
* \param data
* OCTET_STRING으로 Encoding 된 데이터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_EXTENSION_data(X509_EXTENSION *ex, OCTET_STRING *data);

/*!
* \brief
* X509_EXTENSION를 정해진 데이터 셋에 의해 생성
* \param ex
* X509_EXTENSION 포인터
* \param obj
* OBJECT_IDENTIFIER 구조체 포인터
* \param crit
* ciritical 여부
* \param data
* 저장될 데이터
* \return
* 생성된 X509_EXTENSION 구조체 포인터
*/
ISC_API X509_EXTENSION *create_X509_EXTENSION_by_OID(X509_EXTENSION **ex, OBJECT_IDENTIFIER *obj, int crit, OCTET_STRING *data);

/*!
* \brief
* X509_EXTENSION를 정해진 데이터 셋에 의해 생성
* \param ex
* X509_EXTENSION 포인터
* \param index
* OID_index(asn1_object.h)
* \param crit
* ciritical 여부
* \param data
* 저장될 데이터
* \return
* 생성된 X509_EXTENSION 구조체 포인터
*/
ISC_API X509_EXTENSION *create_X509_EXTENSION_by_OID_index(X509_EXTENSION **ex, int index,int crit, OCTET_STRING *data);

/*!
* \brief
* X509_EXTENSION가 가지는 OBJECT_IDENTIFIER 반환
* \param ex
* X509_EXTENSION 포인터
* \return
* OBJECT_IDENTIFIER 구조체 포인터
*/
ISC_API OBJECT_IDENTIFIER *get_X509_EXTENSION_object(X509_EXTENSION *ex);
/*!
* \brief
* X509_EXTENSION가 가지는 data 반환
* \param ex
* X509_EXTENSION 포인터
* \return
* OCTET_STRING 구조체 포인터
*/
ISC_API OCTET_STRING *get_X509_EXTENSION_data(X509_EXTENSION *ex);

/*!
* \brief
* X509_EXTENSION가 가지는 criticial 여부 반환
* \param ex
* X509_EXTENSION 포인터
* \return
* -# 1 : critical
* -# 0 : non-critical
*/
ISC_API int get_X509_EXTENSION_critical(X509_EXTENSION *ex);

/*!
* \brief
* X509_ATTRIBUTE_DATA 구조체의 초기화 함수
* \returns
* X509_ATTRIBUTE_DATA 구조체 포인터
*/
ISC_API X509_ATTRIBUTE_DATA *new_X509_ATTRIBUTE_DATA();

/*!
* \brief
* X509_ATTRIBUTE_DATA 구조체를 메모리 할당 해제
* \param attrData
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_ATTRIBUTE_DATA(X509_ATTRIBUTE_DATA *attrData);

/*!
* \brief
* X509_ATTRIBUTE_DATA 구조체를 복사
* \param attrData
* 복사할 구조체 포인터
* \return
* X509_ATTRIBUTE 구조체 포인터
*/
ISC_API X509_ATTRIBUTE_DATA* dup_X509_ATTRIBUTE_DATA(X509_ATTRIBUTE_DATA *attrData);

/*!
* \brief
* X509_ATTRIBUTE 구조체의 초기화 함수
* \returns
* X509_ATTRIBUTE 구조체 포인터
*/
ISC_API X509_ATTRIBUTE* new_X509_ATTRIBUTE();

/*!
* \brief
* X509_ATTRIBUTE 구조체를 메모리 할당 해제
* \param attribute
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_ATTRIBUTE(X509_ATTRIBUTE* attribute);

/*!
* \brief
* X509_ATTRIBUTE 구조체를 복사
* \param attribute
* 복사할 구조체 포인터
* \return
* X509_ATTRIBUTE 구조체 포인터
*/
ISC_API X509_ATTRIBUTE* dup_X509_ATTRIBUTE(X509_ATTRIBUTE *attribute);

/*!
* \brief
* X509_ATTRIBUTES 구조체의 초기화 함수
* \returns
* X509_ATTRIBUTES 구조체 포인터
*/
ISC_API X509_ATTRIBUTES* new_X509_ATTRIBUTES();

/*!
* \brief
* X509_ATTRIBUTES 구조체를 메모리 할당 해제
* \param atts
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_ATTRIBUTES(X509_ATTRIBUTES* atts);

/*!
* \brief
* X509_ATTRIBUTES 구조체를 복사
* \param src
* 복사할 구조체 포인터
* \return
* X509_ATTRIBUTES 구조체 포인터
*/
ISC_API X509_ATTRIBUTES * dup_X509_ATTRIBUTES(X509_ATTRIBUTES * src); 

/*!
* \brief
* X509_ATTRIBUTE에 OID를 지정
* 
* \param attr
* X509_ATTRIBUTE 구조체 포인터
* 
* \param obj
* OBJECT_IDENTIFIER 구조체 포인터
* 
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_ATTRIBUTE_OID(X509_ATTRIBUTE *attr, OBJECT_IDENTIFIER *obj);

/*!
* \brief
* X509_ATTRIBUTE에 데이터를 지정
* 
* \param attr
* X509_ATTRIBUTE 구조체 포인터
* 
* \param type
* 지정되는 데이터의 ASN1 타입
* \param data
* ASN1 타입 데이터(ASN1_UNIT or ASN1_STRING)
* \param len
* 데이터의 길이
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_X509_ATTRIBUTE_data(X509_ATTRIBUTE *attr, int type, void *data);

/*!
* \brief
* X509_ATTRIBUTE구조체 내의 set에 데이터를 추가
* \param attr
* X509_ATTRIBUTE 구조체 포인터
* \param data
* 데이터
* \param loc
* 저장될 위치 (default : -1)
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_X509_ATTRIBUTE_set(X509_ATTRIBUTE *attr, ASN1_STRING *data, int loc);


/*!
* \brief
* X509_ATTRIBUTE에 OID를 반환
* \param attr
* X509_ATTRIBUTE 구조체 포인터
* \returns
* OBJECT_IDENTIFIER 구조체 포인터
*/
ISC_API OBJECT_IDENTIFIER *get_X509_ATTRIBUTE_OID(X509_ATTRIBUTE *attr);

/*!
* \brief
* X509_ATTRIBUTE가 담고있는 idx번째 데이터 타입를 반환
* \param attr
* X509_ATTRIBUTE 구조체 포인터
* \param idx
* 인덱스
* \returns
* 반환 데이터
*/
ISC_API int get_X509_ATTRIBUTE_data_type(X509_ATTRIBUTE *attr, int idx);

/*!
* \brief
* X509_ATTRIBUTE가 담고있는 idx번째 데이터를 반환
* \param attr
* X509_ATTRIBUTE 구조체 포인터
* \param idx
* 인덱스
* \returns
* 반환 데이터
*/
ISC_API void *get_X509_ATTRIBUTE_data(X509_ATTRIBUTE *attr, int idx);

/*!
* \brief
* X509_ATTRIBUTE가 담고있는 데이터의 개수를 반환
* \param attr
* X509_ATTRIBUTE 구조체 포인터
* \returns
* 개수
*/
ISC_API int get_X509_ATTRIBUTE_count(X509_ATTRIBUTE *attr);

/*!
* \brief
* X509_ATTRIBUTES가 담고있는 X509_ATTRIBUTE 개수를 반환
* \param attr
* X509_ATTRIBUTES 구조체 포인터
* \returns
* 개수
*/
ISC_API int get_X509_ATTRIBUTES_count(X509_ATTRIBUTES *attr);

/*!
* \brief
* X509_ATTRIBUTES의 loc 번째의 X509_ATTRIBUTE 반환
* \param attr
* X509_ATTRIBUTES 구조체 포인터
* \param loc
* 인덱스
* \returns
* X509_ATTRIBUTE 구조체 포인터
*/
ISC_API X509_ATTRIBUTE *get_X509_ATTRIBUTES_child(X509_ATTRIBUTES *attr, int loc);



/*!
* \brief
* X509_ATTRIBUTE를 정해진 데이터 셋에 의해 생성
* \param attr
* X509_EXTENSION 포인터
* \param oid_index
* oid index
* \param type
* 저장되는 데이터의 asn1_type
* \param data
* 저장되는 asn1 구조체 데이터(ASN1_UNIT or ASN1_STRING)
* \return
* 생성된 X509_ATTRIBUTE 구조체 포인터
*/
ISC_API X509_ATTRIBUTE *create_X509_ATTRIBUTE_index(X509_ATTRIBUTE **attr, int oid_index, int type, void *data);

/*!
* \brief
* X509_ATTRIBUTE를 정해진 데이터 셋에 의해 생성
* \param attr
* X509_EXTENSION 포인터
* \param obj
* OBJECT_IDENTIFIER 구조체 포인터
* \param type
* 저장되는 데이터의 asn1_type
* \param data
* 저장되는 asn1 구조체 데이터(ASN1_UNIT or ASN1_STRING)
* \return
* 생성된 X509_ATTRIBUTE 구조체 포인터
*/
ISC_API X509_ATTRIBUTE *create_X509_ATTRIBUTE_OID(X509_ATTRIBUTE **attr, OBJECT_IDENTIFIER *obj, int type, void *data);


/*!
* \brief
* X509_ATTRIBUTES구조체에 X509_ATTRIBUTE를 삽입
* \param attrs
* X509_ATTRIBUTES 구조체 포인터
* \param attr
* 삽입될 X509_ATTRIBUTE 구조체 포인터
* \param loc
* 저장될 위치 (default : -1)
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_X509_ATTRIBUTES_child(X509_ATTRIBUTES *attrs, X509_ATTRIBUTE *attr, int loc);

/*!
* \brief
* X509_ATTRIBUTES구조체에 지정된 데이터로 X509_ATTRIBUTE를 생성하여 삽입
* \param attrs
* X509_ATTRIBUTES 구조체 포인터
* \param obj
* OBJECT_IDENTIFIER 구조체 포인터
* \param type
* 저장되는 데이터의 asn1 type
* \param data
* 저장되는 asn1 구조체 데이터(ASN1_UNIT or ASN1_STRING)
* \param loc
* 저장될 위치 (default : -1)
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_X509_ATTRIBUTES_child_OID(X509_ATTRIBUTES *attrs, OBJECT_IDENTIFIER *obj, int type, void *data, int loc);

/*!
* \brief
* X509_ATTRIBUTES구조체에 지정된 데이터로 X509_ATTRIBUTE를 생성하여 삽입
* \param attrs
* X509_ATTRIBUTES 구조체 포인터
* \param oid_ind
* oid 인덱스
* \param type
* 저장되는 데이터의 asn1 type
* \param data
* 저장되는 asn1 구조체 데이터(ASN1_UNIT or ASN1_STRING)
* \param loc
* 저장될 위치 (default : -1)
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_X509_ATTRIBUTES_OID_INDEX(X509_ATTRIBUTES *attrs, int oid_ind, int type, void *data, int loc);

/*!
* \brief
* X509_CERT 구조체를 Sequence로 Encode 함수
* \param st
* X509_CERT 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_X509_CERT_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_CERT_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_TBS_CERT_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS X509_CERT_to_Seq (X509_CERT *st, SEQUENCE **seq);

/*!
* \brief
* X509_TBS_CERT 구조체를 Sequence로 Encode 함수
* \param st
* X509_TBS_CERT 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_X509_TBS_CERT_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_TBS_CERT_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# LOCATION^F_X509_TBS_CERT_TO_SEQ^ERR_TBS_CERT_SERIAL : 시리얼 정보가 없음
* -# LOCATION^F_X509_TBS_CERT_TO_SEQ^ERR_TBS_CERT_SIGNATURE : 서명알고리즘 정보가 없음
* -# LOCATION^F_X509_TBS_CERT_TO_SEQ^ERR_TBS_CERT_ISSUER : 발급자 정보가 없음
* -# LOCATION^F_X509_TBS_CERT_TO_SEQ^ERR_TBS_CERT_VALIDITY : 우효기간 정보가 없음
* -# LOCATION^F_X509_TBS_CERT_TO_SEQ^ERR_TBS_CERT_SUBJECT : 주체자 정보가 없음
* -# LOCATION^F_X509_TBS_CERT_TO_SEQ^ERR_TBS_CERT_SPKI : 공개키 정보가 없음
* -# X509_PUBKEY_to_Seq()의 에러 코드\n
* -# X509_EXTENSIONS_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS X509_TBS_CERT_to_Seq (X509_TBS_CERT *st, SEQUENCE **seq);

/*!
* \brief
* X509_EXTENSIONS 구조체를 Sequence로 Encode 함수
* \param st
* X509_EXTENSIONS 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_X509_EXT_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_EXT_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_PUBKEY_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS X509_EXTENSIONS_to_Seq(X509_EXTENSIONS *st, SEQUENCE **seq);

/*!
* \brief
* X509_NAME 구조체를 Sequence로 Encode 함수
* \param st
* X509_NAME 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_X509_NAME_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_NAME_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS X509_NAME_to_Seq(X509_NAME *st, SEQUENCE **seq);

/*!
* \brief
* X509_PUBKEY 구조체를 Sequence로 Encode 함수
* \param st
* X509_PUBKEY 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_X509_PUBKEY_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_PUBKEY_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS X509_PUBKEY_to_Seq(X509_PUBKEY *st, SEQUENCE **seq);

/*!
* \brief
* X509_PUBKEY 구조체를 Sequence로 Encode 함수
* \param st
* X509_PUBKEY 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_X509_CERT_PAIR_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_CERT_PAIR_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_CERT_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS X509_CERT_PAIR_to_Seq(X509_CERT_PAIR* st, SEQUENCE** seq);


/*!
* \brief
* Sequence를 X509_CERT 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param st
* X509_CERT 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_X509_CERT^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_SEQ_TO_X509_CERT^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_TBS_CERT()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_X509_CERT (SEQUENCE *seq, X509_CERT** st);

/*!
* \brief
* Sequence를 X509_TBS_CERT 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param st
* X509_TBS_CERT 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_X509_TBS_CERT^ISC_ERR_NULL_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_TBS_CERT^ISC_ERR_INVALID_INPUT : Invalid Input
* -# LOCATION^F_SEQ_TO_X509_TBS_CERT^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_EXTENSIONS()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_X509_TBS_CERT (SEQUENCE *seq, X509_TBS_CERT** st);

/*!
* \brief
* Sequence를 X509_EXTENSIONS 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param st
* X509_EXTENSIONS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_X509_EXT^ISC_ERR_NULL_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_EXT^ISC_ERR_INVALID_INPUT : Invalid Input
* -# LOCATION^F_SEQ_TO_X509_EXT^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_EXTENSIONS()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_X509_EXTENSIONS(SEQUENCE *seq, X509_EXTENSIONS **st);

/*!
* \brief
* Sequence를 X509_NAME 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param st
* X509_NAME 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_X509_NAME^ISC_ERR_NULL_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_NAME^ISC_ERR_INVALID_INPUT : Invalid Input
* -# LOCATION^F_SEQ_TO_X509_NAME^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_X509_NAME(SEQUENCE *seq, X509_NAME **st);

/*!
* \brief
* Sequence를 X509_PUBKEY 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param st
* X509_PUBKEY 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_X509_PUBKEY^ISC_ERR_NULL_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_PUBKEY^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_X509_PUBKEY(SEQUENCE *seq, X509_PUBKEY **st);

/*!
* \brief
* Sequence를 X509_CERT_PAIR 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param st
* X509_CERT_PAIR 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_X509_CERT_PAIR^ISC_ERR_INVALID_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_CERT_PAIR^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_X509_CERT_PAIR(SEQUENCE* seq, X509_CERT_PAIR** st);

/*!
* \brief
* X509_CERTS 구조체의 초기화 함수
* \returns
* X509_CERTS 구조체 포인터
*/
ISC_API X509_CERTS *new_X509_CERTIFICATES();

/*!
* \brief
* X509_CERTS 구조체를 메모리 할당 해제
* \param x509Certificates
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_CERTIFICATES(X509_CERTS *x509Certificates);

/*!
* \brief
* X509_CERTS 스택에서 X509_CERT와 일치하는 인덱스를 검색
* \param x509Certificates
* X509_CERTS 스택 포인터
* \param cert
* X509_CERT 구조체 포인터
* \return
* -# cert와 일치하는 인덱스
* -# cert와 일치하는 인덱스가 없을경우 -1
*/
ISC_API int get_X509_CERTS_index_by_X509_CERT(X509_CERTS *x509Certificates, X509_CERT *cert);

/*!
* \brief
* X509_CERTS 구조체를 Sequence로 Encode 함수
* \param st
* X509_CERTS 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_X509_CERTIFICATES_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_CERTIFICATES_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_CERT_to_Seq()의 에러 코드
*/
ISC_API ISC_STATUS X509_CERTIFICATES_to_Seq(X509_CERTS *st, SEQUENCE **seq);

/*!
* \brief
* Sequence를 X509_CERTS 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param st
* X509_CERTS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_X509_CERTIFICATES^ISC_ERR_INVALID_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_CERTIFICATES^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_CERT()의 에러 코드
*/
ISC_API ISC_STATUS Seq_to_X509_CERTIFICATES(SEQUENCE *seq, X509_CERTS **st);

/*!
* \brief
* X509_CERTS 스택에 X509_CERT를 추가
* \param certs
* X509_CERTS 스택 포인터
* \param cert
* 추가될 X509_CERT 구조체 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_X509_CERTIFICATES(X509_CERTS *certs, X509_CERT *cert);

/*!
* \brief
* X509_CERTS 내의 모든 인증서의 정보를 출력
* \param certs
* X509_CERTS 구조체
*/
ISC_API void print_X509_CERTIFICATES(X509_CERTS *certs);

/*!
* \brief
* Sequence를 X509_ATTRIBUTE 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param st
* X509_ATTRIBUTE 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_X509_ATTRIBUTE^ISC_ERR_INVALID_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_ATTRIBUTE^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_X509_ATTRIBUTE(SEQUENCE *seq, X509_ATTRIBUTE **st);

/*!
* \brief
* Sequence를 X509_ATTRIBUTES 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param st
* X509_ATTRIBUTES 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_X509_ATTRIBUTES^ISC_ERR_INVALID_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_ATTRIBUTES^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_X509_ATTRIBUTES(SEQUENCE *seq, X509_ATTRIBUTES **st);

/*!
* \brief
* X509_ATTRIBUTE 구조체를 Sequence로 Encode 함수
* \param st
* X509_ATTRIBUTE 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_X509_ATTRIBUTE_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_ATTRIBUTE_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_CERT_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS X509_ATTRIBUTE_to_Seq(X509_ATTRIBUTE *st, SEQUENCE **seq);

/*!
* \brief
* X509_ATTRIBUTES 구조체를 Sequence로 Encode 함수
* \param st
* X509_ATTRIBUTES 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_X509_ATTRIBUTES_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_ATTRIBUTES_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_ATTRIBUTE_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS X509_ATTRIBUTES_to_Seq(X509_ATTRIBUTES *st, SEQUENCE **seq);



/*!
* \brief
* ISC_RSA_UNIT 구조체를 BitString 타입으로 Encode 함수
* \param st
* ISC_RSA_UNIT 구조체
* \param bit_string
* BIT_STRING 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_RSA_KEY_to_BITSTRING^ISC_ERR_INVALID_INPUT : 잘못된 키 정보
* -# LOCATION^F_RSA_KEY_to_BITSTRING^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS RSA_KEY_to_BITSTRING(ISC_RSA_UNIT *st, BIT_STRING **bit_string);

/*!
* \brief
* ISC_KCDSA_UNIT 구조체를 BitString 타입으로 Encode 함수
* \param st
* ISC_KCDSA_UNIT 구조체
* \param bit_string
* BIT_STRING 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_KCDSA_KEY_to_BITSTRING^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS KCDSA_KEY_to_BITSTRING(ISC_KCDSA_UNIT *st, BIT_STRING **bit_string);

/*!
* \brief
* BIT_STRING를 ISC_RSA_UNIT 구조체로 Decode 함수
* \param bit_string
* Decoding BIT_STRING 구조체
* \param st
* ISC_RSA_UNIT 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_BITSTRING_to_RSA_KEY^ERR_ASN1_DECODING : ASN1 Err
* -# LOCATION^F_BITSTRING_to_RSA_KEY^ISC_ERR_INVALID_INPUT : Invalid Input
*/
ISC_API ISC_STATUS BITSTRING_to_RSA_KEY(BIT_STRING *bit_string, ISC_RSA_UNIT **st);


/*!
* \brief
* BIT_STRING를 ISC_KCDSA_UNIT 구조체로 Decode 함수
* \param bit_string
* Decoding BIT_STRING 구조체
* \param st
* ISC_KCDSA_UNIT 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_BITSTRING_to_KCDSA_KEY^ERR_ASN1_DECODING : ASN1 Err
* -# LOCATION^F_BITSTRING_to_KCDSA_KEY^ISC_ERR_INVALID_INPUT : Invalid Input
*/
ISC_API ISC_STATUS BITSTRING_to_KCDSA_KEY(BIT_STRING *bit_string, ISC_KCDSA_UNIT **st);

/*!
* \brief
* ISC_RSA_UNIT 구조체를 Sequence로 Encode 함수
* \param st
* ISC_RSA_UNIT 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_RSA_KEY_to_Seq^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_RSA_KEY_to_Seq^ERR_ASN1_ENCODING : ASN1 Err
* -# RSA_KEY_to_BITSTRING()의 에러 코드\n
*/
ISC_API ISC_STATUS RSA_KEY_to_Seq(ISC_RSA_UNIT *st, SEQUENCE **seq);

/*!
* \brief
* Sequence를 ISC_RSA_UNIT 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param st
* ISC_RSA_UNIT 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_Seq_to_RSA_KEY^ISC_ERR_INVALID_INPUT : Null Input
* -# LOCATION^F_Seq_to_RSA_KEY^ERR_ASN1_DECODING : ASN1 Err
* -# BITSTRING_to_RSA_KEY()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_RSA_KEY(SEQUENCE *seq, ISC_RSA_UNIT **st);

/*!
* \brief
* ISC_KCDSA_UNIT 구조체를 Sequence로 Encode 함수
* \param st
* ISC_KCDSA_UNIT 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_KCDSA_KEY_to_Seq^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_KCDSA_KEY_to_Seq^ERR_ASN1_ENCODING : ASN1 Err
* -# KCDSA_KEY_to_BITSTRING()의 에러 코드\n
*/
ISC_API ISC_STATUS KCDSA_KEY_to_Seq(ISC_KCDSA_UNIT *st, SEQUENCE **seq);

/*!
* \brief
* Sequence를 ISC_KCDSA_UNIT 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param st
* ISC_KCDSA_UNIT 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_Seq_to_KCDSA_KEY^ISC_ERR_INVALID_INPUT : Null Input
* -# LOCATION^F_Seq_to_KCDSA_KEY^ERR_ASN1_DECODING : ASN1 Err
* -# BITSTRING_to_KCDSA_KEY()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_KCDSA_KEY(SEQUENCE *seq, ISC_KCDSA_UNIT **st);



/*!
* \brief
* X509_ALGO_IDENTIFIER 구조체의 초기화 함수
* \returns
* X509_ALGO_IDENTIFIER 구조체 포인터
*/
ISC_API X509_ALGO_IDENTIFIER *new_X509_ALGO_IDENTIFIER();
 
/*!
* \brief
* X509_ALGO_IDENTIFIER 구조체를 메모리 할당 해제
* \param x509Algo
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_ALGO_IDENTIFIER(X509_ALGO_IDENTIFIER* x509Algo);

/*!
* \brief
* X509_ALGO_IDENTIFIER 구조체를 복사
* \param src
* 복사할 구조체 포인터
* \return
* X509_ALGO_IDENTIFIER 구조체 포인터
*/
ISC_API X509_ALGO_IDENTIFIER* dup_X509_ALGO_IDENTIFIER(X509_ALGO_IDENTIFIER* src);


/* algID는 null이면 fail, params은 NULL이면 NULL Type이 세팅됨 */
/*!
* \brief
* X509_ALGO_IDENTIFIER 구조체에 OBJECT_IDENTIFIER와 알고리즘 Parameter를 입력(Null Parameter일 경우 NULL을 입력)
* \param x509Algo
* X509 알고리즘 Identifier
* \param alg_id
* 알고리즘 Identifier
* \param params
* 알고리즘 Parameter
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_ALGO_IDENTIFIER_value(X509_ALGO_IDENTIFIER* x509Algo, OBJECT_IDENTIFIER* alg_id, ASN1_STRING* params);

/*!
* \brief
* X509_ALGO_IDENTIFIERS 구조체의 초기화 함수
* \returns
* X509_ALGO_IDENTIFIERS 구조체 포인터
*/
ISC_API X509_ALGO_IDENTIFIERS *new_X509_ALGO_IDENTIFIERS();

/*!
* \brief
* X509_ALGO_IDENTIFIERS 구조체를 메모리 할당 해제
* \param x509Algos
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_ALGO_IDENTIFIERS(X509_ALGO_IDENTIFIERS *x509Algos);

/*!
* \brief
* X509_ALGO_IDENTIFIERS 구조체를 복사
* \param src
* 복사할 구조체 포인터
* \return
* X509_ALGO_IDENTIFIERS 구조체 포인터
*/
ISC_API X509_ALGO_IDENTIFIERS *dup_X509_ALGO_IDENTIFIERS(X509_ALGO_IDENTIFIERS* src);

/*!
* \brief
* X509_ALGO_IDENTIFIER 구조체를 Sequence로 Encode 함수
* \param st
* X509_ALGO_IDENTIFIER 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_X509_ALGO_IDENTIFIER_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_ALGO_IDENTIFIER_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_CERT_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS X509_ALGO_IDENTIFIER_to_Seq(X509_ALGO_IDENTIFIER *st, SEQUENCE **seq);

/*!
* \brief
* Sequence를 X509_ALGO_IDENTIFIER 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param st
* X509_ALGO_IDENTIFIER 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_X509_ALGO_IDENTIFIER^ISC_ERR_INVALID_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_ALGO_IDENTIFIER^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_X509_ALGO_IDENTIFIER(SEQUENCE *seq, X509_ALGO_IDENTIFIER **st);

/*!
* \brief
* X509_ALGO_IDENTIFIERS 구조체를 Sequence로 Encode 함수
* \param st
* X509_ALGO_IDENTIFIERS 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_X509_ALGO_IDENTIFIERS_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_ALGO_IDENTIFIERS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_CERT_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS X509_ALGO_IDENTIFIERS_to_Seq(X509_ALGO_IDENTIFIERS *st, SET_OF **seq);

/*!
* \brief
* Sequence를 X509_ALGO_IDENTIFIERS 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param st
* X509_ALGO_IDENTIFIERS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_X509_ALGO_IDENTIFIERS^ISC_ERR_INVALID_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_ALGO_IDENTIFIERS^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_X509_ALGO_IDENTIFIERS(SET_OF *seq, X509_ALGO_IDENTIFIERS **st);


/* PKCS12 전용 함수 */
ISC_API X509_AUX *new_X509_AUX();
ISC_API void free_X509_AUX(X509_AUX* x509aux);
ISC_API X509_AUX* dup_X509_AUX(X509_AUX* src);
ISC_API ISC_STATUS set_X509_AUX_localkey (X509_CERT* x509, uint8 *keyid, int keyidLen);
ISC_API uint8 * get_X509_AUX_localkey (X509_CERT *x509, int *len);
ISC_API ISC_STATUS set_X509_AUX_friendly (X509_CERT* x509, uint8 *friendly, int friendlyLen);
ISC_API uint8 * get_X509_AUX_friendly (X509_CERT *x509, int *len);



/*!
* \brief
* 인증서의 해쉬값(손도장)을 구하는 함수
* \param cert
* X509_CERT 구조체
* \param alg_id
* 해쉬 알고리즘 (ISC_SHA1 or ISC_MD5, ISC_HAS160, ..)
* \param md
* 반환되는 해쉬값 (외부 할당 필요)
* \param len
* 반화되는 해쉬값을 길이
* \return
* -# ISC_SUCCESS : 성공\n
* -# X509_CERT_to_Seq의 에러코드\n
* -# ISC_DIGEST의 에러코드
*/
ISC_API ISC_STATUS X509_CERT_digest(const X509_CERT *cert, const int alg_id, uint8 *md, int *len);

/*!
* \brief
* X509_CERT 구조체를 복사
* \param src
* 복사할 구조체 포인터
* \return
* X509_CERT 구조체 포인터
*/
ISC_API X509_CERT * dup_X509_CERT(X509_CERT * src);

/*!
* \brief
* X509_EXTENSIONS 구조체를 복사
* \param src
* 복사할 구조체 포인터
* \return
* X509_EXTENSIONS 구조체 포인터
*/
ISC_API X509_EXTENSIONS * dup_X509_EXTENSIONS(X509_EXTENSIONS * src);

/*!
* \brief
* X509_CERT 인증서의 정보를 출력
* \param cert
* X509_CERT 구조체
*/
ISC_API void print_X509(X509_CERT *cert);

/*!
* \brief
* X509_PUBKEY를 복사하는 기능
* \param 복사할 원본 X509_PUBKEY* pkey
* \return 복사된 X509_PUBKEY* 
*/
ISC_API X509_PUBKEY* dup_X509_PUBKEY(X509_PUBKEY* pkey);

/*!
* \brief
* X509_PUBKEY 구조체를 비교
* \param a
* X509_PUBKEY 구조체 포인터
* \param b
* X509_PUBKEY 구조체 포인터
* \return
* -# 0 : 동일할 경우
* -# -1 : 같지 않을 경우
* -# ISC_FAIL : 실패
*/
ISC_API int cmp_X509_PUBKEY(X509_PUBKEY* a, X509_PUBKEY* b);

/*!
* \brief
* X509_SIGN 구조체의 초기화 함수
* \returns
* X509_SIGN 구조체 포인터
*/
ISC_API X509_SIGN* new_X509_SIGN();

/*!
* \brief
* X509_SIGN 구조체를 메모리 할당 해제
* \param sign
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_X509_SIGN(X509_SIGN* sign);



#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(X509_CERT*, new_X509_CERT, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_CERT, (X509_CERT *cert), (cert) );
INI_VOID_LOADLIB_PKI(void, clean_X509_CERT, (X509_CERT *cert), (cert) );
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_version, (X509_CERT *cert, uint8 version), (cert,version), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_serial, (X509_CERT *cert, INTEGER *serialnumber), (cert,serialnumber), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_signature, (X509_CERT *cert, OBJECT_IDENTIFIER *oid), (cert,oid), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_issuer, (X509_CERT *cert, X509_NAME *name), (cert,name), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_subject, (X509_CERT *cert, X509_NAME *name), (cert,name), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_notBefore, (X509_CERT *cert, X509_TIME *notBefore), (cert,notBefore), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_notAfter, (X509_CERT *cert, X509_TIME *notAfter), (cert,notAfter), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_pub_key, (X509_CERT *cert, X509_PUBKEY *key), (cert,key), ISC_FAIL);
INI_RET_LOADLIB_PKI(uint8, get_X509_version, (X509_CERT *cert), (cert), ISC_FAIL);
INI_RET_LOADLIB_PKI(INTEGER*, get_X509_serial, (X509_CERT *cert), (cert), NULL);
INI_RET_LOADLIB_PKI(OBJECT_IDENTIFIER*, get_X509_signature, (X509_CERT *cert), (cert), NULL);
INI_RET_LOADLIB_PKI(X509_NAME*, get_X509_issuer, (X509_CERT *cert), (cert), NULL);
INI_RET_LOADLIB_PKI(X509_NAME*, get_X509_subject, (X509_CERT *cert), (cert), NULL);
INI_RET_LOADLIB_PKI(X509_TIME*, get_X509_notAfter, (X509_CERT *cert), (cert), NULL);
INI_RET_LOADLIB_PKI(X509_TIME*, get_X509_notBefore, (X509_CERT *cert), (cert), NULL);
INI_RET_LOADLIB_PKI(X509_PUBKEY*, get_X509_SPKI, (X509_CERT *cert), (cert), NULL);
INI_RET_LOADLIB_PKI(OBJECT_IDENTIFIER*, get_X509_sig_alg, (X509_CERT *cert), (cert), NULL);
INI_RET_LOADLIB_PKI(BIT_STRING*, get_X509_sig_value, (X509_CERT *cert), (cert), NULL);
INI_RET_LOADLIB_PKI(X509_CERT_PAIR*, new_X509_CERT_PAIR, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_CERT_PAIR, (X509_CERT_PAIR* x509_certPair), (x509_certPair) );
INI_RET_LOADLIB_PKI(X509_TIME*, new_X509_TIME, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_TIME, (X509_TIME *name), (name) );
INI_RET_LOADLIB_PKI(ISC_STATUS, copy_X509_TIME, (X509_TIME *from, X509_TIME *to), (from,to), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_NAME*, new_X509_NAME, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_NAME, (X509_NAME* name), (name) );
INI_RET_LOADLIB_PKI(X509_NAME_CHILD*, new_X509_NAME_CHILD, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_NAME_CHILD, (X509_NAME_CHILD* name), (name) );
INI_RET_LOADLIB_PKI(X509_NAME_CHILD*, dup_X509_NAME_CHILD, (X509_NAME_CHILD* name), (name), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_X509_NAME_child, (X509_NAME *name, X509_NAME_CHILD *child, int loc), (name,child,loc), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_X509_NAME_child_OID_index, (X509_NAME *name, int index, int type, uint8 *bytes, int len, int loc), (name,index,type,bytes,len,loc), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_X509_NAME_child_OID, (X509_NAME *name, OBJECT_IDENTIFIER *oid, int type, uint8 *bytes, int len, int loc), (name,oid,type,bytes,len,loc), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_NAME_CHILD*, remove_X509_NAME_child, (X509_NAME *name, int loc), (name,loc), NULL);
INI_RET_LOADLIB_PKI(int, get_X509_NAME_count, (X509_NAME *name), (name), ISC_FAIL);
INI_RET_LOADLIB_PKI(ASN1_STRING*, get_X509_NAME_CHILD_data, (X509_NAME_CHILD *child), (child), NULL);
INI_RET_LOADLIB_PKI(OBJECT_IDENTIFIER*, get_X509_NAME_CHILD_OID, (X509_NAME_CHILD *child), (child), NULL);
INI_RET_LOADLIB_PKI(X509_NAME_CHILD*, get_X509_NAME_CHILD, (X509_NAME *name, int loc), (name,loc), NULL);
INI_RET_LOADLIB_PKI(int, get_X509_NAME_index_by_OID, (X509_NAME *name, OBJECT_IDENTIFIER *oid,int lastpos), (name,oid,lastpos), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_NAME*, dup_X509_NAME, (X509_NAME * src), (src), NULL);
INI_RET_LOADLIB_PKI(int, cmp_X509_NAME, (X509_NAME *n1, X509_NAME *n2), (n1,n2), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_X509_NAME_hash, (X509_NAME *name,int digest_id, uint8* md), (name,digest_id,md), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_PUBKEY*, new_X509_PUBKEY, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_PUBKEY, (X509_PUBKEY* pkey), (pkey) );
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_PUBKEY_rsa, (X509_PUBKEY* pkey, ISC_RSA_UNIT* rsa), (pkey,rsa), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_PUBKEY_kcdsa, (X509_PUBKEY* pkey, ISC_KCDSA_UNIT* kcdsa), (pkey,kcdsa), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_X509_PUBLIC_KEY_hash, (X509_CERT *cert,int digest_id, uint8* md), (cert,digest_id,md), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, gen_RSA_SIG_X509_TBS_CERT, (X509_TBS_CERT* tbs, BIT_STRING** sig_value, OBJECT_IDENTIFIER *alg, ISC_RSA_UNIT* pri_params), (tbs,sig_value,alg,pri_params), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, gen_KCDSA_SIG_X509_TBS_CERT, (X509_TBS_CERT* tbs, BIT_STRING** signature, OBJECT_IDENTIFIER *alg, ISC_KCDSA_UNIT* pri_params), (tbs,signature,alg,pri_params), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, gen_SIG_X509_Cert, (X509_CERT* cert, ASYMMETRIC_KEY *pkey), (cert,pkey), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, verify_RSA_SIG_X509_CERT, (X509_CERT* cert, ISC_RSA_UNIT* pub_params), (cert,pub_params), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, verify_KCDSA_SIG_X509_CERT, (X509_CERT* cert, ISC_KCDSA_UNIT* pub_params), (cert,pub_params), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, verify_SIG_X509_CERT, (X509_CERT* cert, X509_PUBKEY* pubKey), (cert,pubKey), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, verify_X509_validity, (X509_CERT *cert, X509_TIME *time), (cert,time), ISC_FAIL);
INI_RET_LOADLIB_PKI(ASYMMETRIC_KEY*, new_ASYMMETRIC_KEY, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_ASYMMETRIC_KEY, (ASYMMETRIC_KEY* akey), (akey) );
INI_RET_LOADLIB_PKI(ASYMMETRIC_KEY*, dup_ASYMMETRIC_KEY, (ASYMMETRIC_KEY* src), (src), NULL);
INI_RET_LOADLIB_PKI(int, cmp_ASYMMETRIC_KEY, (ASYMMETRIC_KEY* a, ASYMMETRIC_KEY* b), (a,b), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, ASYMMETRIC_KEY_to_RSA_UNIT, (ASYMMETRIC_KEY *akey, ISC_RSA_UNIT *rsa), (akey,rsa), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, ASYMMETRIC_KEY_to_KCDSA_UNIT, (ASYMMETRIC_KEY *akey, ISC_KCDSA_UNIT *kcdsa), (akey,kcdsa), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, RSA_UNIT_to_ASYMMETRIC_KEY, (ISC_RSA_UNIT *rsa, ASYMMETRIC_KEY *akey), (rsa,akey), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, KCDSA_UNIT_to_ASYMMETRIC_KEY, (ISC_KCDSA_UNIT *kcdsa, ASYMMETRIC_KEY *akey), (kcdsa,akey), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, check_X509_keypair, (X509_PUBKEY* x509_pkey, ASYMMETRIC_KEY* key), (x509_pkey,key), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, check_X509_RSA_keypair, (ISC_RSA_UNIT* rsa1, ISC_RSA_UNIT* rsa2), (rsa1,rsa2), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, check_X509_KCDSA_keypair, (ISC_KCDSA_UNIT* kcdsa1, ISC_KCDSA_UNIT* kcdsa2), (kcdsa1,kcdsa2), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_EXTENSION*, new_X509_EXTENSION, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_EXTENSION, (X509_EXTENSION* ext), (ext) );
INI_RET_LOADLIB_PKI(X509_EXTENSION*, dup_X509_EXTENSION, (X509_EXTENSION *ext), (ext), NULL);
INI_RET_LOADLIB_PKI(X509_EXTENSIONS*, new_X509_EXTENSIONS, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_EXTENSIONS, (X509_EXTENSIONS *exts), (exts) );
INI_RET_LOADLIB_PKI(int, get_X509_EXTENSION_count, (const X509_EXTENSIONS *exts), (exts), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_X509_EXTENSION_index_by_OID, (const X509_EXTENSIONS *exts, OBJECT_IDENTIFIER *obj, int lastpos), (exts,obj,lastpos), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_X509_EXTENSION_index_by_OID_index, (const X509_EXTENSIONS *exts, int OID_index, int lastpos), (exts,OID_index,lastpos), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_EXTENSION*, get_X509_EXTENSION, (const X509_EXTENSIONS *exts, int loc), (exts,loc), NULL);
INI_RET_LOADLIB_PKI(X509_EXTENSION*, remove_X509_EXTENSION, (X509_EXTENSIONS *exts, int loc), (exts,loc), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_X509_EXTENSION, (X509_EXTENSIONS **exts, X509_EXTENSION *ex, int loc), (exts,ex,loc), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_EXTENSION_object, (X509_EXTENSION *ex, OBJECT_IDENTIFIER *obj), (ex,obj), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_EXTENSION_critical, (X509_EXTENSION *ex, int crit), (ex,crit), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_EXTENSION_data, (X509_EXTENSION *ex, OCTET_STRING *data), (ex,data), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_EXTENSION*, create_X509_EXTENSION_by_OID, (X509_EXTENSION **ex, OBJECT_IDENTIFIER *obj, int crit, OCTET_STRING *data), (ex,obj,crit,data), NULL);
INI_RET_LOADLIB_PKI(X509_EXTENSION*, create_X509_EXTENSION_by_OID_index, (X509_EXTENSION **ex, int index,int crit, OCTET_STRING *data), (ex,index,crit,data), NULL);
INI_RET_LOADLIB_PKI(OBJECT_IDENTIFIER*, get_X509_EXTENSION_object, (X509_EXTENSION *ex), (ex), NULL);
INI_RET_LOADLIB_PKI(OCTET_STRING*, get_X509_EXTENSION_data, (X509_EXTENSION *ex), (ex), NULL);
INI_RET_LOADLIB_PKI(int, get_X509_EXTENSION_critical, (X509_EXTENSION *ex), (ex), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_ATTRIBUTE_DATA*, new_X509_ATTRIBUTE_DATA, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_ATTRIBUTE_DATA, (X509_ATTRIBUTE_DATA *attrData), (attrData) );
INI_RET_LOADLIB_PKI(X509_ATTRIBUTE_DATA*, dup_X509_ATTRIBUTE_DATA, (X509_ATTRIBUTE_DATA *attrData), (attrData), NULL);
INI_RET_LOADLIB_PKI(X509_ATTRIBUTE*, new_X509_ATTRIBUTE, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_ATTRIBUTE, (X509_ATTRIBUTE* attribute), (attribute) );
INI_RET_LOADLIB_PKI(X509_ATTRIBUTE*, dup_X509_ATTRIBUTE, (X509_ATTRIBUTE *attribute), (attribute), NULL);
INI_RET_LOADLIB_PKI(X509_ATTRIBUTES*, new_X509_ATTRIBUTES, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_ATTRIBUTES, (X509_ATTRIBUTES* atts), (atts) );
INI_RET_LOADLIB_PKI(X509_ATTRIBUTES*, dup_X509_ATTRIBUTES, (X509_ATTRIBUTES * src), (src), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_ATTRIBUTE_OID, (X509_ATTRIBUTE *attr, OBJECT_IDENTIFIER *obj), (attr,obj), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_X509_ATTRIBUTE_data, (X509_ATTRIBUTE *attr, int type, void *data), (attr,type,data), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_X509_ATTRIBUTE_set, (X509_ATTRIBUTE *attr, ASN1_STRING *data, int loc), (attr,data,loc), ISC_FAIL);
INI_RET_LOADLIB_PKI(OBJECT_IDENTIFIER*, get_X509_ATTRIBUTE_OID, (X509_ATTRIBUTE *attr), (attr), NULL);
INI_RET_LOADLIB_PKI(int, get_X509_ATTRIBUTE_data_type, (X509_ATTRIBUTE *attr, int idx), (attr,idx), ISC_FAIL);
INI_RET_LOADLIB_PKI(void*, get_X509_ATTRIBUTE_data, (X509_ATTRIBUTE *attr, int idx), (attr,idx), NULL);
INI_RET_LOADLIB_PKI(int, get_X509_ATTRIBUTE_count, (X509_ATTRIBUTE *attr), (attr), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_X509_ATTRIBUTES_count, (X509_ATTRIBUTES *attr), (attr), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_ATTRIBUTE*, get_X509_ATTRIBUTES_child, (X509_ATTRIBUTES *attr, int loc), (attr,loc), NULL);
INI_RET_LOADLIB_PKI(X509_ATTRIBUTE*, create_X509_ATTRIBUTE_index, (X509_ATTRIBUTE **attr, int oid_index, int type, void *data), (attr,oid_index,type,data), NULL);
INI_RET_LOADLIB_PKI(X509_ATTRIBUTE*, create_X509_ATTRIBUTE_OID, (X509_ATTRIBUTE **attr, OBJECT_IDENTIFIER *obj, int type, void *data), (attr,obj,type,data), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_X509_ATTRIBUTES_child, (X509_ATTRIBUTES *attrs, X509_ATTRIBUTE *attr, int loc), (attrs,attr,loc), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_X509_ATTRIBUTES_child_OID, (X509_ATTRIBUTES *attrs, OBJECT_IDENTIFIER *obj, int type, void *data, int loc), (attrs,obj,type,data,loc), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_X509_ATTRIBUTES_OID_INDEX, (X509_ATTRIBUTES *attrs, int oid_ind, int type, void *data, int loc), (attrs,oid_ind,type,data,loc), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, X509_CERT_to_Seq, (X509_CERT *st, SEQUENCE **seq), (st,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, X509_TBS_CERT_to_Seq, (X509_TBS_CERT *st, SEQUENCE **seq), (st,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, X509_EXTENSIONS_to_Seq, (X509_EXTENSIONS *st, SEQUENCE **seq), (st,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, X509_NAME_to_Seq, (X509_NAME *st, SEQUENCE **seq), (st,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, X509_PUBKEY_to_Seq, (X509_PUBKEY *st, SEQUENCE **seq), (st,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, X509_CERT_PAIR_to_Seq, (X509_CERT_PAIR* st, SEQUENCE** seq), (st,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_X509_CERT, (SEQUENCE *seq, X509_CERT** st), (seq,st), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_X509_TBS_CERT, (SEQUENCE *seq, X509_TBS_CERT** st), (seq,st), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_X509_EXTENSIONS, (SEQUENCE *seq, X509_EXTENSIONS **st), (seq,st), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_X509_NAME, (SEQUENCE *seq, X509_NAME **st), (seq,st), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_X509_PUBKEY, (SEQUENCE *seq, X509_PUBKEY **st), (seq,st), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_X509_CERT_PAIR, (SEQUENCE* seq, X509_CERT_PAIR** st), (seq,st), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_CERTS*, new_X509_CERTIFICATES, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_CERTIFICATES, (X509_CERTS *x509Certificates), (x509Certificates) );
INI_RET_LOADLIB_PKI(int, get_X509_CERTS_index_by_X509_CERT, (X509_CERTS *x509Certificates, X509_CERT *cert), (x509Certificates,cert), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, X509_CERTIFICATES_to_Seq, (X509_CERTS *st, SEQUENCE **seq), (st,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_X509_CERTIFICATES, (SEQUENCE *seq, X509_CERTS **st), (seq,st), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_X509_CERTIFICATES, (X509_CERTS *certs, X509_CERT *cert), (certs,cert), ISC_FAIL);
INI_VOID_LOADLIB_PKI(void, print_X509_CERTIFICATES, (X509_CERTS *certs), (certs) );
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_X509_ATTRIBUTE, (SEQUENCE *seq, X509_ATTRIBUTE **st), (seq,st), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_X509_ATTRIBUTES, (SEQUENCE *seq, X509_ATTRIBUTES **st), (seq,st), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, X509_ATTRIBUTE_to_Seq, (X509_ATTRIBUTE *st, SEQUENCE **seq), (st,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, X509_ATTRIBUTES_to_Seq, (X509_ATTRIBUTES *st, SEQUENCE **seq), (st,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, RSA_KEY_to_BITSTRING, (ISC_RSA_UNIT *st, BIT_STRING **bit_string), (st,bit_string), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, KCDSA_KEY_to_BITSTRING, (ISC_KCDSA_UNIT *st, BIT_STRING **bit_string), (st,bit_string), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, BITSTRING_to_RSA_KEY, (BIT_STRING *bit_string, ISC_RSA_UNIT **st), (bit_string,st), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, BITSTRING_to_KCDSA_KEY, (BIT_STRING *bit_string, ISC_KCDSA_UNIT **st), (bit_string,st), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, RSA_KEY_to_Seq, (ISC_RSA_UNIT *st, SEQUENCE **seq), (st,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_RSA_KEY, (SEQUENCE *seq, ISC_RSA_UNIT **st), (seq,st), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, KCDSA_KEY_to_Seq, (ISC_KCDSA_UNIT *st, SEQUENCE **seq), (st,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_KCDSA_KEY, (SEQUENCE *seq, ISC_KCDSA_UNIT **st), (seq,st), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_ALGO_IDENTIFIER*, new_X509_ALGO_IDENTIFIER, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_ALGO_IDENTIFIER, (X509_ALGO_IDENTIFIER* x509Algo), (x509Algo) );
INI_RET_LOADLIB_PKI(X509_ALGO_IDENTIFIER*, dup_X509_ALGO_IDENTIFIER, (X509_ALGO_IDENTIFIER* src), (src), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_ALGO_IDENTIFIER_value, (X509_ALGO_IDENTIFIER* x509Algo, OBJECT_IDENTIFIER* alg_id, ASN1_STRING* params), (x509Algo,alg_id,params), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_ALGO_IDENTIFIERS*, new_X509_ALGO_IDENTIFIERS, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_ALGO_IDENTIFIERS, (X509_ALGO_IDENTIFIERS *x509Algos), (x509Algos) );
INI_RET_LOADLIB_PKI(X509_ALGO_IDENTIFIERS*, dup_X509_ALGO_IDENTIFIERS, (X509_ALGO_IDENTIFIERS* src), (src), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, X509_ALGO_IDENTIFIER_to_Seq, (X509_ALGO_IDENTIFIER *st, SEQUENCE **seq), (st,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_X509_ALGO_IDENTIFIER, (SEQUENCE *seq, X509_ALGO_IDENTIFIER **st), (seq,st), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, X509_ALGO_IDENTIFIERS_to_Seq, (X509_ALGO_IDENTIFIERS *st, SET_OF **seq), (st,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_X509_ALGO_IDENTIFIERS, (SET_OF *seq, X509_ALGO_IDENTIFIERS **st), (seq,st), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_AUX*, new_X509_AUX, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_AUX, (X509_AUX* x509aux), (x509aux) );
INI_RET_LOADLIB_PKI(X509_AUX*, dup_X509_AUX, (X509_AUX* src), (src), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_AUX_localkey, (X509_CERT* x509, uint8 *keyid, int keyidLen), (x509,keyid,keyidLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(uint8*, get_X509_AUX_localkey, (X509_CERT *x509, int *len), (x509,len), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_AUX_friendly, (X509_CERT* x509, uint8 *friendly, int friendlyLen), (x509,friendly,friendlyLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(uint8*, get_X509_AUX_friendly, (X509_CERT *x509, int *len), (x509,len), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, X509_CERT_digest, (const X509_CERT *cert, const int alg_id, uint8 *md, int *len), (cert,alg_id,md,len), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_CERT*, dup_X509_CERT, (X509_CERT * src), (src), NULL);
INI_RET_LOADLIB_PKI(X509_EXTENSIONS*, dup_X509_EXTENSIONS, (X509_EXTENSIONS * src), (src), NULL);
INI_VOID_LOADLIB_PKI(void, print_X509, (X509_CERT *cert), (cert) );
INI_RET_LOADLIB_PKI(X509_PUBKEY*, dup_X509_PUBKEY, (X509_PUBKEY* pkey), (pkey), NULL);
INI_RET_LOADLIB_PKI(int, cmp_X509_PUBKEY, (X509_PUBKEY* a, X509_PUBKEY* b), (a,b), ISC_FAIL);
INI_RET_LOADLIB_PKI(X509_SIGN*, new_X509_SIGN, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_X509_SIGN, (X509_SIGN* sign), (sign) );
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_PUBKEY_ecdsa(X509_PUBKEY* pkey, ISC_ECDSA_UNIT* ecdsa), (pkey,ecdsa), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, gen_ECDSA_SIG_X509_TBS_CERT, (X509_TBS_CERT* tbs, BIT_STRING** signature, OBJECT_IDENTIFIER *alg, ISC_ECDSA_UNIT* pri_params), (tbs, signature,alg,pri_params),  ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, verify_ECDSA_SIG_X509_CERT, (X509_CERT* cert, ISC_ECDSA_UNIT* pub_params), (cert,pub_params), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, ASYMMETRIC_KEY_to_ECDSA_UNIT(ASYMMETRIC_KEY *akey, ISC_ECDSA_UNIT *ecdsa), (akey,ecdsa), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, ECDSA_UNIT_to_ASYMMETRIC_KEY(ISC_ECDSA_UNIT *ecdsa, ASYMMETRIC_KEY *akey), (ecdsa, akey), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, ECC_KEY_UNIT_to_ASYMMETRIC_KEY(ISC_ECC_KEY_UNIT *ec_key, ASYMMETRIC_KEY *akey), (ec_key, akey), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, check_X509_ECDSA_keypair(ISC_ECDSA_UNIT* ecdsa1, ISC_ECDSA_UNIT* ecdsa2), (ecdsa1,ecdsa2), ISC_FAIL);

#endif

#ifdef  __cplusplus
}
#endif
#endif

