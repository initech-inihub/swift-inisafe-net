/*!
* \file pkcs12.h
* \brief PKCS12
* Personal Information Exchange Syntax Standard
* \remarks
* 인증서, 키파일의 가져오기/내보내기 등에 관련된 함수
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_PKCS12_H
#define HEADER_PKCS12_H

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/foundation.h>

#include "asn1.h"
#include "asn1_stack.h"
#include "pkcs7.h"
#include "pkcs8.h"
#include "x509.h"
#include "x509_crl.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define PKCS12_KEY_GEN	1	/*!< PKCS12의 KeyGen ID */
#define PKCS12_IV_GEN	2	/*!< PKCS12의 KeyGen ID */
#define PKCS12_MAC_GEN	3	/*!< PKCS12의 KeyGen ID */

#define PKCS12_DEFAULT_ITER	2048	/*!< PKCS12의 기본 값*/
#define PKCS12_MAC_KEY_LEN 20		/*!< PKCS12의 기본 값*/
#define PKCS12_SALT_LEN	8			/*!< PKCS12의 기본 값*/

#ifdef PKCS12_PASSWORD_UNICODE
#define get_PKCS12_key get_PKCS12_key_UNI
#define add_PKCS12_friendlyname add_PKCS12_friendlyname_UNI
#else
#define get_PKCS12_key gen_PKCS12_key_ASC
#define add_PKCS12_friendlyname add_PKCS12_friendlyname_ASC
#endif

/*!
* \brief
* P12_PFX의 P12의 MAC값 관련 내용을 저장하는 P12_MAC_DATA 구조체
*/
typedef struct P12_MAC_DATA_st{
	OBJECT_IDENTIFIER *digest_algor;	/*!< */
	OCTET_STRING *digest_data;			/*!< */
	OCTET_STRING *macsalt;				/*!< */
	INTEGER *iter;			/*!< */ /* defaults to 1 */
} P12_MAC_DATA;

/*!
* \brief
* P12의 구조체
*/
typedef struct P12_PFX_st{
	INTEGER *version;		/*!< */
	P12_MAC_DATA *mac;		/*!< */
	P7_CONTENT_INFO *authsafes;		/*!< */
} P12_PFX;

/*!
* \brief
* P12의 SafeBag 구조체
*/
typedef struct pkcs12_safe_bag_st{
	OBJECT_IDENTIFIER *type;	/*!< */
	OBJECT_IDENTIFIER *shkeybag_oid;	/*!< */
	union {
		struct pkcs12_bag_st *bag; /*!< */ /* secret, crl and certbag */
		struct priv_key_st	*keybag; /*!< */ /* keybag */
		OCTET_STRING *shkeybag; /*!< */
		STK(P12_SAFEBAG) *safes; /*!< */
		ASN1_STRING *other; /*!< */
	} Value;
	X509_ATTRIBUTES *attrib; /*!< */
} P12_SAFEBAG;	

/*!
* \brief
* P12의 SafeBag 구조체의 스택 구조체
*/
typedef STK(P12_SAFEBAG) P12_SAFEBAGS;

/*!
* \brief
* P12의 Bag 구조체
*/
typedef struct pkcs12_bag_st {
	OBJECT_IDENTIFIER *type;	/*!< */
	union {
		OCTET_STRING *x509cert;	/*!< */
		OCTET_STRING *x509crl;	/*!< */
		OCTET_STRING *octet;	/*!< */
		IA5_STRING *sdsicert;	/*!< */
		ASN1_STRING *other;		/*!< */  /* Secret or other bag */
	}Value;
} P12_BAGS;

/*!
* \brief
* PKCS7 구조체의 스택 구조체
*/
typedef STK(P7_CONTENT_INFO) P12_AUTH_SAFE;

/*!
* \brief
* LOCAL_KEY_INFO 구조체의 스택 구조체
*/

#define LOCAL_KEY_INFO OCTET_STRING;

/*!
* \brief
* LOCAL_KEY_INFO 구조체의 스택 구조체
*/
typedef STK(LOCAL_KEY_INFO) LOCAL_KEY_INFOS;

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* P12_PFX 구조체의 초기화 함수
* \returns
* P12_PFX 구조체 포인터
*/
ISC_API P12_PFX* new_PKCS12();

/*!
* \brief
* P12_PFX 구조체를 메모리 할당 해제
* \param pk12
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_PKCS12(P12_PFX* pk12);

/*!
* \brief
* P12_MAC_DATA 구조체의 초기화 함수
* \returns
* P12_MAC_DATA 구조체 포인터
*/
ISC_API P12_MAC_DATA* new_P12_MAC_DATA();

/*!
* \brief
* P12_MAC_DATA 구조체를 메모리 할당 해제
* \param pk12_mac
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_P12_MAC_DATA(P12_MAC_DATA* pk12_mac);

/*!
* \brief
* P12_SAFEBAG 구조체의 초기화 함수
* \returns
* P12_SAFEBAG 구조체 포인터
*/
ISC_API P12_SAFEBAG* new_P12_SAFEBAG();

/*!
* \brief
* P12_SAFEBAG 구조체를 메모리 할당 해제
* \param pk12_sfbag
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_P12_SAFEBAG(P12_SAFEBAG* pk12_sfbag);

/*!
* \brief
* P12_SAFEBAGS 구조체의 초기화 함수
* \returns
* P12_SAFEBAGS 구조체 포인터
*/
ISC_API P12_SAFEBAGS* new_P12_SAFEBAGS();

/*!
* \brief
* P12_SAFEBAGS 구조체를 메모리 할당 해제
* \param psbs
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_P12_SAFEBAGS(P12_SAFEBAGS* psbs);

/*!
* \brief
* P12_BAGS 구조체의 초기화 함수
* \returns
* P12_BAGS 구조체 포인터
*/
ISC_API P12_BAGS* new_P12_BAGS();

/*!
* \brief
* P12_BAGS 구조체를 메모리 할당 해제
* \param pk12_bags
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_P12_BAGS(P12_BAGS* pk12_bags);

/*!
* \brief
* P12_AUTH_SAFE 구조체의 초기화 함수
* \returns
* P12_AUTH_SAFE 구조체 포인터
*/
ISC_API P12_AUTH_SAFE* new_P12_AUTH_SAFE();

/*!
* \brief
* P12_AUTH_SAFE 구조체를 메모리 할당 해제
* \param auth_safe
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_P12_AUTH_SAFE(P12_AUTH_SAFE* auth_safe);

/*!
* \brief
* X509_CERT 구조체를 P12_SAFEBAG 구조체로 저장하는 함수
* \param x509
* X509_CERT 구조체
* \param certbag
* P12_SAFEBAG 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_X509_CERT_TO_CERTBAG^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_CERT_TO_CERTBAG^ISC_ERR_MEM_ALLOC : 메모리 할당 에러
*/
ISC_API ISC_STATUS X509_CERT_to_CertBag(X509_CERT *x509, P12_SAFEBAG** certbag);

/*!
* \brief
* P12_SAFEBAG 구조체를 X509_CERT 구조체로 저장하는 함수
* \param bag
* P12_SAFEBAG 구조체
* \param x509
* X509_CERT 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_CERTBAG_TO_X509_CERT^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_CERTBAG_TO_X509_CERT^ISC_ERR_INVALID_INPUT : input error
*/
ISC_API ISC_STATUS CertBag_to_X509_CERT(P12_SAFEBAG *bag, X509_CERT** x509);

/*!
* \brief
* P12_SAFEBAG 구조체에 localKeyID를 저장하는 함수
* \param bag
* P12_SAFEBAG 구조체
* \param name
* 저장될 localKeyID
* \param namelen
* 저장될 localKeyID의 길이
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_PKCS12_LKID(P12_SAFEBAG *bag, uint8 *name, int namelen);

/*!
* \brief
* P12_SAFEBAG 구조체에 friendlyname(ASCII)을 저장하는 함수
* \param bag
* P12_SAFEBAG 구조체
* \param name
* 저장될 friendlyname
* \param namelen
* 저장될 friendlyname의 길이
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_PKCS12_friendlyname_ASC(P12_SAFEBAG *bag, const char *name, int namelen);

/*!
* \brief
* P12_SAFEBAG 구조체에 friendlyname(UNICODE)을 저장하는 함수
* \param bag
* P12_SAFEBAG 구조체
* \param name
* 저장될 friendlyname
* \param namelen
* 저장될 friendlyname의 길이
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_PKCS12_friendlyname_UNI(P12_SAFEBAG *bag, uint8 *name, int namelen);

/*!
* \brief
* P12_SAFEBAG 구조체의 attributes에서 입력한 attr_oid에 맞는 데이터를 리턴하는 함수
* \param attrs
* 검색후 데이터가 선택될 X509_ATTRIBUTES 구조체
* \param attr_oid
* attrs에서 검색할 OID
* \returns
* ASN1_STRING 구조체
*/
ISC_API ASN1_STRING *get_PKCS12_attribute(X509_ATTRIBUTES *attrs, int attr_oid);

/*!
* \brief
* P12_SAFEBAG 구조체의 attributes에서 friendlyname을 리턴하는 함수
* \param bag
* 검색후 데이터가 선택될 P12_SAFEBAG 구조체
* \returns
* ASN1_STRING 구조체
* NULL : friendlyname의 없음
*/
ISC_API char *get_PKCS12_friendlyname(P12_SAFEBAG *bag);

/*!
* \brief
* PKCS12의 KeyGen 함수 - 패스워드가 ASCII
* \param pass
* ASCII형 패스워드
* \param passlen
* 패스워드 길이
* \param salt
* SALT
* \param saltlen
* SALT 길이
* \param id
* 1:Key, 2:IV, 3:MAC
* \param iter
* iter
* \param n
* Key의 길이
* \param out
* 생성된 Key
* \param md_type
* Key 생성에 사용되는 해시의 기본값을 담고 있는 ISC_DIGEST_UNIT
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS gen_PKCS12_key_ASC(const char *pass, int passlen, uint8 *salt, int saltlen, int id, int iter, int n, uint8 *out, ISC_DIGEST_UNIT *md_type);

/*!
* \brief
* PKCS12의 KeyGen 함수 - 패스워드가 UNICODE
* \param pass
* UNICODE형 패스워드
* \param passlen
* 패스워드 길이
* \param salt
* SALT
* \param saltlen
* SALT 길이
* \param id
* 1:Key, 2:IV, 3:MAC
* \param iter
* iter
* \param n
* Key의 길이
* \param out
* 생성된 Key
* \param md_type
* Key 생성에 사용되는 해시의 기본값을 담고 있는 ISC_DIGEST_UNIT
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS get_PKCS12_key_UNI(uint8 *pass, int passlen, uint8 *salt, int saltlen, int id, int iter, int n, uint8 *out, ISC_DIGEST_UNIT *md_type);

/*!
* \brief
* PKCS12의 검증함수
* \param p12
* 검증할 P12_PFX 구조체
* \param pass
* 패스워드
* \param passlen
* 패스워드 길이
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
* -# -1 : Verify 실패
*/
ISC_API ISC_STATUS verify_PKCS12_mac(P12_PFX *p12, const char *pass, int passlen);

/*!
* \brief
* PKCS12의 PKCS12_MAC_DATA를 초기화하고 MAC값을 계산하여 저장하는 함수
* \param p12
* MAC값을 취하고 MAC값을 저장할 P12_PFX 구조체
* \param pass
* 패스워드
* \param passlen
* 패스워드 길이
* \param salt
* SALT
* \param saltlen
* SALT 길이
* \param iter
* iteration
* \param digest_id
* MAC 연산에 사용될 digest의 algorithm id (Default : ISC_SHA1)
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SET_PKCS12_MAC^ERR_P12_MAC_INIT : MAC 초기화 단계에서 error
* -# LOCATION^F_SET_PKCS12_MAC^ERR_P12_MAC_GEN : MAC 생성 단계에서 error
*/
ISC_API ISC_STATUS set_PKCS12_mac(P12_PFX *p12, const char *pass, int passlen,
				   uint8 *salt, int saltlen, int iter, int digest_id);


/*!
* \brief
* PKCS12를 Decoding하는 함수
* \param p12
* P12_PFX 구조체
* \param pass
* 패스워드
* \param passlen
* 패스워드 길이
* \param keyinfo_stk
* Decoding되는 P8_PRIV_KEY_INFO 스택 구조체
* \param cert_stk
* Decoding되는 X509_CERT 스택 구조체
* \param ca_stk
* Decoding되는 X509_CERT 스택 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_IMPORT_PKCS12^ISC_ERR_NULL_INPUT : null input error
* -# LOCATION^F_IMPORT_PKCS12^ISC_ERR_MEM_ALLOC : 메모리 할당 에러
* -# LOCATION^F_IMPORT_PKCS12^ISC_ERR_VERIFY_FAILURE : verify error
* -# LOCATION^F_IMPORT_PKCS12^ERR_ASN1_DECODING : PKCS12_PFX 구조체의 parsing error
*/
ISC_API ISC_STATUS import_PKCS12(P12_PFX *p12, const char *pass, int passlen, P8_PRIV_KEY_INFOS **keyinfo_stk, X509_CERTS **cert_stk, X509_CERTS **ca_stk);

/*!
* \brief
* P12_SAFEBAG 스택 구조체에 X509_CERT를 저장하는 함수
* \param pbags
* P12_SAFEBAG 스택 구조체
* \param cert
* 저장할 X509_CERT 구조체
* \returns
* X509_CERT 구조체를 통해 생성된 P12_SAFEBAG 구조체
*/
ISC_API P12_SAFEBAG *add_PKCS12_cert(P12_SAFEBAGS **pbags, X509_CERT *cert);

/*!
* \brief
* P12_SAFEBAG 스택 구조체에 ASYMMETRIC_KEY를 저장하는 함수
* \param pbags
* P12_SAFEBAG 스택 구조체
* \param p8
* 저장할 P8_PRIV_KEY_INFO 구조체
* \param key_usage
* 키 사용목적 (x509v3.h 참조)
* \param iter
* iteration
* \param pbe_oid
* PBE Object ID
* \param pass
* 패스워드
* \returns
* ASYMMETRIC_KEY 구조체를 통해 생성된 P12_SAFEBAG 구조체
*/
ISC_API P12_SAFEBAG *add_PKCS12_keyinfo(P12_SAFEBAGS **pbags, P8_PRIV_KEY_INFO *p8, int key_usage, int iter, int pbe_oid, char *pass);

/*!
* \brief
* P12_SAFEBAG 스택구조체를 P7_CONTENT_INFO 스택구조체로 저장하는 함수
* \param psafes
* 저장될 P7_CONTENT_INFO 스택 구조체
* \param bags
* 저장할 P12_SAFEBAG 스택 구조체
* \param pbe_oid
* PBE Object ID.
* \param iter
* iteration
* \param pass
* 패스워드
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_PKCS12_ADD_SAFE^ISC_ERR_MEM_ALLOC : 메모리 할당 에러
* -# LOCATION^F_PKCS12_ADD_SAFE^ERR_ASN1_ENCODING : encoding step error 
* -# LOCATION^F_PKCS12_ADD_SAFE^ERR_STK_ERROR : 스택 push error
*/
ISC_API ISC_STATUS PKCS12_add_safe(P12_AUTH_SAFE **psafes, P12_SAFEBAGS *bags, int pbe_oid, int iter, char *pass);

/*!
* \brief
* P7_CONTENT_INFO 스택구조체를 P7_CONTENT_INFO 구조체로 저장하는 함수
* \param safes
* 저장될 P7_CONTENT_INFO 스택 구조체
* \returns
* P12_PFX 구조체
*/
ISC_API P12_PFX *PKCS12_add_safes(P12_AUTH_SAFE *safes);

/*!
* \brief
* P12_SAFEBAG 구조체를 P12_SAFEBAG 스택구조체로 저장하는 함수
* \param bags
* 저장될 P12_SAFEBAG 스택 구조체
* \param bag
* 저장할 P12_SAFEBAG 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_ADD_PKCS12_BAG^ISC_ERR_NULL_INPUT : Input Null error
* -# LOCATION^F_PKCS12_ADD_SAFE^ISC_ERR_MEM_ALLOC : 메모리 할당 에러
* -# LOCATION^F_PKCS12_ADD_SAFE^ERR_STK_ERROR : 스택 push error
*/
ISC_API ISC_STATUS add_PKCS12_bag(P12_SAFEBAGS **bags, P12_SAFEBAG *bag);

/*!
* \brief
* P8_PRIV_KEY_INFO 구조체를 P12_SAFEBAG 구조체로 저장하는 함수
* \param p8
* 저장될 P8_PRIV_KEY_INFO 구조체
* \returns
* P12_SAFEBAG 구조체
*/
ISC_API P12_SAFEBAG *get_PKCS12_keybag(P8_PRIV_KEY_INFO *p8);
/*!
* \brief
* P8_PRIV_KEY_INFO 구조체를 PKCS8ShroudedKeyBag 형태로 P12_SAFEBAG 구조체로 저장하는 함수
* \param pbe_oid
* PBE OID
* \param pass
* 패스워드
* \param passlen
* 패스워드 길이
* \param salt
* SALT
* \param saltlen
* SALT 길이
* \param iter
* iteration
* \param priv_unit
* P8_PRIV_KEY_INFO 구조체
* \returns
* P12_SAFEBAG 구조체
*/
ISC_API P12_SAFEBAG *get_PKCS12_shr_keybag(int pbe_oid, const char *pass, int passlen, uint8 *salt, int saltlen, int iter, P8_PRIV_KEY_INFO *priv_unit);

/*!
* \brief
* P12_SAFEBAGS 구조체를 P7_CONTENT_INFO 구조체로 저장하는 함수
* \param sk
* P12_SAFEBAGS 구조체
* \returns
* P7_CONTENT_INFO 구조체
*/
ISC_API P7_CONTENT_INFO *gen_PKCS12_p7data(P12_SAFEBAGS *sk);

/*!
* \brief
* P7_CONTENT_INFO 구조체를 P12_SAFEBAGS 구조체로 저장하는 함수
* \param p7
* P7_CONTENT_INFO 구조체
* \returns
* P12_SAFEBAGS 구조체
*/
ISC_API P12_SAFEBAGS *get_PKCS12_p7data(P7_CONTENT_INFO *p7);

/*!
* \brief
* P12_SAFEBAGS 구조체를 암호화하여 P7_CONTENT_INFO 구조체로 저장하는 함수
* \param pbe_oid
* PBE OID
* \param pass
* 패스워드
* \param passlen
* 패스워드 길이
* \param salt
* SALT
* \param saltlen
* SALT 길이
* \param iter
* iteration
* \param bags
* P12_SAFEBAGS 구조체
* \returns
* P7_CONTENT_INFO 구조체
*/
ISC_API P7_CONTENT_INFO *gen_PKCS12_p7encdata(int pbe_oid, const char *pass, int passlen,
										  uint8 *salt, int saltlen, int iter,
										  P12_SAFEBAGS *bags);
/*!
* \brief
* P7_CONTENT_INFO 구조체의 암호화된 정보를 P12_SAFEBAGS 구조체로 저장하는 함수
* \param p7
* P7_CONTENT_INFO 구조체
* \param pass
* 패스워드
* \param passlen
* 패스워드 길이
* \returns
* P12_SAFEBAGS 구조체
*/
ISC_API P12_SAFEBAGS *get_PKCS12_p7encdata(P7_CONTENT_INFO *p7, const char *pass, int passlen);

/*!
* \brief
* P12_AUTH_SAFE 구조체를 P12_PFX 구조체로 저장하는 함수
* \param safes
* P12_AUTH_SAFE 구조체
* \param p12
* P12_PFX 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS P12_AUTH_SAFE_to_PKCS12(P12_AUTH_SAFE *safes, P12_PFX **p12);

/*!
* \brief
* P12_PFX 구조체를 P12_AUTH_SAFE 구조체로 저장하는 함수
* \param p12
* P12_PFX 구조체
* \param safes
* P12_AUTH_SAFE 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS PKCS12_to_P12_AUTH_SAFE(P12_PFX *p12, P12_AUTH_SAFE **safes);

/*!
* \brief
* P12_SAFEBAGS 구조체를 Sequence로 Encode 함수
* \param pk12_sbgs
* P12_SAFEBAGS 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_P12_SAFEBAGS_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_P12_SAFEBAGS_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_P12_SAFEBAGS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P12_SAFEBAG_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS P12_SAFEBAGS_to_Seq(P12_SAFEBAGS* pk12_sbgs, SEQUENCE** seq);

/*!
* \brief
* Sequence를 P12_SAFEBAGS 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param pk12_sbgs
* P12_SAFEBAGS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_P12_SAFEBAGS^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_SEQ_TO_P12_SAFEBAGS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P12_SAFEBAGS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P12_SAFEBAG()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_P12_SAFEBAGS(SEQUENCE* seq, P12_SAFEBAGS** pk12_sbgs);

/*!
* \brief
* P12_SAFEBAG 구조체를 Sequence로 Encode 함수
* \param pk12_sbg
* P12_SAFEBAG 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_P12_SAFEBAG_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_P12_SAFEBAG_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_P12_SAFEBAG_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P8_PRIV_KEY_INFO_to_Seq()의 에러 코드\n
* -# P12_SAFEBAGS_to_Seq()의 에러 코드\n
* -# P12_BAGS_to_Seq()의 에러 코드\n
* -# X509_ATTRIBUTES_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS P12_SAFEBAG_to_Seq(P12_SAFEBAG* pk12_sbg, SEQUENCE** seq);

/*!
* \brief
* Sequence를 P12_SAFEBAG 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param pk12_sbg
* P12_SAFEBAG 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_P12_SAFEBAG^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_SEQ_TO_P12_SAFEBAG^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P12_SAFEBAG^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P8_PRIV_KEY_INFO()의 에러 코드\n
* -# Seq_to_P12_SAFEBAGS()의 에러 코드\n
* -# Seq_to_P12_BAGS()의 에러 코드\n
* -# Seq_to_X509_ATTRIBUTES()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_P12_SAFEBAG(SEQUENCE* seq, P12_SAFEBAG** pk12_sbg);

/*!
* \brief
* Sequence를 P12_BAGS 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param pk12_bags
* P12_BAGS 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_P12_BAGS^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_SEQ_TO_P12_BAGS^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_P12_BAGS(SEQUENCE* seq, P12_BAGS** pk12_bags);

/*!
* \brief
* P12_BAGS 구조체를 Sequence로 Encode 함수
* \param pk12_bags
* P12_BAGS 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_P12_BAGS_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_P12_BAGS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS P12_BAGS_to_Seq (P12_BAGS* pk12_bags, SEQUENCE** seq);

/*!
* \brief
* Sequence를 P12_PFX 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param pk12
* P12_PFX 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_P12_PFX^ISC_ERR_NULL_INPUT : Null_Input
* -# Seq_to_P7_CONTENT_INFO()의 에러 코드\n
* -# Seq_to_P12_MAC_DATA()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_P12_PFX (SEQUENCE* seq, P12_PFX** pk12);

/*!
* \brief
* P12_PFX 구조체를 Sequence로 Encode 함수
* \param pk12
* P12_PFX 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_P12_PFX_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_P12_PFX_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P7_CONTENT_INFO_to_Seq()의 에러 코드\n
* -# P12_MAC_DATA_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS P12_PFX_to_Seq (P12_PFX* pk12, SEQUENCE** seq);

/*!
* \brief
* Sequence를 P12_AUTH_SAFE 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param auth_safe
* P12_AUTH_SAFE 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_P12_AUTH_SAFE^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_SEQ_TO_P12_AUTH_SAFE^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P12_AUTH_SAFE^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P7_CONTENT_INFO()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_P12_AUTH_SAFE (SEQUENCE* seq, P12_AUTH_SAFE** auth_safe);

/*!
* \brief
* P12_AUTH_SAFE 구조체를 Sequence로 Encode 함수
* \param auth_safe
* P12_AUTH_SAFE 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_P12_AUTH_SAFE_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# P7_CONTENT_INFO_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS P12_AUTH_SAFE_to_Seq (P12_AUTH_SAFE* auth_safe, SEQUENCE** seq);

#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(P12_PFX*, new_PKCS12, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_PKCS12, (P12_PFX* pk12), (pk12) );
INI_RET_LOADLIB_PKI(P12_MAC_DATA*, new_P12_MAC_DATA, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P12_MAC_DATA, (P12_MAC_DATA* pk12_mac), (pk12_mac) );
INI_RET_LOADLIB_PKI(P12_SAFEBAG*, new_P12_SAFEBAG, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P12_SAFEBAG, (P12_SAFEBAG* pk12_sfbag), (pk12_sfbag) );
INI_RET_LOADLIB_PKI(P12_SAFEBAGS*, new_P12_SAFEBAGS, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P12_SAFEBAGS, (P12_SAFEBAGS* psbs), (psbs) );
INI_RET_LOADLIB_PKI(P12_BAGS*, new_P12_BAGS, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P12_BAGS, (P12_BAGS* pk12_bags), (pk12_bags) );
INI_RET_LOADLIB_PKI(P12_AUTH_SAFE*, new_P12_AUTH_SAFE, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P12_AUTH_SAFE, (P12_AUTH_SAFE* auth_safe), (auth_safe) );
INI_RET_LOADLIB_PKI(ISC_STATUS, X509_CERT_to_CertBag, (X509_CERT *x509, P12_SAFEBAG** certbag), (x509,certbag), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, CertBag_to_X509_CERT, (P12_SAFEBAG *bag, X509_CERT** x509), (bag,x509), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_PKCS12_LKID, (P12_SAFEBAG *bag, uint8 *name, int namelen), (bag,name,namelen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_PKCS12_friendlyname_ASC, (P12_SAFEBAG *bag, const char *name, int namelen), (bag,name,namelen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_PKCS12_friendlyname_UNI, (P12_SAFEBAG *bag, uint8 *name, int namelen), (bag,name,namelen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ASN1_STRING*, get_PKCS12_attribute, (X509_ATTRIBUTES *attrs, int attr_oid), (attrs,attr_oid), NULL);
INI_RET_LOADLIB_PKI(char*, get_PKCS12_friendlyname, (P12_SAFEBAG *bag), (bag), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, gen_PKCS12_key_ASC, (const char *pass, int passlen, uint8 *salt, int saltlen, int id, int iter, int n, uint8 *out, ISC_DIGEST_UNIT *md_type), (pass,passlen,salt,saltlen,id,iter,n,out,md_type), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, get_PKCS12_key_UNI, (uint8 *pass, int passlen, uint8 *salt, int saltlen, int id, int iter, int n, uint8 *out, ISC_DIGEST_UNIT *md_type), (pass,passlen,salt,saltlen,id,iter,n,out,md_type), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, verify_PKCS12_mac, (P12_PFX *p12, const char *pass, int passlen), (p12,pass,passlen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_PKCS12_mac, (P12_PFX *p12, const char *pass, int passlen, uint8 *salt, int saltlen, int iter, int digest_id), (p12,pass,passlen,salt,saltlen,iter,digest_id), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, import_PKCS12, (P12_PFX *p12, const char *pass, int passlen, P8_PRIV_KEY_INFOS **keyinfo_stk, X509_CERTS **cert_stk, X509_CERTS **ca_stk), (p12,pass,passlen,keyinfo_stk,cert_stk,ca_stk), ISC_FAIL);
INI_RET_LOADLIB_PKI(P12_SAFEBAG*, add_PKCS12_cert, (P12_SAFEBAGS **pbags, X509_CERT *cert), (pbags,cert), NULL);
INI_RET_LOADLIB_PKI(P12_SAFEBAG*, add_PKCS12_keyinfo, (P12_SAFEBAGS **pbags, P8_PRIV_KEY_INFO *p8, int key_usage, int iter, int pbe_oid, char *pass), (pbags,p8,key_usage,iter,pbe_oid,pass), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, PKCS12_add_safe, (P12_AUTH_SAFE **psafes, P12_SAFEBAGS *bags, int pbe_oid, int iter, char *pass), (psafes,bags,pbe_oid,iter,pass), ISC_FAIL);
INI_RET_LOADLIB_PKI(P12_PFX*, PKCS12_add_safes, (P12_AUTH_SAFE *safes), (safes), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_PKCS12_bag, (P12_SAFEBAGS **bags, P12_SAFEBAG *bag), (bags,bag), ISC_FAIL);
INI_RET_LOADLIB_PKI(P12_SAFEBAG*, get_PKCS12_keybag, (P8_PRIV_KEY_INFO *p8), (p8), NULL);
INI_RET_LOADLIB_PKI(P12_SAFEBAG*, get_PKCS12_shr_keybag, (int pbe_oid, const char *pass, int passlen, uint8 *salt, int saltlen, int iter, P8_PRIV_KEY_INFO *priv_unit), (pbe_oid,pass,passlen,salt,saltlen,iter,priv_unit), NULL);
INI_RET_LOADLIB_PKI(P7_CONTENT_INFO*, gen_PKCS12_p7data, (P12_SAFEBAGS *sk), (sk), NULL);
INI_RET_LOADLIB_PKI(P12_SAFEBAGS*, get_PKCS12_p7data, (P7_CONTENT_INFO *p7), (p7), NULL);
INI_RET_LOADLIB_PKI(P7_CONTENT_INFO*, gen_PKCS12_p7encdata, (int pbe_oid, const char *pass, int passlen, uint8 *salt, int saltlen, int iter, P12_SAFEBAGS *bags), (pbe_oid,pass,passlen,salt,saltlen,iter,bags), NULL);
INI_RET_LOADLIB_PKI(P12_SAFEBAGS*, get_PKCS12_p7encdata, (P7_CONTENT_INFO *p7, const char *pass, int passlen), (p7,pass,passlen), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P12_AUTH_SAFE_to_PKCS12, (P12_AUTH_SAFE *safes, P12_PFX **p12), (safes,p12), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, PKCS12_to_P12_AUTH_SAFE, (P12_PFX *p12, P12_AUTH_SAFE **safes), (p12,safes), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P12_SAFEBAGS_to_Seq, (P12_SAFEBAGS* pk12_sbgs, SEQUENCE** seq), (pk12_sbgs,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P12_SAFEBAGS, (SEQUENCE* seq, P12_SAFEBAGS** pk12_sbgs), (seq,pk12_sbgs), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P12_SAFEBAG_to_Seq, (P12_SAFEBAG* pk12_sbg, SEQUENCE** seq), (pk12_sbg,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P12_SAFEBAG, (SEQUENCE* seq, P12_SAFEBAG** pk12_sbg), (seq,pk12_sbg), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P12_BAGS, (SEQUENCE* seq, P12_BAGS** pk12_bags), (seq,pk12_bags), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P12_BAGS_to_Seq, (P12_BAGS* pk12_bags, SEQUENCE** seq), (pk12_bags,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P12_PFX, (SEQUENCE* seq, P12_PFX** pk12), (seq,pk12), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P12_PFX_to_Seq, (P12_PFX* pk12, SEQUENCE** seq), (pk12,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P12_AUTH_SAFE, (SEQUENCE* seq, P12_AUTH_SAFE** auth_safe), (seq,auth_safe), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P12_AUTH_SAFE_to_Seq, (P12_AUTH_SAFE* auth_safe, SEQUENCE** seq), (auth_safe,seq), ISC_FAIL);

#endif

#ifdef  __cplusplus
}
#endif
#endif





