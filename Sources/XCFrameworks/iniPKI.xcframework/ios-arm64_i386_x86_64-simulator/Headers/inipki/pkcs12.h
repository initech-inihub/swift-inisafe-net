/*!
* \file pkcs12.h
* \brief PKCS12
* Personal Information Exchange Syntax Standard
* \remarks
* ������, Ű������ ��������/�������� � ���õ� �Լ�
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

#define PKCS12_KEY_GEN	1	/*!< PKCS12�� KeyGen ID */
#define PKCS12_IV_GEN	2	/*!< PKCS12�� KeyGen ID */
#define PKCS12_MAC_GEN	3	/*!< PKCS12�� KeyGen ID */

#define PKCS12_DEFAULT_ITER	2048	/*!< PKCS12�� �⺻ ��*/
#define PKCS12_MAC_KEY_LEN 20		/*!< PKCS12�� �⺻ ��*/
#define PKCS12_SALT_LEN	8			/*!< PKCS12�� �⺻ ��*/

#ifdef PKCS12_PASSWORD_UNICODE
#define get_PKCS12_key get_PKCS12_key_UNI
#define add_PKCS12_friendlyname add_PKCS12_friendlyname_UNI
#else
#define get_PKCS12_key gen_PKCS12_key_ASC
#define add_PKCS12_friendlyname add_PKCS12_friendlyname_ASC
#endif

/*!
* \brief
* P12_PFX�� P12�� MAC�� ���� ������ �����ϴ� P12_MAC_DATA ����ü
*/
typedef struct P12_MAC_DATA_st{
	OBJECT_IDENTIFIER *digest_algor;	/*!< */
	OCTET_STRING *digest_data;			/*!< */
	OCTET_STRING *macsalt;				/*!< */
	INTEGER *iter;			/*!< */ /* defaults to 1 */
} P12_MAC_DATA;

/*!
* \brief
* P12�� ����ü
*/
typedef struct P12_PFX_st{
	INTEGER *version;		/*!< */
	P12_MAC_DATA *mac;		/*!< */
	P7_CONTENT_INFO *authsafes;		/*!< */
} P12_PFX;

/*!
* \brief
* P12�� SafeBag ����ü
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
* P12�� SafeBag ����ü�� ���� ����ü
*/
typedef STK(P12_SAFEBAG) P12_SAFEBAGS;

/*!
* \brief
* P12�� Bag ����ü
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
* PKCS7 ����ü�� ���� ����ü
*/
typedef STK(P7_CONTENT_INFO) P12_AUTH_SAFE;

/*!
* \brief
* LOCAL_KEY_INFO ����ü�� ���� ����ü
*/

#define LOCAL_KEY_INFO OCTET_STRING;

/*!
* \brief
* LOCAL_KEY_INFO ����ü�� ���� ����ü
*/
typedef STK(LOCAL_KEY_INFO) LOCAL_KEY_INFOS;

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* P12_PFX ����ü�� �ʱ�ȭ �Լ�
* \returns
* P12_PFX ����ü ������
*/
ISC_API P12_PFX* new_PKCS12();

/*!
* \brief
* P12_PFX ����ü�� �޸� �Ҵ� ����
* \param pk12
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_PKCS12(P12_PFX* pk12);

/*!
* \brief
* P12_MAC_DATA ����ü�� �ʱ�ȭ �Լ�
* \returns
* P12_MAC_DATA ����ü ������
*/
ISC_API P12_MAC_DATA* new_P12_MAC_DATA();

/*!
* \brief
* P12_MAC_DATA ����ü�� �޸� �Ҵ� ����
* \param pk12_mac
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P12_MAC_DATA(P12_MAC_DATA* pk12_mac);

/*!
* \brief
* P12_SAFEBAG ����ü�� �ʱ�ȭ �Լ�
* \returns
* P12_SAFEBAG ����ü ������
*/
ISC_API P12_SAFEBAG* new_P12_SAFEBAG();

/*!
* \brief
* P12_SAFEBAG ����ü�� �޸� �Ҵ� ����
* \param pk12_sfbag
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P12_SAFEBAG(P12_SAFEBAG* pk12_sfbag);

/*!
* \brief
* P12_SAFEBAGS ����ü�� �ʱ�ȭ �Լ�
* \returns
* P12_SAFEBAGS ����ü ������
*/
ISC_API P12_SAFEBAGS* new_P12_SAFEBAGS();

/*!
* \brief
* P12_SAFEBAGS ����ü�� �޸� �Ҵ� ����
* \param psbs
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P12_SAFEBAGS(P12_SAFEBAGS* psbs);

/*!
* \brief
* P12_BAGS ����ü�� �ʱ�ȭ �Լ�
* \returns
* P12_BAGS ����ü ������
*/
ISC_API P12_BAGS* new_P12_BAGS();

/*!
* \brief
* P12_BAGS ����ü�� �޸� �Ҵ� ����
* \param pk12_bags
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P12_BAGS(P12_BAGS* pk12_bags);

/*!
* \brief
* P12_AUTH_SAFE ����ü�� �ʱ�ȭ �Լ�
* \returns
* P12_AUTH_SAFE ����ü ������
*/
ISC_API P12_AUTH_SAFE* new_P12_AUTH_SAFE();

/*!
* \brief
* P12_AUTH_SAFE ����ü�� �޸� �Ҵ� ����
* \param auth_safe
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P12_AUTH_SAFE(P12_AUTH_SAFE* auth_safe);

/*!
* \brief
* X509_CERT ����ü�� P12_SAFEBAG ����ü�� �����ϴ� �Լ�
* \param x509
* X509_CERT ����ü
* \param certbag
* P12_SAFEBAG ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_X509_CERT_TO_CERTBAG^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_CERT_TO_CERTBAG^ISC_ERR_MEM_ALLOC : �޸� �Ҵ� ����
*/
ISC_API ISC_STATUS X509_CERT_to_CertBag(X509_CERT *x509, P12_SAFEBAG** certbag);

/*!
* \brief
* P12_SAFEBAG ����ü�� X509_CERT ����ü�� �����ϴ� �Լ�
* \param bag
* P12_SAFEBAG ����ü
* \param x509
* X509_CERT ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_CERTBAG_TO_X509_CERT^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_CERTBAG_TO_X509_CERT^ISC_ERR_INVALID_INPUT : input error
*/
ISC_API ISC_STATUS CertBag_to_X509_CERT(P12_SAFEBAG *bag, X509_CERT** x509);

/*!
* \brief
* P12_SAFEBAG ����ü�� localKeyID�� �����ϴ� �Լ�
* \param bag
* P12_SAFEBAG ����ü
* \param name
* ����� localKeyID
* \param namelen
* ����� localKeyID�� ����
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_PKCS12_LKID(P12_SAFEBAG *bag, uint8 *name, int namelen);

/*!
* \brief
* P12_SAFEBAG ����ü�� friendlyname(ASCII)�� �����ϴ� �Լ�
* \param bag
* P12_SAFEBAG ����ü
* \param name
* ����� friendlyname
* \param namelen
* ����� friendlyname�� ����
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_PKCS12_friendlyname_ASC(P12_SAFEBAG *bag, const char *name, int namelen);

/*!
* \brief
* P12_SAFEBAG ����ü�� friendlyname(UNICODE)�� �����ϴ� �Լ�
* \param bag
* P12_SAFEBAG ����ü
* \param name
* ����� friendlyname
* \param namelen
* ����� friendlyname�� ����
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_PKCS12_friendlyname_UNI(P12_SAFEBAG *bag, uint8 *name, int namelen);

/*!
* \brief
* P12_SAFEBAG ����ü�� attributes���� �Է��� attr_oid�� �´� �����͸� �����ϴ� �Լ�
* \param attrs
* �˻��� �����Ͱ� ���õ� X509_ATTRIBUTES ����ü
* \param attr_oid
* attrs���� �˻��� OID
* \returns
* ASN1_STRING ����ü
*/
ISC_API ASN1_STRING *get_PKCS12_attribute(X509_ATTRIBUTES *attrs, int attr_oid);

/*!
* \brief
* P12_SAFEBAG ����ü�� attributes���� friendlyname�� �����ϴ� �Լ�
* \param bag
* �˻��� �����Ͱ� ���õ� P12_SAFEBAG ����ü
* \returns
* ASN1_STRING ����ü
* NULL : friendlyname�� ����
*/
ISC_API char *get_PKCS12_friendlyname(P12_SAFEBAG *bag);

/*!
* \brief
* PKCS12�� KeyGen �Լ� - �н����尡 ASCII
* \param pass
* ASCII�� �н�����
* \param passlen
* �н����� ����
* \param salt
* SALT
* \param saltlen
* SALT ����
* \param id
* 1:Key, 2:IV, 3:MAC
* \param iter
* iter
* \param n
* Key�� ����
* \param out
* ������ Key
* \param md_type
* Key ������ ���Ǵ� �ؽ��� �⺻���� ��� �ִ� ISC_DIGEST_UNIT
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS gen_PKCS12_key_ASC(const char *pass, int passlen, uint8 *salt, int saltlen, int id, int iter, int n, uint8 *out, ISC_DIGEST_UNIT *md_type);

/*!
* \brief
* PKCS12�� KeyGen �Լ� - �н����尡 UNICODE
* \param pass
* UNICODE�� �н�����
* \param passlen
* �н����� ����
* \param salt
* SALT
* \param saltlen
* SALT ����
* \param id
* 1:Key, 2:IV, 3:MAC
* \param iter
* iter
* \param n
* Key�� ����
* \param out
* ������ Key
* \param md_type
* Key ������ ���Ǵ� �ؽ��� �⺻���� ��� �ִ� ISC_DIGEST_UNIT
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS get_PKCS12_key_UNI(uint8 *pass, int passlen, uint8 *salt, int saltlen, int id, int iter, int n, uint8 *out, ISC_DIGEST_UNIT *md_type);

/*!
* \brief
* PKCS12�� �����Լ�
* \param p12
* ������ P12_PFX ����ü
* \param pass
* �н�����
* \param passlen
* �н����� ����
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
* -# -1 : Verify ����
*/
ISC_API ISC_STATUS verify_PKCS12_mac(P12_PFX *p12, const char *pass, int passlen);

/*!
* \brief
* PKCS12�� PKCS12_MAC_DATA�� �ʱ�ȭ�ϰ� MAC���� ����Ͽ� �����ϴ� �Լ�
* \param p12
* MAC���� ���ϰ� MAC���� ������ P12_PFX ����ü
* \param pass
* �н�����
* \param passlen
* �н����� ����
* \param salt
* SALT
* \param saltlen
* SALT ����
* \param iter
* iteration
* \param digest_id
* MAC ���꿡 ���� digest�� algorithm id (Default : ISC_SHA1)
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SET_PKCS12_MAC^ERR_P12_MAC_INIT : MAC �ʱ�ȭ �ܰ迡�� error
* -# LOCATION^F_SET_PKCS12_MAC^ERR_P12_MAC_GEN : MAC ���� �ܰ迡�� error
*/
ISC_API ISC_STATUS set_PKCS12_mac(P12_PFX *p12, const char *pass, int passlen,
				   uint8 *salt, int saltlen, int iter, int digest_id);


/*!
* \brief
* PKCS12�� Decoding�ϴ� �Լ�
* \param p12
* P12_PFX ����ü
* \param pass
* �н�����
* \param passlen
* �н����� ����
* \param keyinfo_stk
* Decoding�Ǵ� P8_PRIV_KEY_INFO ���� ����ü
* \param cert_stk
* Decoding�Ǵ� X509_CERT ���� ����ü
* \param ca_stk
* Decoding�Ǵ� X509_CERT ���� ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_IMPORT_PKCS12^ISC_ERR_NULL_INPUT : null input error
* -# LOCATION^F_IMPORT_PKCS12^ISC_ERR_MEM_ALLOC : �޸� �Ҵ� ����
* -# LOCATION^F_IMPORT_PKCS12^ISC_ERR_VERIFY_FAILURE : verify error
* -# LOCATION^F_IMPORT_PKCS12^ERR_ASN1_DECODING : PKCS12_PFX ����ü�� parsing error
*/
ISC_API ISC_STATUS import_PKCS12(P12_PFX *p12, const char *pass, int passlen, P8_PRIV_KEY_INFOS **keyinfo_stk, X509_CERTS **cert_stk, X509_CERTS **ca_stk);

/*!
* \brief
* P12_SAFEBAG ���� ����ü�� X509_CERT�� �����ϴ� �Լ�
* \param pbags
* P12_SAFEBAG ���� ����ü
* \param cert
* ������ X509_CERT ����ü
* \returns
* X509_CERT ����ü�� ���� ������ P12_SAFEBAG ����ü
*/
ISC_API P12_SAFEBAG *add_PKCS12_cert(P12_SAFEBAGS **pbags, X509_CERT *cert);

/*!
* \brief
* P12_SAFEBAG ���� ����ü�� ASYMMETRIC_KEY�� �����ϴ� �Լ�
* \param pbags
* P12_SAFEBAG ���� ����ü
* \param p8
* ������ P8_PRIV_KEY_INFO ����ü
* \param key_usage
* Ű ������ (x509v3.h ����)
* \param iter
* iteration
* \param pbe_oid
* PBE Object ID
* \param pass
* �н�����
* \returns
* ASYMMETRIC_KEY ����ü�� ���� ������ P12_SAFEBAG ����ü
*/
ISC_API P12_SAFEBAG *add_PKCS12_keyinfo(P12_SAFEBAGS **pbags, P8_PRIV_KEY_INFO *p8, int key_usage, int iter, int pbe_oid, char *pass);

/*!
* \brief
* P12_SAFEBAG ���ñ���ü�� P7_CONTENT_INFO ���ñ���ü�� �����ϴ� �Լ�
* \param psafes
* ����� P7_CONTENT_INFO ���� ����ü
* \param bags
* ������ P12_SAFEBAG ���� ����ü
* \param pbe_oid
* PBE Object ID.
* \param iter
* iteration
* \param pass
* �н�����
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_PKCS12_ADD_SAFE^ISC_ERR_MEM_ALLOC : �޸� �Ҵ� ����
* -# LOCATION^F_PKCS12_ADD_SAFE^ERR_ASN1_ENCODING : encoding step error 
* -# LOCATION^F_PKCS12_ADD_SAFE^ERR_STK_ERROR : ���� push error
*/
ISC_API ISC_STATUS PKCS12_add_safe(P12_AUTH_SAFE **psafes, P12_SAFEBAGS *bags, int pbe_oid, int iter, char *pass);

/*!
* \brief
* P7_CONTENT_INFO ���ñ���ü�� P7_CONTENT_INFO ����ü�� �����ϴ� �Լ�
* \param safes
* ����� P7_CONTENT_INFO ���� ����ü
* \returns
* P12_PFX ����ü
*/
ISC_API P12_PFX *PKCS12_add_safes(P12_AUTH_SAFE *safes);

/*!
* \brief
* P12_SAFEBAG ����ü�� P12_SAFEBAG ���ñ���ü�� �����ϴ� �Լ�
* \param bags
* ����� P12_SAFEBAG ���� ����ü
* \param bag
* ������ P12_SAFEBAG ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ADD_PKCS12_BAG^ISC_ERR_NULL_INPUT : Input Null error
* -# LOCATION^F_PKCS12_ADD_SAFE^ISC_ERR_MEM_ALLOC : �޸� �Ҵ� ����
* -# LOCATION^F_PKCS12_ADD_SAFE^ERR_STK_ERROR : ���� push error
*/
ISC_API ISC_STATUS add_PKCS12_bag(P12_SAFEBAGS **bags, P12_SAFEBAG *bag);

/*!
* \brief
* P8_PRIV_KEY_INFO ����ü�� P12_SAFEBAG ����ü�� �����ϴ� �Լ�
* \param p8
* ����� P8_PRIV_KEY_INFO ����ü
* \returns
* P12_SAFEBAG ����ü
*/
ISC_API P12_SAFEBAG *get_PKCS12_keybag(P8_PRIV_KEY_INFO *p8);
/*!
* \brief
* P8_PRIV_KEY_INFO ����ü�� PKCS8ShroudedKeyBag ���·� P12_SAFEBAG ����ü�� �����ϴ� �Լ�
* \param pbe_oid
* PBE OID
* \param pass
* �н�����
* \param passlen
* �н����� ����
* \param salt
* SALT
* \param saltlen
* SALT ����
* \param iter
* iteration
* \param priv_unit
* P8_PRIV_KEY_INFO ����ü
* \returns
* P12_SAFEBAG ����ü
*/
ISC_API P12_SAFEBAG *get_PKCS12_shr_keybag(int pbe_oid, const char *pass, int passlen, uint8 *salt, int saltlen, int iter, P8_PRIV_KEY_INFO *priv_unit);

/*!
* \brief
* P12_SAFEBAGS ����ü�� P7_CONTENT_INFO ����ü�� �����ϴ� �Լ�
* \param sk
* P12_SAFEBAGS ����ü
* \returns
* P7_CONTENT_INFO ����ü
*/
ISC_API P7_CONTENT_INFO *gen_PKCS12_p7data(P12_SAFEBAGS *sk);

/*!
* \brief
* P7_CONTENT_INFO ����ü�� P12_SAFEBAGS ����ü�� �����ϴ� �Լ�
* \param p7
* P7_CONTENT_INFO ����ü
* \returns
* P12_SAFEBAGS ����ü
*/
ISC_API P12_SAFEBAGS *get_PKCS12_p7data(P7_CONTENT_INFO *p7);

/*!
* \brief
* P12_SAFEBAGS ����ü�� ��ȣȭ�Ͽ� P7_CONTENT_INFO ����ü�� �����ϴ� �Լ�
* \param pbe_oid
* PBE OID
* \param pass
* �н�����
* \param passlen
* �н����� ����
* \param salt
* SALT
* \param saltlen
* SALT ����
* \param iter
* iteration
* \param bags
* P12_SAFEBAGS ����ü
* \returns
* P7_CONTENT_INFO ����ü
*/
ISC_API P7_CONTENT_INFO *gen_PKCS12_p7encdata(int pbe_oid, const char *pass, int passlen,
										  uint8 *salt, int saltlen, int iter,
										  P12_SAFEBAGS *bags);
/*!
* \brief
* P7_CONTENT_INFO ����ü�� ��ȣȭ�� ������ P12_SAFEBAGS ����ü�� �����ϴ� �Լ�
* \param p7
* P7_CONTENT_INFO ����ü
* \param pass
* �н�����
* \param passlen
* �н����� ����
* \returns
* P12_SAFEBAGS ����ü
*/
ISC_API P12_SAFEBAGS *get_PKCS12_p7encdata(P7_CONTENT_INFO *p7, const char *pass, int passlen);

/*!
* \brief
* P12_AUTH_SAFE ����ü�� P12_PFX ����ü�� �����ϴ� �Լ�
* \param safes
* P12_AUTH_SAFE ����ü
* \param p12
* P12_PFX ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS P12_AUTH_SAFE_to_PKCS12(P12_AUTH_SAFE *safes, P12_PFX **p12);

/*!
* \brief
* P12_PFX ����ü�� P12_AUTH_SAFE ����ü�� �����ϴ� �Լ�
* \param p12
* P12_PFX ����ü
* \param safes
* P12_AUTH_SAFE ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS PKCS12_to_P12_AUTH_SAFE(P12_PFX *p12, P12_AUTH_SAFE **safes);

/*!
* \brief
* P12_SAFEBAGS ����ü�� Sequence�� Encode �Լ�
* \param pk12_sbgs
* P12_SAFEBAGS ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P12_SAFEBAGS_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_P12_SAFEBAGS_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_P12_SAFEBAGS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P12_SAFEBAG_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS P12_SAFEBAGS_to_Seq(P12_SAFEBAGS* pk12_sbgs, SEQUENCE** seq);

/*!
* \brief
* Sequence�� P12_SAFEBAGS ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param pk12_sbgs
* P12_SAFEBAGS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P12_SAFEBAGS^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_SEQ_TO_P12_SAFEBAGS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P12_SAFEBAGS^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P12_SAFEBAG()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P12_SAFEBAGS(SEQUENCE* seq, P12_SAFEBAGS** pk12_sbgs);

/*!
* \brief
* P12_SAFEBAG ����ü�� Sequence�� Encode �Լ�
* \param pk12_sbg
* P12_SAFEBAG ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P12_SAFEBAG_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_P12_SAFEBAG_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_P12_SAFEBAG_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P8_PRIV_KEY_INFO_to_Seq()�� ���� �ڵ�\n
* -# P12_SAFEBAGS_to_Seq()�� ���� �ڵ�\n
* -# P12_BAGS_to_Seq()�� ���� �ڵ�\n
* -# X509_ATTRIBUTES_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS P12_SAFEBAG_to_Seq(P12_SAFEBAG* pk12_sbg, SEQUENCE** seq);

/*!
* \brief
* Sequence�� P12_SAFEBAG ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param pk12_sbg
* P12_SAFEBAG ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P12_SAFEBAG^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_SEQ_TO_P12_SAFEBAG^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P12_SAFEBAG^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P8_PRIV_KEY_INFO()�� ���� �ڵ�\n
* -# Seq_to_P12_SAFEBAGS()�� ���� �ڵ�\n
* -# Seq_to_P12_BAGS()�� ���� �ڵ�\n
* -# Seq_to_X509_ATTRIBUTES()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P12_SAFEBAG(SEQUENCE* seq, P12_SAFEBAG** pk12_sbg);

/*!
* \brief
* Sequence�� P12_BAGS ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param pk12_bags
* P12_BAGS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P12_BAGS^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_SEQ_TO_P12_BAGS^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_P12_BAGS(SEQUENCE* seq, P12_BAGS** pk12_bags);

/*!
* \brief
* P12_BAGS ����ü�� Sequence�� Encode �Լ�
* \param pk12_bags
* P12_BAGS ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P12_BAGS_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_P12_BAGS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS P12_BAGS_to_Seq (P12_BAGS* pk12_bags, SEQUENCE** seq);

/*!
* \brief
* Sequence�� P12_PFX ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param pk12
* P12_PFX ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P12_PFX^ISC_ERR_NULL_INPUT : Null_Input
* -# Seq_to_P7_CONTENT_INFO()�� ���� �ڵ�\n
* -# Seq_to_P12_MAC_DATA()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P12_PFX (SEQUENCE* seq, P12_PFX** pk12);

/*!
* \brief
* P12_PFX ����ü�� Sequence�� Encode �Լ�
* \param pk12
* P12_PFX ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P12_PFX_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_P12_PFX_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# P7_CONTENT_INFO_to_Seq()�� ���� �ڵ�\n
* -# P12_MAC_DATA_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS P12_PFX_to_Seq (P12_PFX* pk12, SEQUENCE** seq);

/*!
* \brief
* Sequence�� P12_AUTH_SAFE ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param auth_safe
* P12_AUTH_SAFE ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P12_AUTH_SAFE^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_SEQ_TO_P12_AUTH_SAFE^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P12_AUTH_SAFE^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_P7_CONTENT_INFO()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P12_AUTH_SAFE (SEQUENCE* seq, P12_AUTH_SAFE** auth_safe);

/*!
* \brief
* P12_AUTH_SAFE ����ü�� Sequence�� Encode �Լ�
* \param auth_safe
* P12_AUTH_SAFE ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P12_AUTH_SAFE_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# P7_CONTENT_INFO_to_Seq()�� ���� �ڵ�\n
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





