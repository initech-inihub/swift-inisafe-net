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
 * X509 �� pkcs5/8�� ���Ǵ� ����Ű�� ������ ����ü
 */
typedef struct asymmetric_key_parma_st{
	int keyType;		/*!< Ű ����*/
	union{		
		ISC_RSA_UNIT* rsa_key;		/*!< ISC_RSA Ű ����*/
		ISC_KCDSA_UNIT* kcdsa_key;	/*!< ISC_KCDSA Ű ����*/
		ISC_ECDSA_UNIT* ecdsa_key;	/*!< ECDSA Ű ����*/
		ISC_ECC_KEY_UNIT* ecc_key;	/*!< ECC Ű ����*/
	}keyData;	
}ASYMMETRIC_KEY;

/*!
* \brief
* X509 DN�� �����ϴ� ���
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
* X509 Extensions�� ���� ���
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
* X509 Attribute Data ����ü
*/
typedef struct x509_attribute_data_st
{
	int type;
	void *data;
} X509_ATTRIBUTE_DATA;
    
/*!
* \brief
* X509 Attribute Data ����ü ����Ʈ
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
	OBJECT_IDENTIFIER *object;	/*!< attribute�� oid*/
	X509_ATTRIBUTE_DATAS *values;	/*!< attribute�� values*/
} X509_ATTRIBUTE;

/*!
* \brief
* X509 Attributes
*/
typedef STK(X509_ATTRIBUTE) X509_ATTRIBUTES;

/*!
* \brief
* X509 TBS Certificate ����ü
*/
typedef struct x509_tbs_st
{
	uint8 version;						/*!< ���� ���� */		
	ISC_BIGINT *serialnumber;				/*!< �ø��� ��ȣ */
	OBJECT_IDENTIFIER *signature;		/*!< ���ڼ��� �˰��� */
	X509_NAME *issuer;					/*!< �߱��� ���� DN*/
	X509_VALIDITY *validity;			/*!< ��ȿ�Ⱓ */
	X509_NAME *subject;					/*!< ��ü�� ���� DN*/
	X509_PUBKEY *pubkey;				/*!< �������� ����Ű */
	BIT_STRING *issuerUniqueID;         /*!< �߱��� �ĺ� ID */
	BIT_STRING *subjectUniqueID;        /*!< ��ü�� �ĺ� ID */ 
	X509_EXTENSIONS *exts;				/*!< x509v3 Ȯ�� �ʵ� */
} X509_TBS_CERT;

/*!
* \brief
* X509 ������ ���� PKCS12 friendly name / LKID�� ĳ��
*/
typedef struct x509_aux_st
{
	UTF8_STRING *friendly;
	OCTET_STRING *localkeyID;		
} X509_AUX;

/*!
* \brief
* X509 Certificate ����ü
*/
typedef struct x509_st
{
	X509_TBS_CERT *tbs;		/*!< X509 TBS ������ ���� */		
	OBJECT_IDENTIFIER *sig_alg;	 /*!< ������ ���� �˰��� */		
	BIT_STRING *signature;		 /*!< ������ ���� */		
	X509_AUX * aux_verify;		 /*!< PKCS12���� ���Ǵ� friendly name, LKID */
} X509_CERT;

/*!
* \brief
* X509 Certificate Pair ����ü
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
* X509 �� pkcs � ���Ǵ� �˰��� �� ����ü
*/
typedef struct X509_ALGO_IDENTIFIER_st {
	OBJECT_IDENTIFIER *algorithm;  /*!< �˰����� OBJECT IDENTIFIER */
	ASN1_STRING *parameters; /*!< �˰��� ���� Parameter */
} X509_ALGO_IDENTIFIER;

typedef STK(X509_ALGO_IDENTIFIER) X509_ALGO_IDENTIFIERS;

/*!
* \brief
* X509 Signature�� �����ϴ� ���
*/
typedef struct X509_SIGN_st
{
	X509_ALGO_IDENTIFIER *algorithm;	/*!< hash �˰���*/
	OCTET_STRING *hashedData;		/*!< h(m)�� */

} X509_SIGN;

    
#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* X509_CERT ����ü�� �ʱ�ȭ �Լ�
* \returns
* X509_CERT ����ü ������
*/
ISC_API X509_CERT *new_X509_CERT(void);

/*!
* \brief
* X509_CERT ����ü�� �޸� �Ҵ� ����
* \param cert
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_X509_CERT(X509_CERT *cert);

/*!
* \brief
* X509_CERT ����ü�� ����
* \param cert
* ������ ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API void clean_X509_CERT(X509_CERT *cert);

/*!
* \brief
* X509_CERT�� version�� ����
* \param cert
* ������ ������
* \param version
* ���� ���� (0x00, 0x01, 0x02)
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_version(X509_CERT *cert, uint8 version);

/*!
* \brief
* X509_CERT�� serialnumber ����
* \param cert
* ������ ������
* \param serialnumber
* ������ �ø��� ��ȣ
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_serial (X509_CERT *cert, INTEGER *serialnumber);

/*!
* \brief
* X509_CERT�� ���� �˰��� ����
* \param cert
* ������ ������
* \param oid
* ������ ���� �˰���
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_signature(X509_CERT *cert, OBJECT_IDENTIFIER *oid);

/*!
* \brief
* X509_CERT�� �߱��� DN ����
* \param cert
* ������ ������
* \param name
* �߱��� DN
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_issuer (X509_CERT *cert, X509_NAME *name);

/*!
* \brief
* X509_CERT�� ��ü�� DN ����
* \param cert
* ������ ������
* \param name
* �߱��� DN
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_subject (X509_CERT *cert, X509_NAME *name);

/*!
* \brief
* X509_CERT�� notBefore ����
* \param cert
* ������ ������
* \param notBefore
* notAfter�� X509_TIME ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_notBefore(X509_CERT *cert, X509_TIME *notBefore);

/*!
* \brief
* X509_CERT�� notAfter ����
* \param cert
* ������ ������
* \param notAfter
* notAfter�� X509_TIME ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_notAfter(X509_CERT *cert, X509_TIME *notAfter);

/*!
* \brief
* X509_CERT�� public key ����
* \param cert
* ������ ������
* \param key
* x509 pubic key ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_pub_key(X509_CERT *cert, X509_PUBKEY *key);

/*!
* \brief
* X509_CERT�� �������� ����
* \param cert
* ������ ����ü ������
* \returns
* ��������
*/
ISC_API uint8 get_X509_version(X509_CERT *cert);

/*!
* \brief
* X509_CERT�� �ø��� ��ȣ ����
* \param cert
* ������ ����ü ������
* \returns
* �ø��� ��ȣ
*/
ISC_API INTEGER* get_X509_serial(X509_CERT *cert);

/*!
* \brief
* X509_CERT�� ����˰��� ����
* \param cert
* ������ ����ü ������
* \returns
* ���� �˰���
*/
ISC_API OBJECT_IDENTIFIER* get_X509_signature(X509_CERT *cert);
/*!
* \brief
* X509_CERT�� �߱��� DN ����
* \param cert
* ������ ����ü ������
* \returns
* �߱��� DN
*/
ISC_API X509_NAME* get_X509_issuer(X509_CERT *cert);

/*!
* \brief
* X509_CERT�� ��ü�� DN ����
* \param cert
* ������ ����ü ������
* \returns
* ��ü�� DN
*/
ISC_API X509_NAME* get_X509_subject(X509_CERT *cert);

/*!
* \brief
* X509_CERT�� NotAfter �ð����� ����
* \param cert
* ������ ����ü ������
* \returns
* NotAfter �ð�����
*/
ISC_API X509_TIME* get_X509_notAfter(X509_CERT *cert);

/*!
* \brief
* X509_CERT�� NotBefore �ð����� ����
* \param cert
* ������ ����ü ������
* \returns
* NotBefore �ð�����
*/
ISC_API X509_TIME* get_X509_notBefore(X509_CERT *cert);

/*!
* \brief
* X509_CERT�� ����Ű ���� ����
* \param cert
* ������ ����ü ������
* \returns
* X509 ����Ű ����
*/
ISC_API X509_PUBKEY* get_X509_SPKI(X509_CERT *cert);

/*!
* \brief
* X509_CERT�� ���� �˰��� ����
* \param cert
* ������ ����ü ������
* \returns
* ���� �˰��� ����
*/
ISC_API OBJECT_IDENTIFIER* get_X509_sig_alg(X509_CERT *cert);

/*!
* \brief
* X509_CERT�� ���� ����
* \param cert
* ������ ����ü ������
* \returns
* ���� ����
*/
ISC_API BIT_STRING* get_X509_sig_value(X509_CERT *cert);



/*!
* \brief
* X509_CERT_PAIR ����ü�� �ʱ�ȭ �Լ�
* \returns
* X509_CERT_PAIR ����ü ������
*/
ISC_API X509_CERT_PAIR *new_X509_CERT_PAIR();

/*!
* \brief
* X509_CERT_PAIR ����ü�� �޸� �Ҵ� ����
* \param x509_certPair
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_X509_CERT_PAIR(X509_CERT_PAIR* x509_certPair);

/*!
* \brief
* X509_TIME ����ü�� �ʱ�ȭ �Լ�
* \returns
* X509_TIME ����ü ������
*/
ISC_API X509_TIME* new_X509_TIME();

/*!
* \brief
* X509_TIME ����ü�� �޸� �Ҵ� ����
* \param name
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_X509_TIME(X509_TIME *name);

/*!
* \brief
* X509_TIME ����ü�� �����ϴ� �Լ�
* \param from
* ������ ����
* \param to
* ����� ���(�޸� �Ҵ��ؼ� �ٰ�.)
*/
ISC_API ISC_STATUS copy_X509_TIME(X509_TIME *from, X509_TIME *to);

/*!
* \brief
* X509_NAME ����ü�� �ʱ�ȭ �Լ�
* \returns
* X509_NAME ����ü ������
*/
ISC_API X509_NAME* new_X509_NAME();

/*!
* \brief
* X509_NAME ����ü�� �޸� �Ҵ� ����
* \param name
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_X509_NAME(X509_NAME* name);

/*!
* \brief
* X509_NAME_CHILD ����ü�� �ʱ�ȭ �Լ�
* \returns
* X509_NAME_CHILD ����ü ������
*/
ISC_API X509_NAME_CHILD* new_X509_NAME_CHILD();

/*!
* \brief
* X509_NAME_CHILD ����ü�� �޸� �Ҵ� ����
* \param name
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_X509_NAME_CHILD(X509_NAME_CHILD* name);

/*!
* \brief
* X509_NAME_CHILD ����ü�� ����
* \param name
* ������ ����ü ������
* \return
* X509_NAME_CHILD ����ü ������
*/
ISC_API X509_NAME_CHILD* dup_X509_NAME_CHILD(X509_NAME_CHILD* name);

/*!
* \brief
* X509_NAME����ü�� X509_NAME_CHILD�� ����
* \param name
* X509_NAME ����ü ������
* \param child
* X509_NAME_CHILD ����ü ������
* \param loc
* ����� ��ġ (default : -1)
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_X509_NAME_child(X509_NAME *name, X509_NAME_CHILD *child, int loc);

/*!
* \brief
* X509_NAME����ü�� X509_NAME_CHILD�� ���� (OID index�� ����)
* \param name
* X509_NAME ����ü ������
* \param index
* oid index (asn1_object.h ����)
* \param type
* ans1 Ÿ��
* \param bytes
* value
* \param len
* value�� ����
* \param loc
* ����� ��ġ (default : -1)
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_X509_NAME_child_OID_index(X509_NAME *name, int index, int type, uint8 *bytes, int len, int loc);

/*!
* \brief
* X509_NAME����ü�� X509_NAME_CHILD�� ���� (OID �� ����)
* \param name
* X509_NAME ����ü ������
* \param oid
* oid ����ü(asn1_object.h ����)
* \param type
* ans1 Ÿ��
* \param bytes
* value
* \param len
* value�� ����
* \param loc
* ����� ��ġ (default : -1)
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_X509_NAME_child_OID(X509_NAME *name, OBJECT_IDENTIFIER *oid, int type, uint8 *bytes, int len, int loc);

/*!
* \brief
* X509_NAME����ü���� loc �� ��ġ�� �ִ� child ����
* \param name
* X509_NAME ����ü ������
* \param loc
* ������ ��ġ
* \return
* ������ X509_NAME_CHILD����ü�� ������
*/
ISC_API X509_NAME_CHILD *remove_X509_NAME_child(X509_NAME *name, int loc);

/*!
* \brief
* X509_NAME����ü�� ��� �ִ� Child�� ���� ��ȯ
* \param name
* X509_NAME ����ü ������
* \return
* child�� ����
*/
ISC_API int get_X509_NAME_count(X509_NAME *name);

/*!
* \brief
* X509_NAME_CHILD����ü�� ��� �ִ� ������ ��ȯ
* \param child
* X509_NAME_CHILD ����ü ������
* \return
* ASN1_STRING ����ü ������
*/
ISC_API ASN1_STRING *get_X509_NAME_CHILD_data(X509_NAME_CHILD *child);

/*!
* \brief
* X509_NAME_CHILD����ü�� ��� �ִ� OBJECT_IDENTIFIER ��ȯ
* \param child
* X509_NAME_CHILD ����ü ������
* \return
* OBJECT_IDENTIFIER ����ü ������
*/
ISC_API OBJECT_IDENTIFIER *get_X509_NAME_CHILD_OID(X509_NAME_CHILD *child);

/*!
* \brief
* X509_NAME����ü�� loc�� ��ġ�� X509_NAME_CHILD�� ������ ��ȯ
* \param name
* X509_NAME ����ü ������
* \param loc
* �ε���
* \return
* X509_NAME_CHILD ����ü ������
*/
ISC_API X509_NAME_CHILD *get_X509_NAME_CHILD(X509_NAME *name, int loc);

/*!
* \brief
* X509_NAME����ü�� OBJECT_IDENTIFIER�� ��ġ�ϴ� �ε����� lastpos���� �˻�
* \param name
* X509_NAME ����ü ������
* \param oid
* OBJECT_IDENTIFIER ����ü ������
* \param lastpos
* �ε��� (default = -1)
* \return
* -# oid�� ��ġ�ϴ� �ε���
* -# oid�� ��ġ�ϴ� �ε����� ������� -1
*/
ISC_API int get_X509_NAME_index_by_OID(X509_NAME *name, OBJECT_IDENTIFIER *oid,int lastpos);

/*!
* \brief
* X509_NAME ����ü�� ����
* \param src
* ������ ����ü ������
* \return
* X509_NAME ����ü ������
*/
ISC_API X509_NAME * dup_X509_NAME(X509_NAME * src);

/*!
* \brief
* X509_NAME ����ü�� ��
* \param n1
* X509_NAME ����ü ������
* \param n2
* X509_NAME ����ü ������
* \return
* -# 0 : ������ ���
* -# -1 : ���� ���� ���
* -# ISC_FAIL : ����
*/
ISC_API int cmp_X509_NAME(X509_NAME *n1, X509_NAME *n2);

/*!
* DN �񱳷꿡 ���� �̸� �� �Լ�
* \brief
* X509_NAME ����ü�� ��
* \param n1
* X509_NAME ����ü ������
* \param n2
* X509_NAME ����ü ������
* \return
* -# 0 : ������ ���
* -# -1 : ���� ���� ���
* -# ISC_FAIL : ����
*/
ISC_API int cmp_X509_DN(X509_NAME *n1, X509_NAME *n2);

/*!
* \brief
* X509_NAME-der ���ڵ��� �ؽð��� ����
* \param name
* X509_NAME ����ü ������
* \param digest_id
* ��������Ʈ �˰��� ID
* \param md
* ������� ����� ������
* \return
* ������� ����� ����
*/
ISC_API int get_X509_NAME_hash(X509_NAME *name,int digest_id, uint8* md);



/*!
* \brief
* X509_PUBKEY ����ü�� �ʱ�ȭ �Լ�
* \returns
* X509_PUBKEY ����ü ������
*/
ISC_API X509_PUBKEY* new_X509_PUBKEY();

/*!
* \brief
* X509_PUBKEY ����ü�� �޸� �Ҵ� ����
* \param pkey
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_X509_PUBKEY(X509_PUBKEY* pkey);

/*!
* \brief
* X509_PUBKEY ����ü�� rsa ����Ű�� �Է�
* \param pkey
* X509_PUBKEY ����ü ������
* \param rsa
* rsa Ű
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_PUBKEY_rsa(X509_PUBKEY* pkey, ISC_RSA_UNIT* rsa);

/*!
* \brief
* X509_PUBKEY ����ü�� kcdsa ����Ű�� �Է�
* \param pkey
* X509_PUBKEY ����ü ������
* \param kcdsa
* kcdsa Ű
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_PUBKEY_kcdsa(X509_PUBKEY* pkey, ISC_KCDSA_UNIT* kcdsa);

/*!
 * \brief
 * X509_PUBKEY ����ü�� ecdsa ����Ű�� �Է�
 * \param pkey
 * X509_PUBKEY ����ü ������
 * \param ecdsa
 * kcdsa Ű
 * \return
 * -# ISC_SUCCESS : ����
 * -# ISC_FAIL : ����
 */
ISC_API ISC_STATUS set_X509_PUBKEY_ecdsa(X509_PUBKEY* pkey, ISC_ECDSA_UNIT* ecdsa);
    
/*!
* \brief
* X509 �������� �����ϰ� �ִ� ����Ű�� �ؽð��� ����
* \param cert
* X509_CERT ����ü ������
* \param digest_id
* ��������Ʈ �˰��� ID
* \param md
* �ؽð��� ����� ����(�޸� �Ҵ� �Ǿ� �־�� ��)
* \return
* ���ۿ� ����� ����
* 0 : ����
*/
ISC_API int get_X509_PUBLIC_KEY_hash(X509_CERT *cert,int digest_id, uint8* md);


/*!
* \brief
* X509_TBS �������� ISC_RSA�˰������� ����
* \param tbs
* X509_CERT ����ü ������
* \param sig_value
* ������ ����� ������
* \param alg
* ���� �˰��� oid
* \param pri_params
* ISC_RSA ����Ű�� ���Ե� ����ü ������
* \return
* -# ISC_SUCCESS : ����
* -# LOCATION^F_GEN_RSASIGN_TBS_CERT^ISC_ERR_NULL_INPUT : �Է��� NULL�� ���
* -# LOCATION^F_GEN_RSASIGN_TBS_CERT^ISC_ERR_INVALID_INPUT : alg�� �˰����� �ν� �Ұ�, ISC_RSA�迭�� �ƴ� ���
*/
ISC_API ISC_STATUS gen_RSA_SIG_X509_TBS_CERT(X509_TBS_CERT* tbs, BIT_STRING** sig_value, OBJECT_IDENTIFIER *alg, ISC_RSA_UNIT* pri_params);

/*!
* \brief
* X509_TBS �������� ISC_KCDSA�˰������� ����
* \param tbs
* X509_CERT ����ü ������
* \param signature
* ������ ����� ������
* \param alg
* ���� �˰��� oid
* \param pri_params
* ISC_KCDSA ����Ű�� ���Ե� ����ü ������
* \return
* -# ISC_SUCCESS : ����
* -# LOCATION^F_GEN_KCDSASIGN_TBS_CERT^ISC_ERR_NULL_INPUT : �Է��� NULL�� ���
* -# LOCATION^F_GEN_KCDSASIGN_TBS_CERT^ISC_ERR_INVALID_INPUT : alg�� �˰����� �ν� �Ұ�, ISC_KCDSA�迭�� �ƴ� ���
*/
ISC_API ISC_STATUS gen_KCDSA_SIG_X509_TBS_CERT(X509_TBS_CERT* tbs, BIT_STRING** signature, OBJECT_IDENTIFIER *alg, ISC_KCDSA_UNIT* pri_params);

/*!
 * \brief
 * X509_TBS �������� ISC_ECDSA�˰������� ����
 * \param tbs
 * X509_CERT ����ü ������
 * \param signature
 * ������ ����� ������
 * \param alg
 * ���� �˰��� oid
 * \param pri_params
 * ISC_ECDSA ����Ű�� ���Ե� ����ü ������
 * \return
 * -# ISC_SUCCESS : ����
 * -# LOCATION^F_GEN_ECDSASIGN_TBS_CERT^ISC_ERR_NULL_INPUT : �Է��� NULL�� ���
 * -# LOCATION^F_GEN_ECDSASIGN_TBS_CERT^ISC_ERR_INVALID_INPUT : alg�� �˰����� �ν� �Ұ�, ISC_KCDSA�迭�� �ƴ� ���
 */
ISC_API ISC_STATUS gen_ECDSA_SIG_X509_TBS_CERT(X509_TBS_CERT* tbs, BIT_STRING** signature, OBJECT_IDENTIFIER *alg, ISC_ECDSA_UNIT* pri_params);
    
/*!
* \brief
* X509 �������� ���ڼ��� ������ ó���ϰ� ���� ������ x509 ����ü�� �Է���
* \param cert
* X509_CERT ����ü ������
* \param pkey
* ����Ű ������
* \return
* -# ISC_SUCCESS : ����
* -# gen_RSA_SIG_X509_TBS_CERT() �� ���
* -# gen_KCDSA_SIG_X509_TBS_CERT() �� ���
*/
ISC_API ISC_STATUS gen_SIG_X509_Cert(X509_CERT* cert, ASYMMETRIC_KEY *pkey);


/*!
* \brief
* �������� ������ ������ (ISC_RSA)
* \param cert
* X509_CERT ����ü ������
* \param pub_params
* rsa ����Ű
* \return
* -# ISC_SUCCESS : ����
* -# LOCATION^F_VERIFY_RSASIGN_TBS_CERT^ISC_ERR_NULL_INPUT : �Է��� NULL�� ���
* -# X509_TBS_CERT_to_Seq()�� ���� �ڵ�
* -# LOCATION^F_VERIFY_RSASIGN_TBS_CERT^ISC_ERR_INVALID_INPUT : �˰��� �ν� �Ұ�
*/
ISC_API ISC_STATUS verify_RSA_SIG_X509_CERT(X509_CERT* cert, ISC_RSA_UNIT* pub_params);

/*!
* \brief
* �������� ������ ������ (ISC_KCDSA)
* \param cert
* X509_CERT ����ü ������
* \param pub_params
* kcdsa ����Ű
* \return
* -# ISC_SUCCESS : ����
* -# LOCATION^F_VERIFY_KCDSASIGN_TBS_CERT^ISC_ERR_NULL_INPUT : �Է��� NULL�� ���
* -# X509_TBS_CERT_to_Seq() �� ���
* -# LOCATION^F_VERIFY_KCDSASIGN_TBS_CERT^ISC_ERR_INVALID_INPUT : �˰��� �ν� �Ұ�
*/
ISC_API ISC_STATUS verify_KCDSA_SIG_X509_CERT(X509_CERT* cert, ISC_KCDSA_UNIT* pub_params);

/*!
 * \brief
 * �������� ������ ������ (ISC_ECDSA)
 * \param cert
 * X509_CERT ����ü ������
 * \param pub_params
 * ecdsa ����Ű
 * \return
 * -# ISC_SUCCESS : ����
 * -# LOCATION^F_VERIFY_ECDSASIGN_TBS_CERT^ISC_ERR_NULL_INPUT : �Է��� NULL�� ���
 * -# X509_TBS_CERT_to_Seq() �� ���
 * -# LOCATION^F_VERIFY_ECDSASIGN_TBS_CERT^ISC_ERR_INVALID_INPUT : �˰��� �ν� �Ұ�
 */
ISC_API ISC_STATUS verify_ECDSA_SIG_X509_CERT(X509_CERT* cert, ISC_ECDSA_UNIT* pub_params);
    
/*!
* \brief
* �������� ������ ������
* \param cert
* X509_CERT ����ü ������
* \param pubKey
* ����Ű
* \return
* -# ISC_SUCCESS : ����
* -# verify_RSA_SIG_X509_CERT()�� ���� �ڵ�
* -# verify_KCDSA_SIG_X509_CERT()�� ���� �ڵ�
* -# LOCATION^F_VERIFY_KCDSASIGN_TBS_CERT^ISC_ERR_INVALID_INPUT : �˰��� �ν� �Ұ�
*/
ISC_API ISC_STATUS verify_SIG_X509_CERT(X509_CERT* cert, X509_PUBKEY* pubKey);

/*!
* \brief
* �������� ��ȿ�Ⱓ�� ������ (time�� NULL�� �Է��ϸ� ����ð��� ����)
* \param cert
* X509_CERT ����ü ������
* \param time
* time
* \return
* -# ISC_SUCCESS : ����
* -# LOCATION^F_VERIFY_X509_VALIDITY^ERR_CERT_NOT_BEFORE : ����ð��� ��ȿ�Ⱓ ����
* -# LOCATION^F_VERIFY_X509_VALIDITY^ERR_CERT_NOT_AFTER : ���� �ð��� ��ȿ�Ⱓ ����
*/
/* time ���ڰ� NULL�� �ܿ� ���� �ð��� �� */
ISC_API ISC_STATUS verify_X509_validity(X509_CERT *cert, X509_TIME *time);


/*!
* \brief
* ASYMMETRIC_KEY ����ü�� �ʱ�ȭ �Լ�
* \returns
* ASYMMETRIC_KEY ����ü ������
*/
ISC_API ASYMMETRIC_KEY* new_ASYMMETRIC_KEY();

/*!
* \brief
* ASYMMETRIC_KEY ����ü�� �޸� �Ҵ� ����
* \param akey
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_ASYMMETRIC_KEY(ASYMMETRIC_KEY* akey);

/*!
* \brief
* ASYMMETRIC_KEY ����ü�� ����
* \param src
* ������ ����ü ������
* \return
* ASYMMETRIC_KEY ����ü ������
*/
ISC_API ASYMMETRIC_KEY* dup_ASYMMETRIC_KEY(ASYMMETRIC_KEY* src);

/*!
* \brief
* ASYMMETRIC_KEY ����ü�� ��
* \param a
* ASYMMETRIC_KEY ����ü ������
* \param b
* ASYMMETRIC_KEY ����ü ������
* \return
* -# 0 : ������ ���
* -# -1 : ���� ���� ���
* -# ISC_FAIL : ����
*/
ISC_API int cmp_ASYMMETRIC_KEY(ASYMMETRIC_KEY* a, ASYMMETRIC_KEY* b);

/*!
* \brief
* ASYMMETRIC_KEY ����ü���� ISC_RSA_UNIT�� ���� (�޸𸮰� duplicate �ǹǷ� �ݵ�� �޸� ���� �ʿ�)
* \param akey
* ASYMMETRIC_KEY ����ü ������
* \param rsa
* ISC_RSA ����ü ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS ASYMMETRIC_KEY_to_RSA_UNIT(ASYMMETRIC_KEY *akey, ISC_RSA_UNIT *rsa);

/*!
* \brief
* ASYMMETRIC_KEY ����ü���� ISC_KCDSA_UNIT�� ���� (�޸𸮰� duplicate �ǹǷ� �ݵ�� �޸� ���� �ʿ�)
* \param akey
* ASYMMETRIC_KEY ����ü ������
* \param kcdsa
* ISC_KCDSA_UNIT ����ü ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS ASYMMETRIC_KEY_to_KCDSA_UNIT(ASYMMETRIC_KEY *akey, ISC_KCDSA_UNIT *kcdsa);

/*!
 * \brief
 * ASYMMETRIC_KEY ����ü���� ISC_ECDSA_UNIT�� ���� (�޸𸮰� duplicate �ǹǷ� �ݵ�� �޸� ���� �ʿ�)
 * \param akey
 * ASYMMETRIC_KEY ����ü ������
 * \param ecdsa
 * ISC_ECDSA_UNIT ����ü ������
 * \return
 * -# ISC_SUCCESS : ����
 * -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS ASYMMETRIC_KEY_to_ECDSA_UNIT(ASYMMETRIC_KEY *akey, ISC_ECDSA_UNIT *ecdsa);
    
/*!
* \brief
* ISC_RSA Ű�� ����Ű ����ü�� ASYMMETRIC_KEY�� ��ȯ
* \param rsa
* ISC_RSA Ű
* \param akey
* ASYMMETRIC_KEY ����ü ������ (�޸� �Ҵ� �Ǿ� �־�� ��)
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS RSA_UNIT_to_ASYMMETRIC_KEY(ISC_RSA_UNIT *rsa, ASYMMETRIC_KEY *akey);

/*!
* \brief
* ISC_KCDSA Ű�� ����Ű ����ü�� ASYMMETRIC_KEY�� ��ȯ
* \param kcdsa
* kcdsa Ű
* \param akey
* ASYMMETRIC_KEY ����ü ������ (�޸� �Ҵ� �Ǿ� �־�� ��)
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS KCDSA_UNIT_to_ASYMMETRIC_KEY(ISC_KCDSA_UNIT *kcdsa, ASYMMETRIC_KEY *akey);

/*!
 * \brief
 * ISC_ECDSA Ű�� ����Ű ����ü�� ASYMMETRIC_KEY�� ��ȯ
 * \param ecdsa
 * ecdsa Ű
 * \param akey
 * ASYMMETRIC_KEY ����ü ������ (�޸� �Ҵ� �Ǿ� �־�� ��)
 * \return
 * -# ISC_SUCCESS : ����
 * -# ISC_FAIL : ����
 */
ISC_API ISC_STATUS ECDSA_UNIT_to_ASYMMETRIC_KEY(ISC_ECDSA_UNIT *ecdsa, ASYMMETRIC_KEY *akey);

/*!
 * \brief
 * ISC_ECC_KEY_UNIT ����ü�� ����ü�� ASYMMETRIC_KEY�� ��ȯ
 * \param ec_key
 * ISC_ECC_KEY_UNIT ����ü
 * \param akey
 * ASYMMETRIC_KEY ����ü ������ (�޸� �Ҵ� �Ǿ� �־�� ��)
 * \returns
 * -# ISC_SUCCESS : ����
 * -# ISC_FAIL : ����
 */
ISC_STATUS ECC_KEY_UNIT_to_ASYMMETRIC_KEY(ISC_ECC_KEY_UNIT *ec_key, ASYMMETRIC_KEY *akey);

/*!
* \brief
* �������� ����Ű�� ����Ű�� Ű�� ����
* \param x509_pkey
* ����Ű
* \param key
* ASYMMETRIC_KEY ����ü ������
* \return
* -# ISC_SUCCESS : Ű��� ��ġ
* -# ISC_FAIL : Ű��� ����ġ
*/
ISC_API ISC_STATUS check_X509_keypair(X509_PUBKEY* x509_pkey, ASYMMETRIC_KEY* key);

/*!
* \brief
* ����Ű�� ���Ű�� Ű�� ����
* \param rsa1
* Ű 1
* \param rsa2
* Ű 2
* \return
* -# 1 : Ű��� ��ġ
* -# ISC_FAIL : Ű��� ����ġ
*/
ISC_API ISC_STATUS check_X509_RSA_keypair(ISC_RSA_UNIT* rsa1, ISC_RSA_UNIT* rsa2);

/*!
* \brief
* ����Ű�� ���Ű�� Ű�� ����
* \param kcdsa1
* Ű 1
* \param kcdsa2
* Ű 2
* \return
* -# 1 : Ű��� ��ġ
* -# ISC_FAIL : Ű��� ����ġ
*/
ISC_API ISC_STATUS check_X509_KCDSA_keypair(ISC_KCDSA_UNIT* kcdsa1, ISC_KCDSA_UNIT* kcdsa2);

/*!
 * \brief
 * ����Ű�� ���Ű�� Ű�� ����
 * \param ecdsa1
 * Ű 1
 * \param ecdsa2
 * Ű 2
 * \return
 * -# 1 : Ű��� ��ġ
 * -# ISC_FAIL : Ű��� ����ġ
 */
ISC_API ISC_STATUS check_X509_ECDSA_keypair(ISC_ECDSA_UNIT* ecdsa1, ISC_ECDSA_UNIT* ecdsa2);

/*!
* \brief
* X509_EXTENSION ����ü�� �ʱ�ȭ �Լ�
* \returns
* X509_EXTENSION ����ü ������
*/
ISC_API X509_EXTENSION* new_X509_EXTENSION();

/*!
* \brief
* X509_EXTENSION ����ü�� �޸� �Ҵ� ����
* \param ext
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_X509_EXTENSION(X509_EXTENSION* ext);
/*!
* \brief
* X509_EXTENSION ����ü�� ����
* \param ext
* ������ ����ü ������
* \return
* X509_EXTENSION ����ü ������
*/
ISC_API X509_EXTENSION* dup_X509_EXTENSION(X509_EXTENSION *ext);

/*!
* \brief
* X509_EXTENSIONS ����ü�� �ʱ�ȭ �Լ�
* \returns
* X509_EXTENSIONS ����ü ������
*/
ISC_API X509_EXTENSIONS *new_X509_EXTENSIONS(void);

/*!
* \brief
* X509_EXTENSIONS ����ü�� �޸� �Ҵ� ����
* \param exts
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_X509_EXTENSIONS(X509_EXTENSIONS *exts);

/*!
* \brief
* X509_EXTENSIONS�� ��� �ִ� X509_EXTENSION�� ���� ��ȯ
* \param exts
* X509_EXTENSIONS ����ü ������
* \return
* ����
*/
ISC_API int get_X509_EXTENSION_count(const X509_EXTENSIONS *exts);

/*!
* \brief
* X509_EXTENSIONS����ü�� OBJECT_IDENTIFIER�� ��ġ�ϴ� �ε����� lastpos���� �˻�
* \param exts
* X509_EXTENSIONS ����ü ������
* \param *obj
* OBJECT_IDENTIFIER ����ü ������
* \param lastpos
* �ε��� (default = -1)
* \return
* -# oid�� ��ġ�ϴ� �ε���
* -# oid�� ��ġ�ϴ� �ε����� ������� -1
*/
ISC_API int get_X509_EXTENSION_index_by_OID(const X509_EXTENSIONS *exts, OBJECT_IDENTIFIER *obj, int lastpos);

/*!
* \brief
* X509_EXTENSIONS����ü�� oid_index�� ��ġ�ϴ� �ε����� lastpos���� �˻�
* \param exts
* X509_EXTENSIONS ����ü ������
* \param OID_index
* OID_index ��
* \param lastpos
* �ε��� (default = -1)
* \return
* -# oid�� ��ġ�ϴ� �ε���
* -# oid�� ��ġ�ϴ� �ε����� ������� -1
*/
ISC_API int get_X509_EXTENSION_index_by_OID_index(const X509_EXTENSIONS *exts, int OID_index, int lastpos);

/*!
* \brief
* X509_EXTENSIONS����ü�� loc�� ��ġ�� X509_EXTENSION�� ������ ��ȯ
* \param exts
* X509_EXTENSIONS ����ü ������
* \param loc
* �ε���
* \return
* X509_EXTENSION ����ü ������
*/
ISC_API X509_EXTENSION *get_X509_EXTENSION(const X509_EXTENSIONS *exts, int loc);

/*!
* \brief
* X509_EXTENSIONS����ü�� loc�� ��ġ�� X509_EXTENSION�� ����
* \param exts
* X509_EXTENSIONS ����ü ������
* \param loc
* �ε���
* \return
* ������ X509_EXTENSION ����ü ������
*/
ISC_API X509_EXTENSION *remove_X509_EXTENSION(X509_EXTENSIONS *exts, int loc);

/*!
* \brief
* X509_EXTENSIONS����ü�� loc�� ��ġ�� X509_EXTENSION�� ����
* \param exts
* X509_EXTENSIONS ����ü ������
* \param ex
* X509_EXTENSION ����ü ������
* \param loc
* �ε���
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_X509_EXTENSION(X509_EXTENSIONS **exts, X509_EXTENSION *ex, int loc);

/*!
* \brief
* X509_EXTENSION�� OID�� �Է�(dup)
* \param ex
* X509_EXTENSION ����ü ������
* \param obj
* OBJECT_IDENTIFIER ����ü ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_EXTENSION_object(X509_EXTENSION *ex, OBJECT_IDENTIFIER *obj);

/*!
* \brief
* X509_EXTENSION�� Critical ���θ� �Է�
* \param ex
* X509_EXTENSION ����ü ������
* \param crit
* critical : 0�� �ƴ� ����, non-critical : 0
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_EXTENSION_critical(X509_EXTENSION *ex, int crit);

/*!
* \brief
* X509_EXTENSION�� Value�� �Է�
* \param ex
* X509_EXTENSION ����ü ������
* \param data
* OCTET_STRING���� Encoding �� ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_EXTENSION_data(X509_EXTENSION *ex, OCTET_STRING *data);

/*!
* \brief
* X509_EXTENSION�� ������ ������ �¿� ���� ����
* \param ex
* X509_EXTENSION ������
* \param obj
* OBJECT_IDENTIFIER ����ü ������
* \param crit
* ciritical ����
* \param data
* ����� ������
* \return
* ������ X509_EXTENSION ����ü ������
*/
ISC_API X509_EXTENSION *create_X509_EXTENSION_by_OID(X509_EXTENSION **ex, OBJECT_IDENTIFIER *obj, int crit, OCTET_STRING *data);

/*!
* \brief
* X509_EXTENSION�� ������ ������ �¿� ���� ����
* \param ex
* X509_EXTENSION ������
* \param index
* OID_index(asn1_object.h)
* \param crit
* ciritical ����
* \param data
* ����� ������
* \return
* ������ X509_EXTENSION ����ü ������
*/
ISC_API X509_EXTENSION *create_X509_EXTENSION_by_OID_index(X509_EXTENSION **ex, int index,int crit, OCTET_STRING *data);

/*!
* \brief
* X509_EXTENSION�� ������ OBJECT_IDENTIFIER ��ȯ
* \param ex
* X509_EXTENSION ������
* \return
* OBJECT_IDENTIFIER ����ü ������
*/
ISC_API OBJECT_IDENTIFIER *get_X509_EXTENSION_object(X509_EXTENSION *ex);
/*!
* \brief
* X509_EXTENSION�� ������ data ��ȯ
* \param ex
* X509_EXTENSION ������
* \return
* OCTET_STRING ����ü ������
*/
ISC_API OCTET_STRING *get_X509_EXTENSION_data(X509_EXTENSION *ex);

/*!
* \brief
* X509_EXTENSION�� ������ criticial ���� ��ȯ
* \param ex
* X509_EXTENSION ������
* \return
* -# 1 : critical
* -# 0 : non-critical
*/
ISC_API int get_X509_EXTENSION_critical(X509_EXTENSION *ex);

/*!
* \brief
* X509_ATTRIBUTE_DATA ����ü�� �ʱ�ȭ �Լ�
* \returns
* X509_ATTRIBUTE_DATA ����ü ������
*/
ISC_API X509_ATTRIBUTE_DATA *new_X509_ATTRIBUTE_DATA();

/*!
* \brief
* X509_ATTRIBUTE_DATA ����ü�� �޸� �Ҵ� ����
* \param attrData
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_X509_ATTRIBUTE_DATA(X509_ATTRIBUTE_DATA *attrData);

/*!
* \brief
* X509_ATTRIBUTE_DATA ����ü�� ����
* \param attrData
* ������ ����ü ������
* \return
* X509_ATTRIBUTE ����ü ������
*/
ISC_API X509_ATTRIBUTE_DATA* dup_X509_ATTRIBUTE_DATA(X509_ATTRIBUTE_DATA *attrData);

/*!
* \brief
* X509_ATTRIBUTE ����ü�� �ʱ�ȭ �Լ�
* \returns
* X509_ATTRIBUTE ����ü ������
*/
ISC_API X509_ATTRIBUTE* new_X509_ATTRIBUTE();

/*!
* \brief
* X509_ATTRIBUTE ����ü�� �޸� �Ҵ� ����
* \param attribute
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_X509_ATTRIBUTE(X509_ATTRIBUTE* attribute);

/*!
* \brief
* X509_ATTRIBUTE ����ü�� ����
* \param attribute
* ������ ����ü ������
* \return
* X509_ATTRIBUTE ����ü ������
*/
ISC_API X509_ATTRIBUTE* dup_X509_ATTRIBUTE(X509_ATTRIBUTE *attribute);

/*!
* \brief
* X509_ATTRIBUTES ����ü�� �ʱ�ȭ �Լ�
* \returns
* X509_ATTRIBUTES ����ü ������
*/
ISC_API X509_ATTRIBUTES* new_X509_ATTRIBUTES();

/*!
* \brief
* X509_ATTRIBUTES ����ü�� �޸� �Ҵ� ����
* \param atts
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_X509_ATTRIBUTES(X509_ATTRIBUTES* atts);

/*!
* \brief
* X509_ATTRIBUTES ����ü�� ����
* \param src
* ������ ����ü ������
* \return
* X509_ATTRIBUTES ����ü ������
*/
ISC_API X509_ATTRIBUTES * dup_X509_ATTRIBUTES(X509_ATTRIBUTES * src); 

/*!
* \brief
* X509_ATTRIBUTE�� OID�� ����
* 
* \param attr
* X509_ATTRIBUTE ����ü ������
* 
* \param obj
* OBJECT_IDENTIFIER ����ü ������
* 
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_ATTRIBUTE_OID(X509_ATTRIBUTE *attr, OBJECT_IDENTIFIER *obj);

/*!
* \brief
* X509_ATTRIBUTE�� �����͸� ����
* 
* \param attr
* X509_ATTRIBUTE ����ü ������
* 
* \param type
* �����Ǵ� �������� ASN1 Ÿ��
* \param data
* ASN1 Ÿ�� ������(ASN1_UNIT or ASN1_STRING)
* \param len
* �������� ����
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_X509_ATTRIBUTE_data(X509_ATTRIBUTE *attr, int type, void *data);

/*!
* \brief
* X509_ATTRIBUTE����ü ���� set�� �����͸� �߰�
* \param attr
* X509_ATTRIBUTE ����ü ������
* \param data
* ������
* \param loc
* ����� ��ġ (default : -1)
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_X509_ATTRIBUTE_set(X509_ATTRIBUTE *attr, ASN1_STRING *data, int loc);


/*!
* \brief
* X509_ATTRIBUTE�� OID�� ��ȯ
* \param attr
* X509_ATTRIBUTE ����ü ������
* \returns
* OBJECT_IDENTIFIER ����ü ������
*/
ISC_API OBJECT_IDENTIFIER *get_X509_ATTRIBUTE_OID(X509_ATTRIBUTE *attr);

/*!
* \brief
* X509_ATTRIBUTE�� ����ִ� idx��° ������ Ÿ�Ը� ��ȯ
* \param attr
* X509_ATTRIBUTE ����ü ������
* \param idx
* �ε���
* \returns
* ��ȯ ������
*/
ISC_API int get_X509_ATTRIBUTE_data_type(X509_ATTRIBUTE *attr, int idx);

/*!
* \brief
* X509_ATTRIBUTE�� ����ִ� idx��° �����͸� ��ȯ
* \param attr
* X509_ATTRIBUTE ����ü ������
* \param idx
* �ε���
* \returns
* ��ȯ ������
*/
ISC_API void *get_X509_ATTRIBUTE_data(X509_ATTRIBUTE *attr, int idx);

/*!
* \brief
* X509_ATTRIBUTE�� ����ִ� �������� ������ ��ȯ
* \param attr
* X509_ATTRIBUTE ����ü ������
* \returns
* ����
*/
ISC_API int get_X509_ATTRIBUTE_count(X509_ATTRIBUTE *attr);

/*!
* \brief
* X509_ATTRIBUTES�� ����ִ� X509_ATTRIBUTE ������ ��ȯ
* \param attr
* X509_ATTRIBUTES ����ü ������
* \returns
* ����
*/
ISC_API int get_X509_ATTRIBUTES_count(X509_ATTRIBUTES *attr);

/*!
* \brief
* X509_ATTRIBUTES�� loc ��°�� X509_ATTRIBUTE ��ȯ
* \param attr
* X509_ATTRIBUTES ����ü ������
* \param loc
* �ε���
* \returns
* X509_ATTRIBUTE ����ü ������
*/
ISC_API X509_ATTRIBUTE *get_X509_ATTRIBUTES_child(X509_ATTRIBUTES *attr, int loc);



/*!
* \brief
* X509_ATTRIBUTE�� ������ ������ �¿� ���� ����
* \param attr
* X509_EXTENSION ������
* \param oid_index
* oid index
* \param type
* ����Ǵ� �������� asn1_type
* \param data
* ����Ǵ� asn1 ����ü ������(ASN1_UNIT or ASN1_STRING)
* \return
* ������ X509_ATTRIBUTE ����ü ������
*/
ISC_API X509_ATTRIBUTE *create_X509_ATTRIBUTE_index(X509_ATTRIBUTE **attr, int oid_index, int type, void *data);

/*!
* \brief
* X509_ATTRIBUTE�� ������ ������ �¿� ���� ����
* \param attr
* X509_EXTENSION ������
* \param obj
* OBJECT_IDENTIFIER ����ü ������
* \param type
* ����Ǵ� �������� asn1_type
* \param data
* ����Ǵ� asn1 ����ü ������(ASN1_UNIT or ASN1_STRING)
* \return
* ������ X509_ATTRIBUTE ����ü ������
*/
ISC_API X509_ATTRIBUTE *create_X509_ATTRIBUTE_OID(X509_ATTRIBUTE **attr, OBJECT_IDENTIFIER *obj, int type, void *data);


/*!
* \brief
* X509_ATTRIBUTES����ü�� X509_ATTRIBUTE�� ����
* \param attrs
* X509_ATTRIBUTES ����ü ������
* \param attr
* ���Ե� X509_ATTRIBUTE ����ü ������
* \param loc
* ����� ��ġ (default : -1)
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_X509_ATTRIBUTES_child(X509_ATTRIBUTES *attrs, X509_ATTRIBUTE *attr, int loc);

/*!
* \brief
* X509_ATTRIBUTES����ü�� ������ �����ͷ� X509_ATTRIBUTE�� �����Ͽ� ����
* \param attrs
* X509_ATTRIBUTES ����ü ������
* \param obj
* OBJECT_IDENTIFIER ����ü ������
* \param type
* ����Ǵ� �������� asn1 type
* \param data
* ����Ǵ� asn1 ����ü ������(ASN1_UNIT or ASN1_STRING)
* \param loc
* ����� ��ġ (default : -1)
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_X509_ATTRIBUTES_child_OID(X509_ATTRIBUTES *attrs, OBJECT_IDENTIFIER *obj, int type, void *data, int loc);

/*!
* \brief
* X509_ATTRIBUTES����ü�� ������ �����ͷ� X509_ATTRIBUTE�� �����Ͽ� ����
* \param attrs
* X509_ATTRIBUTES ����ü ������
* \param oid_ind
* oid �ε���
* \param type
* ����Ǵ� �������� asn1 type
* \param data
* ����Ǵ� asn1 ����ü ������(ASN1_UNIT or ASN1_STRING)
* \param loc
* ����� ��ġ (default : -1)
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_X509_ATTRIBUTES_OID_INDEX(X509_ATTRIBUTES *attrs, int oid_ind, int type, void *data, int loc);

/*!
* \brief
* X509_CERT ����ü�� Sequence�� Encode �Լ�
* \param st
* X509_CERT ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_X509_CERT_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_CERT_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_TBS_CERT_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS X509_CERT_to_Seq (X509_CERT *st, SEQUENCE **seq);

/*!
* \brief
* X509_TBS_CERT ����ü�� Sequence�� Encode �Լ�
* \param st
* X509_TBS_CERT ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_X509_TBS_CERT_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_TBS_CERT_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# LOCATION^F_X509_TBS_CERT_TO_SEQ^ERR_TBS_CERT_SERIAL : �ø��� ������ ����
* -# LOCATION^F_X509_TBS_CERT_TO_SEQ^ERR_TBS_CERT_SIGNATURE : ����˰��� ������ ����
* -# LOCATION^F_X509_TBS_CERT_TO_SEQ^ERR_TBS_CERT_ISSUER : �߱��� ������ ����
* -# LOCATION^F_X509_TBS_CERT_TO_SEQ^ERR_TBS_CERT_VALIDITY : ��ȿ�Ⱓ ������ ����
* -# LOCATION^F_X509_TBS_CERT_TO_SEQ^ERR_TBS_CERT_SUBJECT : ��ü�� ������ ����
* -# LOCATION^F_X509_TBS_CERT_TO_SEQ^ERR_TBS_CERT_SPKI : ����Ű ������ ����
* -# X509_PUBKEY_to_Seq()�� ���� �ڵ�\n
* -# X509_EXTENSIONS_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS X509_TBS_CERT_to_Seq (X509_TBS_CERT *st, SEQUENCE **seq);

/*!
* \brief
* X509_EXTENSIONS ����ü�� Sequence�� Encode �Լ�
* \param st
* X509_EXTENSIONS ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_X509_EXT_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_EXT_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_PUBKEY_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS X509_EXTENSIONS_to_Seq(X509_EXTENSIONS *st, SEQUENCE **seq);

/*!
* \brief
* X509_NAME ����ü�� Sequence�� Encode �Լ�
* \param st
* X509_NAME ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_X509_NAME_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_NAME_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS X509_NAME_to_Seq(X509_NAME *st, SEQUENCE **seq);

/*!
* \brief
* X509_PUBKEY ����ü�� Sequence�� Encode �Լ�
* \param st
* X509_PUBKEY ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_X509_PUBKEY_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_PUBKEY_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS X509_PUBKEY_to_Seq(X509_PUBKEY *st, SEQUENCE **seq);

/*!
* \brief
* X509_PUBKEY ����ü�� Sequence�� Encode �Լ�
* \param st
* X509_PUBKEY ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_X509_CERT_PAIR_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_CERT_PAIR_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_CERT_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS X509_CERT_PAIR_to_Seq(X509_CERT_PAIR* st, SEQUENCE** seq);


/*!
* \brief
* Sequence�� X509_CERT ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param st
* X509_CERT ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_X509_CERT^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_SEQ_TO_X509_CERT^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_TBS_CERT()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_X509_CERT (SEQUENCE *seq, X509_CERT** st);

/*!
* \brief
* Sequence�� X509_TBS_CERT ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param st
* X509_TBS_CERT ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_X509_TBS_CERT^ISC_ERR_NULL_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_TBS_CERT^ISC_ERR_INVALID_INPUT : Invalid Input
* -# LOCATION^F_SEQ_TO_X509_TBS_CERT^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_EXTENSIONS()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_X509_TBS_CERT (SEQUENCE *seq, X509_TBS_CERT** st);

/*!
* \brief
* Sequence�� X509_EXTENSIONS ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param st
* X509_EXTENSIONS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_X509_EXT^ISC_ERR_NULL_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_EXT^ISC_ERR_INVALID_INPUT : Invalid Input
* -# LOCATION^F_SEQ_TO_X509_EXT^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_EXTENSIONS()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_X509_EXTENSIONS(SEQUENCE *seq, X509_EXTENSIONS **st);

/*!
* \brief
* Sequence�� X509_NAME ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param st
* X509_NAME ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_X509_NAME^ISC_ERR_NULL_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_NAME^ISC_ERR_INVALID_INPUT : Invalid Input
* -# LOCATION^F_SEQ_TO_X509_NAME^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_X509_NAME(SEQUENCE *seq, X509_NAME **st);

/*!
* \brief
* Sequence�� X509_PUBKEY ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param st
* X509_PUBKEY ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_X509_PUBKEY^ISC_ERR_NULL_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_PUBKEY^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_X509_PUBKEY(SEQUENCE *seq, X509_PUBKEY **st);

/*!
* \brief
* Sequence�� X509_CERT_PAIR ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param st
* X509_CERT_PAIR ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_X509_CERT_PAIR^ISC_ERR_INVALID_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_CERT_PAIR^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_X509_CERT_PAIR(SEQUENCE* seq, X509_CERT_PAIR** st);

/*!
* \brief
* X509_CERTS ����ü�� �ʱ�ȭ �Լ�
* \returns
* X509_CERTS ����ü ������
*/
ISC_API X509_CERTS *new_X509_CERTIFICATES();

/*!
* \brief
* X509_CERTS ����ü�� �޸� �Ҵ� ����
* \param x509Certificates
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_X509_CERTIFICATES(X509_CERTS *x509Certificates);

/*!
* \brief
* X509_CERTS ���ÿ��� X509_CERT�� ��ġ�ϴ� �ε����� �˻�
* \param x509Certificates
* X509_CERTS ���� ������
* \param cert
* X509_CERT ����ü ������
* \return
* -# cert�� ��ġ�ϴ� �ε���
* -# cert�� ��ġ�ϴ� �ε����� ������� -1
*/
ISC_API int get_X509_CERTS_index_by_X509_CERT(X509_CERTS *x509Certificates, X509_CERT *cert);

/*!
* \brief
* X509_CERTS ����ü�� Sequence�� Encode �Լ�
* \param st
* X509_CERTS ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_X509_CERTIFICATES_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_CERTIFICATES_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_CERT_to_Seq()�� ���� �ڵ�
*/
ISC_API ISC_STATUS X509_CERTIFICATES_to_Seq(X509_CERTS *st, SEQUENCE **seq);

/*!
* \brief
* Sequence�� X509_CERTS ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param st
* X509_CERTS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_X509_CERTIFICATES^ISC_ERR_INVALID_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_CERTIFICATES^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_CERT()�� ���� �ڵ�
*/
ISC_API ISC_STATUS Seq_to_X509_CERTIFICATES(SEQUENCE *seq, X509_CERTS **st);

/*!
* \brief
* X509_CERTS ���ÿ� X509_CERT�� �߰�
* \param certs
* X509_CERTS ���� ������
* \param cert
* �߰��� X509_CERT ����ü ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_X509_CERTIFICATES(X509_CERTS *certs, X509_CERT *cert);

/*!
* \brief
* X509_CERTS ���� ��� �������� ������ ���
* \param certs
* X509_CERTS ����ü
*/
ISC_API void print_X509_CERTIFICATES(X509_CERTS *certs);

/*!
* \brief
* Sequence�� X509_ATTRIBUTE ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param st
* X509_ATTRIBUTE ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_X509_ATTRIBUTE^ISC_ERR_INVALID_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_ATTRIBUTE^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_X509_ATTRIBUTE(SEQUENCE *seq, X509_ATTRIBUTE **st);

/*!
* \brief
* Sequence�� X509_ATTRIBUTES ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param st
* X509_ATTRIBUTES ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_X509_ATTRIBUTES^ISC_ERR_INVALID_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_ATTRIBUTES^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_X509_ATTRIBUTES(SEQUENCE *seq, X509_ATTRIBUTES **st);

/*!
* \brief
* X509_ATTRIBUTE ����ü�� Sequence�� Encode �Լ�
* \param st
* X509_ATTRIBUTE ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_X509_ATTRIBUTE_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_ATTRIBUTE_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_CERT_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS X509_ATTRIBUTE_to_Seq(X509_ATTRIBUTE *st, SEQUENCE **seq);

/*!
* \brief
* X509_ATTRIBUTES ����ü�� Sequence�� Encode �Լ�
* \param st
* X509_ATTRIBUTES ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_X509_ATTRIBUTES_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_ATTRIBUTES_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_ATTRIBUTE_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS X509_ATTRIBUTES_to_Seq(X509_ATTRIBUTES *st, SEQUENCE **seq);



/*!
* \brief
* ISC_RSA_UNIT ����ü�� BitString Ÿ������ Encode �Լ�
* \param st
* ISC_RSA_UNIT ����ü
* \param bit_string
* BIT_STRING ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_RSA_KEY_to_BITSTRING^ISC_ERR_INVALID_INPUT : �߸��� Ű ����
* -# LOCATION^F_RSA_KEY_to_BITSTRING^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS RSA_KEY_to_BITSTRING(ISC_RSA_UNIT *st, BIT_STRING **bit_string);

/*!
* \brief
* ISC_KCDSA_UNIT ����ü�� BitString Ÿ������ Encode �Լ�
* \param st
* ISC_KCDSA_UNIT ����ü
* \param bit_string
* BIT_STRING ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_KCDSA_KEY_to_BITSTRING^ERR_ASN1_ENCODING : ASN1 Err
*/
ISC_API ISC_STATUS KCDSA_KEY_to_BITSTRING(ISC_KCDSA_UNIT *st, BIT_STRING **bit_string);

/*!
* \brief
* BIT_STRING�� ISC_RSA_UNIT ����ü�� Decode �Լ�
* \param bit_string
* Decoding BIT_STRING ����ü
* \param st
* ISC_RSA_UNIT ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_BITSTRING_to_RSA_KEY^ERR_ASN1_DECODING : ASN1 Err
* -# LOCATION^F_BITSTRING_to_RSA_KEY^ISC_ERR_INVALID_INPUT : Invalid Input
*/
ISC_API ISC_STATUS BITSTRING_to_RSA_KEY(BIT_STRING *bit_string, ISC_RSA_UNIT **st);


/*!
* \brief
* BIT_STRING�� ISC_KCDSA_UNIT ����ü�� Decode �Լ�
* \param bit_string
* Decoding BIT_STRING ����ü
* \param st
* ISC_KCDSA_UNIT ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_BITSTRING_to_KCDSA_KEY^ERR_ASN1_DECODING : ASN1 Err
* -# LOCATION^F_BITSTRING_to_KCDSA_KEY^ISC_ERR_INVALID_INPUT : Invalid Input
*/
ISC_API ISC_STATUS BITSTRING_to_KCDSA_KEY(BIT_STRING *bit_string, ISC_KCDSA_UNIT **st);

/*!
* \brief
* ISC_RSA_UNIT ����ü�� Sequence�� Encode �Լ�
* \param st
* ISC_RSA_UNIT ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_RSA_KEY_to_Seq^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_RSA_KEY_to_Seq^ERR_ASN1_ENCODING : ASN1 Err
* -# RSA_KEY_to_BITSTRING()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS RSA_KEY_to_Seq(ISC_RSA_UNIT *st, SEQUENCE **seq);

/*!
* \brief
* Sequence�� ISC_RSA_UNIT ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param st
* ISC_RSA_UNIT ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_Seq_to_RSA_KEY^ISC_ERR_INVALID_INPUT : Null Input
* -# LOCATION^F_Seq_to_RSA_KEY^ERR_ASN1_DECODING : ASN1 Err
* -# BITSTRING_to_RSA_KEY()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_RSA_KEY(SEQUENCE *seq, ISC_RSA_UNIT **st);

/*!
* \brief
* ISC_KCDSA_UNIT ����ü�� Sequence�� Encode �Լ�
* \param st
* ISC_KCDSA_UNIT ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_KCDSA_KEY_to_Seq^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_KCDSA_KEY_to_Seq^ERR_ASN1_ENCODING : ASN1 Err
* -# KCDSA_KEY_to_BITSTRING()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS KCDSA_KEY_to_Seq(ISC_KCDSA_UNIT *st, SEQUENCE **seq);

/*!
* \brief
* Sequence�� ISC_KCDSA_UNIT ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param st
* ISC_KCDSA_UNIT ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_Seq_to_KCDSA_KEY^ISC_ERR_INVALID_INPUT : Null Input
* -# LOCATION^F_Seq_to_KCDSA_KEY^ERR_ASN1_DECODING : ASN1 Err
* -# BITSTRING_to_KCDSA_KEY()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_KCDSA_KEY(SEQUENCE *seq, ISC_KCDSA_UNIT **st);



/*!
* \brief
* X509_ALGO_IDENTIFIER ����ü�� �ʱ�ȭ �Լ�
* \returns
* X509_ALGO_IDENTIFIER ����ü ������
*/
ISC_API X509_ALGO_IDENTIFIER *new_X509_ALGO_IDENTIFIER();
 
/*!
* \brief
* X509_ALGO_IDENTIFIER ����ü�� �޸� �Ҵ� ����
* \param x509Algo
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_X509_ALGO_IDENTIFIER(X509_ALGO_IDENTIFIER* x509Algo);

/*!
* \brief
* X509_ALGO_IDENTIFIER ����ü�� ����
* \param src
* ������ ����ü ������
* \return
* X509_ALGO_IDENTIFIER ����ü ������
*/
ISC_API X509_ALGO_IDENTIFIER* dup_X509_ALGO_IDENTIFIER(X509_ALGO_IDENTIFIER* src);


/* algID�� null�̸� fail, params�� NULL�̸� NULL Type�� ���õ� */
/*!
* \brief
* X509_ALGO_IDENTIFIER ����ü�� OBJECT_IDENTIFIER�� �˰��� Parameter�� �Է�(Null Parameter�� ��� NULL�� �Է�)
* \param x509Algo
* X509 �˰��� Identifier
* \param alg_id
* �˰��� Identifier
* \param params
* �˰��� Parameter
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_ALGO_IDENTIFIER_value(X509_ALGO_IDENTIFIER* x509Algo, OBJECT_IDENTIFIER* alg_id, ASN1_STRING* params);

/*!
* \brief
* X509_ALGO_IDENTIFIERS ����ü�� �ʱ�ȭ �Լ�
* \returns
* X509_ALGO_IDENTIFIERS ����ü ������
*/
ISC_API X509_ALGO_IDENTIFIERS *new_X509_ALGO_IDENTIFIERS();

/*!
* \brief
* X509_ALGO_IDENTIFIERS ����ü�� �޸� �Ҵ� ����
* \param x509Algos
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_X509_ALGO_IDENTIFIERS(X509_ALGO_IDENTIFIERS *x509Algos);

/*!
* \brief
* X509_ALGO_IDENTIFIERS ����ü�� ����
* \param src
* ������ ����ü ������
* \return
* X509_ALGO_IDENTIFIERS ����ü ������
*/
ISC_API X509_ALGO_IDENTIFIERS *dup_X509_ALGO_IDENTIFIERS(X509_ALGO_IDENTIFIERS* src);

/*!
* \brief
* X509_ALGO_IDENTIFIER ����ü�� Sequence�� Encode �Լ�
* \param st
* X509_ALGO_IDENTIFIER ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_X509_ALGO_IDENTIFIER_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_ALGO_IDENTIFIER_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_CERT_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS X509_ALGO_IDENTIFIER_to_Seq(X509_ALGO_IDENTIFIER *st, SEQUENCE **seq);

/*!
* \brief
* Sequence�� X509_ALGO_IDENTIFIER ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param st
* X509_ALGO_IDENTIFIER ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_X509_ALGO_IDENTIFIER^ISC_ERR_INVALID_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_ALGO_IDENTIFIER^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_X509_ALGO_IDENTIFIER(SEQUENCE *seq, X509_ALGO_IDENTIFIER **st);

/*!
* \brief
* X509_ALGO_IDENTIFIERS ����ü�� Sequence�� Encode �Լ�
* \param st
* X509_ALGO_IDENTIFIERS ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_X509_ALGO_IDENTIFIERS_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_ALGO_IDENTIFIERS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_CERT_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS X509_ALGO_IDENTIFIERS_to_Seq(X509_ALGO_IDENTIFIERS *st, SET_OF **seq);

/*!
* \brief
* Sequence�� X509_ALGO_IDENTIFIERS ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param st
* X509_ALGO_IDENTIFIERS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_X509_ALGO_IDENTIFIERS^ISC_ERR_INVALID_INPUT : Null Input
* -# LOCATION^F_SEQ_TO_X509_ALGO_IDENTIFIERS^ERR_ASN1_DECODING : ASN1 Err
*/
ISC_API ISC_STATUS Seq_to_X509_ALGO_IDENTIFIERS(SET_OF *seq, X509_ALGO_IDENTIFIERS **st);


/* PKCS12 ���� �Լ� */
ISC_API X509_AUX *new_X509_AUX();
ISC_API void free_X509_AUX(X509_AUX* x509aux);
ISC_API X509_AUX* dup_X509_AUX(X509_AUX* src);
ISC_API ISC_STATUS set_X509_AUX_localkey (X509_CERT* x509, uint8 *keyid, int keyidLen);
ISC_API uint8 * get_X509_AUX_localkey (X509_CERT *x509, int *len);
ISC_API ISC_STATUS set_X509_AUX_friendly (X509_CERT* x509, uint8 *friendly, int friendlyLen);
ISC_API uint8 * get_X509_AUX_friendly (X509_CERT *x509, int *len);



/*!
* \brief
* �������� �ؽ���(�յ���)�� ���ϴ� �Լ�
* \param cert
* X509_CERT ����ü
* \param alg_id
* �ؽ� �˰��� (ISC_SHA1 or ISC_MD5, ISC_HAS160, ..)
* \param md
* ��ȯ�Ǵ� �ؽ��� (�ܺ� �Ҵ� �ʿ�)
* \param len
* ��ȭ�Ǵ� �ؽ����� ����
* \return
* -# ISC_SUCCESS : ����\n
* -# X509_CERT_to_Seq�� �����ڵ�\n
* -# ISC_DIGEST�� �����ڵ�
*/
ISC_API ISC_STATUS X509_CERT_digest(const X509_CERT *cert, const int alg_id, uint8 *md, int *len);

/*!
* \brief
* X509_CERT ����ü�� ����
* \param src
* ������ ����ü ������
* \return
* X509_CERT ����ü ������
*/
ISC_API X509_CERT * dup_X509_CERT(X509_CERT * src);

/*!
* \brief
* X509_EXTENSIONS ����ü�� ����
* \param src
* ������ ����ü ������
* \return
* X509_EXTENSIONS ����ü ������
*/
ISC_API X509_EXTENSIONS * dup_X509_EXTENSIONS(X509_EXTENSIONS * src);

/*!
* \brief
* X509_CERT �������� ������ ���
* \param cert
* X509_CERT ����ü
*/
ISC_API void print_X509(X509_CERT *cert);

/*!
* \brief
* X509_PUBKEY�� �����ϴ� ���
* \param ������ ���� X509_PUBKEY* pkey
* \return ����� X509_PUBKEY* 
*/
ISC_API X509_PUBKEY* dup_X509_PUBKEY(X509_PUBKEY* pkey);

/*!
* \brief
* X509_PUBKEY ����ü�� ��
* \param a
* X509_PUBKEY ����ü ������
* \param b
* X509_PUBKEY ����ü ������
* \return
* -# 0 : ������ ���
* -# -1 : ���� ���� ���
* -# ISC_FAIL : ����
*/
ISC_API int cmp_X509_PUBKEY(X509_PUBKEY* a, X509_PUBKEY* b);

/*!
* \brief
* X509_SIGN ����ü�� �ʱ�ȭ �Լ�
* \returns
* X509_SIGN ����ü ������
*/
ISC_API X509_SIGN* new_X509_SIGN();

/*!
* \brief
* X509_SIGN ����ü�� �޸� �Ҵ� ����
* \param sign
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
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

