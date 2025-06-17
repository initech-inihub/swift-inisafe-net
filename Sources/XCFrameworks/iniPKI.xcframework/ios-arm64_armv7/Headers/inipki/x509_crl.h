/*!
* \file x509_crl.h
* \brief X509_CRL
* ���ڼ��� ������ ȿ������ �� ������� ��������
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
* X509 ����� ������ ��� �ִ� ����ü
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
* X509_REVOKED�� ���� ����ü
*/
typedef STK(X509_REVOKED) X509_REVOKED_LIST; 

/*!
* \brief
* X509_CRL�� �⺻�ʵ�
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
* ������ ȿ������ �� ����� �������� ����ü
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
* X509_CRL�� ���� ����ü
*/
typedef STK(X509_CRL) X509_CRLS;

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* X509_CRL ����ü�� �ʱ�ȭ �Լ�
* \returns
* X509_CRL ����ü ������
*/
ISC_API X509_CRL *new_X509_CRL(void);
/*!
* \brief
* X509_CRL ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_X509_CRL(X509_CRL *unit);
/*!
* \brief
* X509_CRL ����ü�� ����
* \param unit
* ������ X509_CRL ����ü
*/
ISC_API void clean_X509_CRL(X509_CRL *unit);

/*!
* \brief
* X509_CRL_INFO ����ü�� �ʱ�ȭ �Լ�
* \returns
* X509_CRL_INFO ����ü ������
*/
ISC_API X509_CRL_INFO *new_X509_CRL_INFO(void);
/*!
* \brief
* X509_CRL_INFO ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_X509_CRL_INFO(X509_CRL_INFO *unit);

/*!
* \brief
* X509_CRL ����ü�� ������ version�� �����ϱ� ���� �Լ�
* \param unit
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \param version
* ������ ����
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_CRL_version(X509_CRL *unit, uint8 version);
/*!
* \brief
* X509_CRL ����ü�� ������ OID�� �����ϱ� ���� �Լ�
* \param unit
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \param oid
* �����Ҷ� ���Ǵ� �˰��� OID
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_CRL_signature(X509_CRL *unit, OBJECT_IDENTIFIER *oid);
/*!
* \brief
* X509_CRL ����ü�� �߱��� ������ �����ϱ� ���� �Լ�
* \param unit
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \param name
* �߱��� ������ ��� �ִ� X509_NAME ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_CRL_issuer (X509_CRL *unit, X509_NAME *name);
/*!
* \brief
* X509_CRL ����ü�� �߱����ڸ� �����ϱ� ���� �Լ�
* \param unit
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \param thisUpdate
* �߱����ڸ� ��� �ִ� X509_TIME ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_CRL_thisUpdate(X509_CRL *unit, X509_TIME *thisUpdate);
/*!
* \brief
* X509_CRL ����ü�� ���� �߱����ڸ� �����ϱ� ���� �Լ�
* \param unit
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \param nextUpdate
* ���� �߱����ڸ� ��� �ִ� X509_TIME ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_CRL_nextUpdate(X509_CRL *unit, X509_TIME *nextUpdate);

/*!
* \brief
* X509_CRL ����ü�� ������ �����ϱ� ���� �Լ�
* \param unit
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \param sigValue
* ������ ��� �ִ� BIT_STRING ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_CRL_sig_value(X509_CRL *unit, BIT_STRING* sigValue);
/*!
* \brief
* X509_CRL ����ü�� ������ �� ���Ǵ� �˰����� ������ �����ϱ� ���� �Լ�
* \param unit
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \param oid
* ���� �˰��� OID
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_CRL_sig_alg(X509_CRL *unit, OBJECT_IDENTIFIER* oid);

/*!
* \brief
* X509_CRL ����ü���� version�� ��� ���� �Լ�
* \param unit
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \returns
* version
*/
ISC_API uint8 get_X509_CRL_version(X509_CRL *unit);
/*!
* \brief
* X509_CRL ����ü���� ���� �˰��� OID�� ��� ���� �Լ�
* \param unit
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \returns
* Signature OID
*/
ISC_API OBJECT_IDENTIFIER* get_X509_CRL_signature(X509_CRL *unit);
/*!
* \brief
* X509_CRL ����ü���� �߱��� ������ ��� ���� �Լ�
* \param unit
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \returns
* X509_NAME ����ü
*/
ISC_API X509_NAME* get_X509_CRL_issuer(X509_CRL *unit);
/*!
* \brief
* X509_CRL ����ü���� �߱����ڸ� ��� ���� �Լ�
* \param unit
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \returns
* X509_TIME ����ü
*/
ISC_API X509_TIME* get_X509_CRL_thisUpdate(X509_CRL *unit);
/*!
* \brief
* X509_CRL ����ü���� ���� �߱����ڸ� ��� ���� �Լ�
* \param unit
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \returns
* X509_TIME ����ü
*/
ISC_API X509_TIME* get_X509_CRL_nextUpdate(X509_CRL *unit);
/*!
* \brief
* X509_CRL ����ü���� ��� ��� ������ ��� ���� �Լ�
* \param unit
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \param loc
* �����ϰ��� �ϴ� ������� ����
* \returns
* X509_REVOKED ����ü
*/
ISC_API X509_REVOKED* get_X509_CRL_revoked(X509_CRL *unit, int loc);

/*!
* \brief
* X509_CRL ����ü�� ���� ���� �˰��� ������ ��� ���� �Լ�
* \param unit
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \returns
* OBJECT_IDENTIFIER ����ü
*/
ISC_API OBJECT_IDENTIFIER* get_X509_CRL_sig_alg(X509_CRL *unit);
/*!
* \brief
* X509_CRL ����ü�� ������ ��� ���� �Լ�
* \param unit
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \returns
* BIT_STRING ����ü
*/
ISC_API BIT_STRING* get_X509_CRL_sig_value(X509_CRL *unit);

/*!
* \brief
* X509_CRL ����ü�� X509 Ȯ���ʵ��� ������ �˱� ���� �Լ�
* \param x
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \returns
* Ȯ���ʵ��� ����
*/
ISC_API int	get_X509_CRL_ext_count(X509_CRL *x);
/*!
* \brief
* X509_CRL ����ü�� X509 Ȯ���ʵ忡�� �Է¹��� OID���� ����� index�� �˱� ���� �Լ�
* \param x
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \param obj
* ã���� �ϴ� OID
* \param lastpos
* ������ TOP
* \returns
* �ش� index
*/
ISC_API int get_X509_CRL_ext_by_OBJ(X509_CRL *x, OBJECT_IDENTIFIER *obj, int lastpos);
/*!
* \brief
* X509_CRL ����ü�� X509 Ȯ���ʵ忡�� �Է¹��� OID���� ����� index�� �˱� ���� �Լ�
* \param x
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \param OID_index
* ã���� �ϴ� OID�� index
* \param lastpos
* ������ TOP
* \returns
* �ش� index
*/
ISC_API int get_X509_CRL_ext_index_by_OID_index(X509_CRL *x, int OID_index, int lastpos);

/*!
* \brief
* X509_CRL ����ü�� �� X509 Ȯ���ʵ带 ��� ���� �Լ�
* \param x
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \param loc
* �ش� �ε���
* \returns
* X509_EXTENSION ����ü
*/
ISC_API X509_EXTENSION *get_X509_CRL_ext(X509_CRL *x, int loc);
/*!
* \brief
* X509_CRL ����ü�� �� X509 Ȯ���ʵ带 �����ϱ� ���� �Լ�
* \param x
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \param loc
* �ش� �ε���
* \returns
* ���ŵ� X509_EXTENSION ����ü
*/
ISC_API X509_EXTENSION *remove_X509_CRL_ext(X509_CRL *x, int loc);
/*!
* \brief
* X509_CRL ����ü�� X509 Ȯ���ʵ带 �߰��ϱ� ���� �Լ�
* \param x
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \param ex
* �߰��ϰ��� �ϴ� X509_EXTENSION ����ü
* \param loc
* �ش� �ε���
* \returns
* -# add_X509_EXTENSION�� �����ڵ�\n
*/
ISC_API ISC_STATUS	add_X509_CRL_ext(X509_CRL *x, X509_EXTENSION *ex, int loc);
/*!
* \brief
* X509_CRL ����ü�� ������� �����ϱ� ���� �Լ�
* \param c
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS sort_X509_CRL_revoked(X509_CRL *c);

/*!
* \brief
* X509_CRL_INFO ����ü�� Sequence�� Encode �Լ�
* \param in
* X509_CRL_INFO ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_X509_CRLINFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_X509_CRLINFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_NAME_to_Seq()�� ���� �ڵ�\n
* -# X509_EXTENSIONS_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS X509_CRL_INFO_to_Seq(X509_CRL_INFO *in, SEQUENCE **seq);
/*!
* \brief
* Sequence�� X509_CRL_INFO ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param crl_info
* X509_CRL_INFO ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_X509_CRLINFO^ISC_ERR_NULL_INPUT : Null input error
* -# LOCATION^F_SEQ_TO_X509_CRLINFO^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_X509_CRLINFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_ATTRIBUTES()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_X509_CRL_INFO(SEQUENCE *seq, X509_CRL_INFO **crl_info);

/*!
* \brief
* X509_CERT ����ü�� �������� �������� �����ϴ� �Լ�
* \param crl
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \param x
* Ȯ���� �������� ������ ����ִ� X509_CERT ����ü
* \returns
* -# 0 : CRL ����Ͽ� �������� �ʴ� ������
* -# n : ������� n��° �ִ� ������
*/
ISC_API int verify_CRL_X509_CERT(X509_CRL *crl, X509_CERT *x);

/*===================== X509_REVOKED ============================= */

/*!
* \brief
* X509_REVOKED ����ü�� �ʱ�ȭ �Լ�
* \returns
* X509_REVOKED ����ü ������
*/
ISC_API X509_REVOKED* new_X509_REVOKED(void);
/*!
* \brief
* X509_REVOKED ����ü�� �޸� �Ҵ� ����
* \param revoked
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_X509_REVOKED(X509_REVOKED* revoked);
/*!
* \brief
* X509_REVOKED_LIST ����ü�� �޸� �Ҵ� ����
* \param revoked_list
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_X509_REVOKED_LIST (X509_REVOKED_LIST* revoked_list);

/*!
* \brief
* X509_REVOKED ����ü�� �����ϴ� �Լ�
* \param in
* ���� ������ X509_REVOKED ����ü
* \returns
* ����� X509_REVOKED ����ü
*/
ISC_API X509_REVOKED* dup_X509_REVOKED(X509_REVOKED* in);
/*!
* \brief
* X509_CRL_INFO ����ü ���� X509_REVOKED�� ������ Ȯ���ϴ� �Լ�
* \param unit
* X509_CRL_INFO ����ü
* \returns
* ���Ե� X509_REVOKED�� ����
*/
ISC_API int get_X509_REVOKED_count(X509_CRL_INFO *unit);
/*!
* \brief
* X509_CRL_INFO ����ü ���� X509_REVOKED�� ���Ϲޱ� ���� �Լ�
* \param unit
* X509_CRL_INFO ����ü
* \param loc
* ���Ϲޱ� ���� �ش� ������ �ε���
* \returns
* X509_REVOKED ����ü
*/
ISC_API X509_REVOKED *get_X509_REVOKED(X509_CRL_INFO *unit, int loc);

/*!
* \brief
* X509_REVOKED ����ü ���� userCert�� ���Ϲޱ� ���� �Լ�
* \param unit
* X509_REVOKED ����ü
* \returns
* version�� ����ִ� INTEGER ����ü
*/
ISC_API INTEGER* get_X509_REVOKED_userCert(X509_REVOKED *unit);
/*!
* \brief
* X509_REVOKED ����ü ���� ������ڸ� ���Ϲޱ� ���� �Լ�
* \param unit
* X509_REVOKED ����ü
* \returns
* ������ڸ� ����ִ� X509_TIME ����ü
*/
ISC_API X509_TIME* get_X509_REVOKED_revocationDate(X509_REVOKED *unit);
/*!
* \brief
* X509_REVOKED ����ü ���� CRL��� ������ Ȯ���ϱ� ���� �Լ� 
* \param revoked
* X509_REVOKED ����ü
* \param loc
* X509_REVOKED�� Ư�� X509_EXTENSION�� index
* \returns
* CRL ��� ����
*/
ISC_API int get_X509_REVOKED_CRLreason(X509_REVOKED* revoked, int loc);

/*!
* \brief
* X509_REVOKED ����ü�� userCert�� �Է��ϱ� ���� �Լ�
* \param x
* X509_REVOKED ����ü
* \param serial
* user SerialNumber (userCert)
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_REVOKED_userCert(X509_REVOKED *x, INTEGER *serial);
/*!
* \brief
* X509_REVOKED ����ü�� ������ڸ� �Է��ϱ� ���� �Լ�
* \param unit
* X509_REVOKED ����ü
* \param revocationDate
* ������ڸ� ����ִ� X509_TIME ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_REVOKED_revocationDate(X509_REVOKED *unit, X509_TIME *revocationDate);

/*!
* \brief
* X509_REVOKED ����ü�� �����Ͽ� X509_CRL ����ü�� �Է��ϱ� ���� �Լ�
* \param unit
* X509_CRL ����ü
* \param userCert
* user SerialNumber (userCert)
* \param revokeTime
* ������ڸ� ����ִ� X509_TIME ����ü
* \param extentions
* �ش� ����� �ΰ����� ������ ��� �ִ� X509_EXTENSIONS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_X509_REVOKED_child(X509_CRL *unit, INTEGER* userCert, X509_TIME* revokeTime, 
						   X509_EXTENSION* extention);
/*!
* \brief
* ������ X509_REVOKED ����ü�� X509_CRL_INFO ����ü�� �Է��ϱ� ���� �Լ�
* \param crl
* X509_CRL_INFO ����ü
* \param rev
* X509_REVOKED ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_X509_CRL_revoked(X509_CRL_INFO **crl, X509_REVOKED *rev);

/*!
* \brief
* X509_CRL_INFO ����ü���� X509_REVOKED�� Sequence�� Encode �Լ�
* \param in
* X509_CRL_INFO ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_X509_REVOKED_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_X509_REVOKED_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_EXTENSIONS_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS X509_REVOKED_to_Seq(X509_CRL_INFO *in, SEQUENCE **seq);
/*!
* \brief
* Sequence�� X509_CRL_INFO ����ü���� X509_REVOKED�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param out
* X509_CRL_INFO ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_X509_REVOKED^ISC_ERR_NULL_INPUT : Null input error
* -# LOCATION^F_SEQ_TO_X509_REVOKED^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_EXTENSIONS()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_X509_REVOKED(SEQUENCE *seq, X509_CRL_INFO **out);


/* =====================REVOKED���� EXT���� �Լ�======================== */
/*!
* \brief
* X509_REVOKED ����ü�� X509 Ȯ���ʵ��� ������ �˱� ���� �Լ�
* \param x
* ����Ͽ� ���� ������ ����ִ� X509_REVOKED ����ü
* \returns
* Ȯ���ʵ��� ����
*/
ISC_API int	get_X509_REVOKED_ext_count(X509_REVOKED *x);
/*!
* \brief
* X509_REVOKED ����ü�� X509 Ȯ���ʵ忡�� �Է¹��� OID���� ����� index�� �˱� ���� �Լ�
* \param x
* ����Ͽ� ���� ������ ����ִ� X509_REVOKED ����ü
* \param obj
* ã���� �ϴ� OID
* \param lastpos
* ������ TOP
* \returns
* �ش� index
*/
ISC_API int get_X509_REVOKED_ext_by_OID(X509_REVOKED *x, OBJECT_IDENTIFIER *obj, int lastpos);
/*!
* \brief
* X509_REVOKED ����ü�� X509 Ȯ���ʵ忡�� �Է¹��� OID���� ����� index�� �˱� ���� �Լ�
* \param x
* ����Ͽ� ���� ������ ����ִ� X509_REVOKED ����ü
* \param OID_index
* ã���� �ϴ� OID�� index
* \param lastpos
* ������ TOP
* \returns
* �ش� index
*/
ISC_API int get_X509_REVOKED_ext_index_by_OID_index(X509_REVOKED *x, int OID_index, int lastpos);

/*!
* \brief
* X509_REVOKED ����ü�� �� X509 Ȯ���ʵ带 ��� ���� �Լ�
* \param x
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \param loc
* �ش� �ε���
* \returns
* X509_EXTENSION ����ü
*/
ISC_API X509_EXTENSION *get_X509_REVOKED_ext(X509_REVOKED *x, int loc);
/*!
* \brief
* X509_REVOKED ����ü�� �� X509 Ȯ���ʵ带 �����ϱ� ���� �Լ�
* \param x
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \param loc
* �ش� �ε���
* \returns
* ���ŵ� X509_EXTENSION ����ü
*/
ISC_API X509_EXTENSION *remove_X509_REVOKED_ext(X509_REVOKED *x, int loc);
/*!
* \brief
* X509_REVOKED ����ü�� X509 Ȯ���ʵ带 �߰��ϱ� ���� �Լ�
* \param x
* ����Ͽ� ���� ������ ����ִ� X509_CRL ����ü
* \param ex
* �߰��ϰ��� �ϴ� X509_EXTENSION ����ü
* \param loc
* �ش� �ε���
* \returns
* -# add_X509_EXTENSION�� �����ڵ�\n
*/
ISC_API ISC_STATUS	add_X509_REVOKED_ext(X509_REVOKED *x, X509_EXTENSION *ex, int loc);


/* =======================X509_CRL ��ü���� �Լ�============================ */
/*!
* \brief
* X509_CRL ����ü�� Sequence�� Encode �Լ�
* \param in
* X509_CRL ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_X509_CRL_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_CRL_INFO_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS X509_CRL_to_Seq(X509_CRL *in, SEQUENCE **seq);
/*!
* \brief
* Sequence�� P8_PRIV_KEY_INFO ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param crl
* P8_PRIV_KEY_INFO ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_X509_CRL^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_X509_CRL^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_CRL_INFO()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_X509_CRL(SEQUENCE *seq, X509_CRL **crl);

/*!
* \brief
* X509_CRLS ����ü�� �ʱ�ȭ �Լ�
* \returns
* X509_CRLS ����ü ������
*/
ISC_API X509_CRLS *new_X509_CRLS();
/*!
* \brief
* X509_CRLS ����ü�� �޸� �Ҵ� ����
* \param x509Crls
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_X509_CRLS(X509_CRLS *x509Crls);

/*!
* \brief
* X509_CRLS ����ü�� Sequence�� Encode �Լ�
* \param crls
* X509_CRL ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_X509_CRLS_TO_SEQ^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_X509_CRLS_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_CRL_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS X509_CRLS_to_Seq(X509_CRLS *crls, SEQUENCE **seq);
/*!
* \brief
* Sequence�� X509_CRLS ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param crls
* X509_CRLS ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_X509_CRLS^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_SEQ_TO_X509_CRLS^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_X509_CRLS^ERR_ASN1_DECODING : ASN1 Err
* -# LOCATION^F_SEQ_TO_X509_CRLS^ERR_STK_ERROR : stack error
* -# Seq_to_X509_CRL()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_X509_CRLS(SEQUENCE *seq, X509_CRLS **crls);

/*!
* \brief
* X509_CRL ����ü�� ISC_RSA ������ �ϴ� �Լ�
* \param tbs
* X509_CRL ����ü
* \param rsa_signature
* ISC_RSA ����
* \param alg
* ���� �˰��� OID
* \param pri_params
* ISC_RSA Ű
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_GEN_RSASIGN^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_GEN_RSASIGN^ISC_ERR_INVALID_INPUT : input error
* -# X509_CRL_INFO_to_Seq()�� ���� �ڵ�\n
* -# ISC_Init_RSASSA()�� ���� �ڵ�\n
* -# ISC_Update_RSASSA()�� ���� �ڵ�\n
* -# ISC_Final_RSASSA()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS gen_RSA_SIG_X509_CRL(X509_CRL* tbs, BIT_STRING** rsa_signature, OBJECT_IDENTIFIER *alg, ISC_RSA_UNIT* pri_params);
/*!
* \brief
* X509_CRL ����ü�� ISC_KCDSA ������ �ϴ� �Լ�
* \param crl
* X509_CRL ����ü
* \param signature
* ISC_KCDSA ����
* \param alg
* ���� �˰��� OID
* \param pri_params
* ISC_KCDSA Ű
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_GEN_KCDSASIGN^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_GEN_KCDSASIGN^ISC_ERR_INVALID_INPUT : input error
* -# X509_CRL_INFO_to_Seq()�� ���� �ڵ�\n
* -# ISC_Init_KCDSA()�� ���� �ڵ�\n
* -# ISC_Update_KCDSA()�� ���� �ڵ�\n
* -# ISC_Final_KCDSA()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS gen_KCDSA_SIG_X509_CRL(X509_CRL* crl, BIT_STRING** signature, OBJECT_IDENTIFIER *alg, ISC_KCDSA_UNIT* pri_params);
/*!
* \brief
* X509_CRL ����ü�� ISC_ECDSA ������ �ϴ� �Լ�
* \param tbs
* X509_CRL ����ü
* \param ecdsa_signature
* ISC_ECDSA ����
* \param alg
* ���� �˰��� OID
* \param pri_params
* ISC_ECDSA Ű
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_GEN_RSASIGN^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_GEN_RSASIGN^ISC_ERR_INVALID_INPUT : input error
* -# X509_CRL_INFO_to_Seq()�� ���� �ڵ�\n
* -# ISC_Init_ECDSA()�� ���� �ڵ�\n
* -# ISC_Update_ECDSA()�� ���� �ڵ�\n
* -# ISC_Final_ECDSA()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS gen_ECDSA_SIG_X509_CRL(X509_CRL* tbs, BIT_STRING** ecdsa_signature, OBJECT_IDENTIFIER *alg, ISC_ECDSA_UNIT* pri_params);

/*!
* \brief
* X509_CRL ����ü�� ����(ISC_RSA)�� �����ϴ� �Լ�
* \param cert
* X509_CRL ����ü
* \param pub_params
* ISC_RSA Ű
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_VERIFY_RSASIGN^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_VERIFY_RSASIGN^ISC_ERR_INVALID_INPUT : input error
* -# X509_CRL_INFO_to_Seq()�� ���� �ڵ�\n
* -# ISC_Init_RSASSA()�� ���� �ڵ�\n
* -# ISC_Update_RSASSA()�� ���� �ڵ�\n
* -# ISC_Final_RSASSA()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS verify_RSA_SIG_X509_CRL(X509_CRL* cert, ISC_RSA_UNIT* pub_params);
/*!
* \brief
* X509_CRL ����ü�� ����(ISC_KCDSA)�� �����ϴ� �Լ�
* \param cert
* X509_CRL ����ü
* \param pub_params
* ISC_KCDSA Ű
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_VERIFY_KCDSASIGN^ISC_ERR_NULL_INPUT : Null input
* -# LOCATION^F_VERIFY_KCDSASIGN^ISC_ERR_INVALID_INPUT : input error
* -# X509_CRL_INFO_to_Seq()�� ���� �ڵ�\n
* -# ISC_Init_KCDSA()�� ���� �ڵ�\n
* -# ISC_Update_KCDSA()�� ���� �ڵ�\n
* -# ISC_Final_KCDSA()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS verify_KCDSA_SIG_X509_CRL(X509_CRL* cert, ISC_KCDSA_UNIT* pub_params);
/*!
* \brief
* X509_CRL ����ü�� ������ �����ϴ� �Լ�
* \param cert
* X509_CRL ����ü
* \param pubKey
* X509_PUBKEY ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
* -# verify_RSA_SIG_X509_CRL()�� ���� �ڵ�\n
* -# verify_KCDSA_SIG_X509_CRL()�� ���� �ڵ�\n
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
