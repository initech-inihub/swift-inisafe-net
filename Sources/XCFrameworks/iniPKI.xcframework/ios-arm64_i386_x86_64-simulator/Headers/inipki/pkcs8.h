/*!
* \file pkcs8.h
* \brief PKCS8
* Private-Key Information Syntax Standard
* \remarks
* P8_ENCRYPTED_KEY, P8_PRIV_KEY_INFO ���� ���
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_PKCS8_H
#define HEADER_PKCS8_H

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/biginteger.h>

#include "asn1.h"
#include "x509.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* P8_ENCRYPTED_KEY�� PBE_PARAM
*/
typedef struct pbeparam_st {
	OCTET_STRING* salt;		/*!< */
	INTEGER* count;		/*!< */
	X509_ALGO_IDENTIFIER* cipher;	/*!< */ /* OPTIONAL, PBES2 version */
	X509_ALGO_IDENTIFIER *prf;	/*!< */ /* PBKDF2 PRF Algorithm Identifier */ 
} P5_PBE_PARAM;

/*!
* \brief
* P8_PRIV_KEY_INFO�� encrypt���� ������ �ٷ�� ����ü
*/
typedef struct pkcs8_key_st {
	int version;	/*!< */	/* version = 0, OID_pbeWithSHA1AndSEED_CBC or OID_seed_cbc */
							/* version = 1, OID_pbeWithMD2AndDES_CBC or OID_pbeWithMD5AndDES_CBC or	OID_pbeWithSHA1AndDES_CBC */
							/* version = 2, OID_PBES2 */
	X509_ALGO_IDENTIFIER* EncAlgId;	/*!< */
	OCTET_STRING * encryptedData; /*!< */
} P8_ENCRYPTED_KEY;

/*!
* \brief
* ����Ű�� ������ �ٷ�� ����ü
*/
typedef struct priv_key_st
{
	INTEGER* version;		/*!< */
	OBJECT_IDENTIFIER* oID;		/*!< */
	ASYMMETRIC_KEY* akey;		/*!< */
	X509_ATTRIBUTES * attributes;		/*!< */
} P8_PRIV_KEY_INFO;

/*!
* \brief
* P8_PRIV_KEY_INFO ������(�迭)
*/
typedef STK(P8_PRIV_KEY_INFO) P8_PRIV_KEY_INFOS;

/*!
 * \brief
 * P8_EXTENDED_PRIV_KEY_OID info
 */
typedef struct ext_priv_key_oid_info_st
{
    INTEGER* count;		/*!< */
    OBJECT_IDENTIFIER* oID;		/*!< */
} P8_PRIV_KEY_OID_INFO;

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* P8_ENCRYPTED_KEY ����ü�� �ʱ�ȭ �Լ�
* \returns
* P8_ENCRYPTED_KEY ����ü ������
*/
ISC_API P8_ENCRYPTED_KEY *new_PKCS8(void);

/*!
* \brief
* P8_ENCRYPTED_KEY ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_PKCS8(P8_ENCRYPTED_KEY *unit);

/*!
* \brief
* P8_ENCRYPTED_KEY ����ü�� ����
* \param unit
* ������ P8_ENCRYPTED_KEY ����ü
*/
ISC_API void clean_PKCS8(P8_ENCRYPTED_KEY *unit);

/*!
* \brief
* P8_PRIV_KEY_INFO ����ü�� �ʱ�ȭ �Լ�
* \returns
* P8_PRIV_KEY_INFO ����ü ������
*/
ISC_API P8_PRIV_KEY_INFO *new_P8_PRIV_KEY_INFO(void);

/*!
* \brief
* P8_PRIV_KEY_INFO ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P8_PRIV_KEY_INFO(P8_PRIV_KEY_INFO *unit);

/*!
* \brief
* P8_PRIV_KEY_INFO ����ü�� ����
* \param unit
* ������ P8_PRIV_KEY_INFO ����ü
*/
ISC_API void clean_P8_PRIV_KEY_INFO(P8_PRIV_KEY_INFO *unit);

/*!
* \brief
* P5_PBE_PARAM ����ü�� �ʱ�ȭ �Լ�
* \returns
* P5_PBE_PARAM ����ü ������
*/
ISC_API P5_PBE_PARAM* new_P5_PBE_PARAM (void);

/*!
* \brief
* P5_PBE_PARAM ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_P5_PBE_PARAM(P5_PBE_PARAM *unit);

/*!
* \brief
* P5_PBE_PARAM ����ü�� ����
* \param unit
* ������ P5_PBE_PARAM ����ü
*/
ISC_API void clean_P5_PBE_PARAM(P5_PBE_PARAM *unit);

/*!
* \brief
* P8_ENCRYPTED_KEY ����ü���� encryptedData�� ��� ���� �Լ�
* \param unit
* ����Ű�� ������ ��ȣȭ �Ǿ��ִ� ����ü
* \returns
* unit->encryptedData
*/
ISC_API uint8 *get_encryptedData_PKCS8(P8_ENCRYPTED_KEY *unit);

/*!
* \brief
* P8_ENCRYPTED_KEY ����ü�� encryptedData�� �����ϱ� ���� �Լ�
* \param unit
* ����Ű�� ������ ��ȣȭ �Ǿ��ִ� ����ü
* \param encryptedData
* ����Ű�� ��ȣȭ�� Data
* \param encryptedDataLen
* ����Ű�� ��ȣȭ�� Data�� ����
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_encryptedData_PKCS8(P8_ENCRYPTED_KEY *unit, uint8* encryptedData, int encryptedDataLen);

/*!
* \brief
* P8_ENCRYPTED_KEY ����ü���� encrypt Object Identifier�� ��� ���� �Լ�
* \param unit
* ����Ű�� ������ ��ȣȭ �Ǿ��ִ� ����ü
* \returns
* unit->EncAlgId->algorithm
*/
ISC_API OBJECT_IDENTIFIER *get_OID_PKCS8 (P8_ENCRYPTED_KEY * unit);

/*!
* \brief
* P8_ENCRYPTED_KEY ����ü�� encrypt Object Identifier�� �����ϱ� ���� �Լ�
* \param unit
* ����Ű�� ������ ��ȣȭ �Ǿ��ִ� ����ü
* \param OID
* ����Ű�� ��ȣȭ�� �˰��� OID
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_OID_PKCS8(P8_ENCRYPTED_KEY *unit, OBJECT_IDENTIFIER* OID);

/*!
* \brief
* P8_ENCRYPTED_KEY ����ü���� P5_PBE_PARAM�� ��� ���� �Լ�
* \param unit
* ����Ű�� ������ ��ȣȭ �Ǿ��ִ� ����ü
* \returns
* P5_PBE_PARAM
*/
ISC_API P5_PBE_PARAM *get_PKCS8_P5_PBE_PARAM(P8_ENCRYPTED_KEY *unit);

/*!
* \brief
* P5_PBE_PARAM ����ü�� �����ϴ� �Լ�
* \param pbe
* ������ P5_PBE_PARAM ����ü
* \param salt
* SALT
* \param saltLen
* SALT�� ����
* \param count
* iter
* \param countLen
* iter�� ����
* \param oid
* PBES2�� X509_ALGO_IDENTIFIER�� OID (optional)
* \param parameters
* PBES2�� X509_ALGO_IDENTIFIER�� parameters (optional)
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_P5_PBE_PARAM(P5_PBE_PARAM *pbe, uint8* salt, int saltLen, uint8* count, int countLen, OBJECT_IDENTIFIER* oid, ASN1_STRING* parameters);

/*!
* \brief
* P5_PBE_PARAM ����ü�� �����ϴ� �Լ�
* \param pbe
* ������ P5_PBE_PARAM ����ü
* \param salt
* SALT
* \param saltLen
* SALT�� ����
* \param count
* iter
* \param countLen
* iter�� ����
* \param oid
* PBES2�� X509_ALGO_IDENTIFIER�� OID (optional)
* \param parameters
* PBES2�� X509_ALGO_IDENTIFIER�� parameters (optional)
* \param prfOid
* PBES2�� PBKDF2 prf algorithm OID (optional)
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_P5_PBE_PARAM_ex(P5_PBE_PARAM *pbe, uint8* salt, int saltLen, uint8* count, int countLen, OBJECT_IDENTIFIER* oid, ASN1_STRING* parameters, OBJECT_IDENTIFIER* prfOid);

/*!
* \brief
* P8_ENCRYPTED_KEY ����ü�� P5_PBE_PARAM�� �����ϱ� ���� �Լ�
* \param unit
* ����Ű�� ������ ��ȣȭ �Ǿ��ִ� ����ü
* \param pbe
* ��ȣȭ �˰���� �Ķ���Ͱ� ����� P5_PBE_PARAM ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_PKCS8_P5_PBE_PARAM(P8_ENCRYPTED_KEY *unit, P5_PBE_PARAM* pbe);

/*!
* \brief
* X509_ALGO_IDENTIFIER ����ü�� ������ P5_PBE_PARAM�� ����� ���� �Լ�
* \param unit
* X509_ALGO_IDENTIFIER�� ����ü
* \returns
* P5_PBE_PARAM
*/
ISC_API P5_PBE_PARAM *get_P5_PBE_PARAM_from_X509_ALGO_IDENTIFIER(X509_ALGO_IDENTIFIER *unit);

/*!
* \brief
* P8_PRIV_KEY_INFO ����ü���� version�� ��� ���� �Լ�
* \param unit
* P8_PRIV_KEY_INFO�� ����ü
* \returns
* version�� ���̳ʸ�
*/
ISC_API uint8 *get_PRIV_KEY_version(P8_PRIV_KEY_INFO *unit);

/*!
* \brief
* P5_PBE_PARAM ����ü�� �����ϴ� �Լ�
* \param pbe
* ������ P5_PBE_PARAM ����ü
* \param salt
* SALT
* \param saltLen
* SALT�� ����
* \param count
* iter
* \param countLen
* iter�� ����
* \param oid
* PBES2�� X509_ALGO_IDENTIFIER�� OID (optional)
* \param parameters
* PBES2�� X509_ALGO_IDENTIFIER�� parameters (optional)
* \param prfOid
* PBES2�� PBKDF2 prf algorithm OID (optional)
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_P5_PBE_PARAM_ex(P5_PBE_PARAM *pbe, uint8* salt, int saltLen, uint8* count, int countLen, OBJECT_IDENTIFIER* oid, ASN1_STRING* parameters, OBJECT_IDENTIFIER* prfOid);

/*!
* \brief
* P8_PRIV_KEY_INFO ����ü�� version�� �����ϱ� ���� �Լ�
* \param unit
* ����Ű�� ������ ��� �ִ� ����ü
* \param version
* default 0
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_PRIV_KEY_version(P8_PRIV_KEY_INFO *unit, uint8* version);
/*!
* \brief
* P8_PRIV_KEY_INFO ����ü���� Object Identifier�� ��� ���� �Լ�
* \param unit
* P8_PRIV_KEY_INFO�� ����ü
* \returns
* OID
*/
ISC_API OBJECT_IDENTIFIER *get_PRIV_KEY_OID (P8_PRIV_KEY_INFO * unit);

/*!
* \brief
* P8_PRIV_KEY_INFO ����ü�� ����Ű�� OID�� �����ϱ� ���� �Լ�
* \param unit
* ����Ű�� ������ ��� �ִ� ����ü
* \param OID
* ������ OID
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_PRIV_KEY_OID(P8_PRIV_KEY_INFO *unit, OBJECT_IDENTIFIER *OID);

/*!
* \brief
* P8_PRIV_KEY_INFO ����ü���� ����Ű�� ��� ���� �Լ�
* \param unit
* P8_PRIV_KEY_INFO�� ����ü
* \returns
* ASYMMETRIC_KEY
*/
ISC_API ASYMMETRIC_KEY* get_PRIV_KEY_KeyParams (P8_PRIV_KEY_INFO* unit);

/*!
* \brief
* P8_PRIV_KEY_INFO ����ü�� ����Ű�� �����ϱ� ���� �Լ�
* \param unit
* ����Ű�� ������ ��� �ִ� ����ü
* \param akey
* ������ Ű ������ ��� �ִ� ASYMMETRIC_KEY ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_PRIV_KEY_KeyParams (P8_PRIV_KEY_INFO* unit, ASYMMETRIC_KEY* akey);

/*!
* \brief
* P8_PRIV_KEY_INFO ����ü�� ����� �Լ�
* \param key
* ����Ű�� ������ ��� �ִ� ASYMMETRIC_KEY ����ü
* \param attributes
* VID�� P8_PRIV_KEY_INFO ����ü�� �ΰ����� ������ ����ִ� X509_ATTRIBUTES ����ü
* \returns
* P8_PRIV_KEY_INFO ����ü
*/
ISC_API P8_PRIV_KEY_INFO* gen_P8_PRIV_KEY_INFO(ASYMMETRIC_KEY* key, X509_ATTRIBUTES* attributes);

/*!
* \brief
* P5_PBE_PARAM ����ü�� Sequence�� Encode �Լ�
* \param pbe
* P5_PBE_PARAM ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P5_PBE_PARAM_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_P5_PBE_PARAM_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_ALGO_IDENTIFIER_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS P5_PBE_PARAM_to_Seq (P5_PBE_PARAM* pbe, SEQUENCE** seq);

/*!
* \brief
* Sequence�� P5_PBE_PARAM ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param pbe
* P5_PBE_PARAM ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P5_PBE_PARAM^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_SEQ_TO_P5_PBE_PARAM^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P5_PBE_PARAM^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_ALGO_IDENTIFIER()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P5_PBE_PARAM (SEQUENCE* seq, P5_PBE_PARAM** pbe);

/*!
* \brief
* P8_ENCRYPTED_KEY ����ü�� Sequence�� Encode �Լ�
* \param unit
* P8_ENCRYPTED_KEY ����ü
* \param out
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P8_ENCRYPTED_KEY_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_P8_ENCRYPTED_KEY_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_ALGO_IDENTIFIER_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS P8_ENCRYPTED_KEY_to_Seq (P8_ENCRYPTED_KEY *unit, SEQUENCE** out);

/*!
* \brief
* Sequence�� P8_ENCRYPTED_KEY ����ü�� Decode �Լ�
* \param in
* Decoding Sequece ����ü
* \param out
* P8_ENCRYPTED_KEY ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P8_ENCRYPTED_KEY^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_SEQ_TO_P8_ENCRYPTED_KEY^ISC_ERR_INVALID_INPUT : input error
* -# LOCATION^F_SEQ_TO_P8_ENCRYPTED_KEY^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_ALGO_IDENTIFIER()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P8_ENCRYPTED_KEY (SEQUENCE* in, P8_ENCRYPTED_KEY **out);

/*!
* \brief
* P8_PRIV_KEY_INFO ����ü�� Sequence�� Encode �Լ�
* \param unit
* P8_PRIV_KEY_INFO ����ü
* \param out
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_P8_PRIV_KEY_INFO_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_P8_PRIV_KEY_INFO_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# X509_ATTRIBUTES_to_Seq()�� ���� �ڵ�\n
*/

ISC_API ISC_STATUS P8_PRIV_KEY_INFO_to_Seq (P8_PRIV_KEY_INFO *unit, SEQUENCE** out);
/*!
* \brief
* Sequence�� P8_PRIV_KEY_INFO ����ü�� Decode �Լ�
* \param in
* Decoding Sequece ����ü
* \param out
* P8_PRIV_KEY_INFO ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_P8_PRIV_KEY_INFO^ERR_ASN1_DECODING : ASN1 Err
* -# Seq_to_X509_ATTRIBUTES()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_P8_PRIV_KEY_INFO (SEQUENCE* in, P8_PRIV_KEY_INFO **out);

/*!
* \brief
* P8_PRIV_KEY_INFO ����ü�� ����
* \param pkey
* ������ ����ü ������
* \return
* P8_PRIV_KEY_INFO ����ü ������
*/
ISC_API P8_PRIV_KEY_INFO *dup_P8_PRIV_KEY_INFO(P8_PRIV_KEY_INFO* pkey);
    
ISC_API P8_ENCRYPTED_KEY *dup_P8_ENCRYPTED_KEY(P8_ENCRYPTED_KEY* p8_enc_key, int oid_Type, char* obj_Name, char* keyFactorIDs);
ISC_API ISC_STATUS get_keyFactors_PKCS8 (P8_ENCRYPTED_KEY * unit, char** keyFactors);
ISC_API UTF8_STRING* get_objName_PKCS8 (P8_ENCRYPTED_KEY * unit);
#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(P8_ENCRYPTED_KEY*, new_PKCS8, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_PKCS8, (P8_ENCRYPTED_KEY *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_PKCS8, (P8_ENCRYPTED_KEY *unit), (unit) );
INI_RET_LOADLIB_PKI(P8_PRIV_KEY_INFO*, new_P8_PRIV_KEY_INFO, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P8_PRIV_KEY_INFO, (P8_PRIV_KEY_INFO *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_P8_PRIV_KEY_INFO, (P8_PRIV_KEY_INFO *unit), (unit) );
INI_RET_LOADLIB_PKI(P5_PBE_PARAM*, new_P5_PBE_PARAM, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_P5_PBE_PARAM, (P5_PBE_PARAM *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_P5_PBE_PARAM, (P5_PBE_PARAM *unit), (unit) );
INI_RET_LOADLIB_PKI(uint8*, get_encryptedData_PKCS8, (P8_ENCRYPTED_KEY *unit), (unit), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_encryptedData_PKCS8, (P8_ENCRYPTED_KEY *unit, uint8* encryptedData, int encryptedDataLen), (unit,encryptedData,encryptedDataLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(OBJECT_IDENTIFIER*, get_OID_PKCS8, (P8_ENCRYPTED_KEY * unit), (unit), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_OID_PKCS8, (P8_ENCRYPTED_KEY *unit, OBJECT_IDENTIFIER* OID), (unit,OID), ISC_FAIL);
INI_RET_LOADLIB_PKI(P5_PBE_PARAM*, get_PKCS8_P5_PBE_PARAM, (P8_ENCRYPTED_KEY *unit), (unit), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_P5_PBE_PARAM, (P5_PBE_PARAM *pbe, uint8* salt, int saltLen, uint8* count, int countLen, OBJECT_IDENTIFIER* oid, ASN1_STRING* parameters), (pbe,salt,saltLen,count,countLen,oid,parameters), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_PKCS8_P5_PBE_PARAM, (P8_ENCRYPTED_KEY *unit, P5_PBE_PARAM* pbe), (unit,pbe), ISC_FAIL);
INI_RET_LOADLIB_PKI(P5_PBE_PARAM*, get_P5_PBE_PARAM_from_X509_ALGO_IDENTIFIER, (X509_ALGO_IDENTIFIER *unit), (unit), NULL);
INI_RET_LOADLIB_PKI(uint8*, get_PRIV_KEY_version, (P8_PRIV_KEY_INFO *unit), (unit), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_PRIV_KEY_version, (P8_PRIV_KEY_INFO *unit, uint8* version), (unit,version), ISC_FAIL);
INI_RET_LOADLIB_PKI(OBJECT_IDENTIFIER*, get_PRIV_KEY_OID, (P8_PRIV_KEY_INFO * unit), (unit), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_PRIV_KEY_OID, (P8_PRIV_KEY_INFO *unit, OBJECT_IDENTIFIER *OID), (unit,OID), ISC_FAIL);
INI_RET_LOADLIB_PKI(ASYMMETRIC_KEY*, get_PRIV_KEY_KeyParams, (P8_PRIV_KEY_INFO* unit), (unit), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_PRIV_KEY_KeyParams, (P8_PRIV_KEY_INFO* unit, ASYMMETRIC_KEY* akey), (unit,akey), ISC_FAIL);
INI_RET_LOADLIB_PKI(P8_PRIV_KEY_INFO*, gen_P8_PRIV_KEY_INFO, (ASYMMETRIC_KEY* key, X509_ATTRIBUTES* attributes), (key,attributes), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P5_PBE_PARAM_to_Seq, (P5_PBE_PARAM* pbe, SEQUENCE** seq), (pbe,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P5_PBE_PARAM, (SEQUENCE* seq, P5_PBE_PARAM** pbe), (seq,pbe), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P8_ENCRYPTED_KEY_to_Seq, (P8_ENCRYPTED_KEY *unit, SEQUENCE** out), (unit,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P8_ENCRYPTED_KEY, (SEQUENCE* in, P8_ENCRYPTED_KEY **out), (in,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, P8_PRIV_KEY_INFO_to_Seq, (P8_PRIV_KEY_INFO *unit, SEQUENCE** out), (unit,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_P8_PRIV_KEY_INFO, (SEQUENCE* in, P8_PRIV_KEY_INFO **out), (in,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(P8_PRIV_KEY_INFO*, dup_P8_PRIV_KEY_INFO, (P8_PRIV_KEY_INFO* pkey), (pkey), NULL);


#endif

#ifdef  __cplusplus
}
#endif
#endif
