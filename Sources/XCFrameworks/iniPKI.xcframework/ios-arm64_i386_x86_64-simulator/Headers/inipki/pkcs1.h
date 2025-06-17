/*!
* \file pkcs1.h
* \brief PKCS1 
* Private-Key Information Syntax Standard
* \remarks
* P1_ENCRYPTED_KEY, P1_PRIV_KEY_INFO ���� ���
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_PKCS1_H
#define HEADER_PKCS1_H

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/foundation.h>

#include "asn1.h"
#include "asn1_objects.h"
#include "x509.h"

#define PKCS1_TYPE_ENCRYPT		0x00
#define PKCS1_TYPE_PLAIN		0x01

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* PKCS1 ISC_RSA ����Ű ������ �ٷ�� ����ü
* ��ȣȭ�� PKCS1������ �ٷ�� ��� ��ȣȭ �˰����� ISC_DES-EDE3-CBC���� ����Ѵ�.
*/
typedef struct pkcs1_rsa_private_key_st
{
	INTEGER	* version;						/*!< Version : �׻� 0 */
	INTEGER * modulus;						/*!< n */
	INTEGER * publicExponent;				/*!< e */
	INTEGER * privateExponent;				/*!< d */
	INTEGER * prime1;						/*!< p */
	INTEGER * prime2;						/*!< q */
	INTEGER * exponent1;					/*!< d mod (p-1) */
	INTEGER * exponent2;					/*!< d mod (q-1) */
	INTEGER * coefficient;					/*!< (inverse of q) mod p */
	SEQUENCE * otherPrimeInfos;				/*!< Not Used yet */
} PKCS1_RSA_PRIVATE_KEY;

typedef struct pkcs1_rsa_public_key_st
{
	INTEGER * modulus;
	INTEGER * publicExponent;
} PKCS1_RSA_PUBLIC_KEY;
    
/*!
* \brief
* RSAES OAEP Parameter�� �����ϴ� ����ü
*/
typedef struct RSAES_OAEP_PARAM_st {
	X509_ALGO_IDENTIFIER *hashAlgorithm;	/*!< identifies the hash function */
	X509_ALGO_IDENTIFIER *maskGenAlgorithm;	/*!< identifies the mask generation function */
	X509_ALGO_IDENTIFIER *pSourceAlgorithm;	/*!< identifies the source (and possibly the value) of the label L. */
} RSAES_OAEP_PARAM;

/*!
* \brief
* RSASSA PSS Parameter�� �����ϴ� ����ü
*/
typedef struct RSASSA_PSS_PARAM_st {
	X509_ALGO_IDENTIFIER *hashAlgorithm;	/*!< identifies the hash function */
	X509_ALGO_IDENTIFIER *maskGenAlgorithm;	/*!< identifies the mask generation function */
	INTEGER *trailerField;		/*!< the trailer field number */
} RSASSA_PSS_PARAM;
    
#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* PKCS1_RSA_PRIVATE_KEY ����ü�� �ʱ�ȭ �Լ�
* \returns
* PKCS1_RSA_PRIVATE_KEY ����ü ������
*/
ISC_API PKCS1_RSA_PRIVATE_KEY *new_PKCS1_RSA_PRIVATE_KEY(void);

/*!
* \brief
* PKCS1_RSA_PUBLIC_KEY ����ü�� �ʱ�ȭ �Լ�
* \returns
* PKCS1_RSA_PUBLIC_KEY ����ü ������
*/
ISC_API PKCS1_RSA_PUBLIC_KEY *new_PKCS1_RSA_PUBLIC_KEY(void);

/*!
* \brief
* PKCS1_RSA_PRIVATE_KEY ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_PKCS1_RSA_PRIVATE_KEY(PKCS1_RSA_PRIVATE_KEY *unit);

/*!
* \brief
* PKCS1_RSA_PUBLIC_KEY ����ü�� �޸� �Ҵ� ����
* \param unit
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_PKCS1_RSA_PUBLIC_KEY(PKCS1_RSA_PUBLIC_KEY *unit);

/*!
* \brief
* PKCS1_RSA_PRIVATE_KEY ����ü�� ����
* \param unit
* ������ PKCS1_RSA_PRIVATE_KEY ����ü
*/
ISC_API void clean_PKCS1_RSA_PRIVATE_KEY(PKCS1_RSA_PRIVATE_KEY *unit);

/*!
* \brief
* PKCS1_RSA_PUBLIC_KEY ����ü�� ����
* \param unit
* ������ PKCS1_RSA_PUBLIC_KEY ����ü
*/
ISC_API void clean_PKCS1_RSA_PUBLIC_KEY(PKCS1_RSA_PUBLIC_KEY *unit);

/*!
* \brief
* PKCS1_RSA_PRIVATE_KEY ����ü�� Sequence�� Encode �Լ�
* \param unit
* PKCS1_RSA_PRIVATE_KEY ����ü
* \param out
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# L_PKCS1^F_P1_PRIV_KEY_INFO_TO_SEQ : �⺻ �����ڵ�
*/
ISC_API ISC_STATUS PKCS1_RSA_PRIVATE_KEY_to_Seq (PKCS1_RSA_PRIVATE_KEY *unit, SEQUENCE** out);

/*!
* \brief
* PKCS1_RSA_PUBLIC_KEY ����ü�� Sequence�� Encode �Լ�
* \param unit
* PKCS1_RSA_PUBLIC_KEY ����ü
* \param out
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# L_PKCS1^F_P1_PUB_KEY_INFO_TO_SEQ : �⺻ �����ڵ�
*/
ISC_API ISC_STATUS PKCS1_RSA_PUBLIC_KEY_to_Seq (PKCS1_RSA_PUBLIC_KEY *unit, SEQUENCE** out);

/*!
* \brief
* Sequence�� PKCS1_RSA_PRIVATE_KEY ����ü�� Decode �Լ�
* \param in
* Decoding Sequece ����ü
* \param out
* PKCS1_RSA_PRIVATE_KEY ����ü
* \returns
* -# ISC_SUCCESS : ����
* -#  L_PKCS1^F_SEQ_TO_P1_PRIV_KEY_INFO : �⺻ �����ڵ�
*/
ISC_API ISC_STATUS Seq_to_PKCS1_RSA_PRIVATE_KEY (SEQUENCE* in, PKCS1_RSA_PRIVATE_KEY **out);

/*!
* \brief
* Sequence�� PKCS1_RSA_PUBLIC_KEY ����ü�� Decode �Լ�
* \param in
* Decoding Sequece ����ü
* \param out
* PKCS1_RSA_PUBLIC_KEY ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# L_PKCS1^F_SEQ_TO_P1_PUB_KEY_INFO : �⺻ �����ڵ�
*/
ISC_API ISC_STATUS Seq_to_PKCS1_RSA_PUBLIC_KEY (SEQUENCE* in, PKCS1_RSA_PUBLIC_KEY **out);

/*!
* \brief
* PKCS1_RSA_PRIVATE_KEY ����ü�κ��� ISC_RSA_UNIT�� ���ϴ� �Լ�
* \param rsa
* ISC_RSA_UNIT ����ü
* \param out
* PKCS1_RSA_PRIVATE_KEY ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# L_PKCS1^F_GET_RSA_UNIT_FROM_PRIV_KEY : �⺻ �����ڵ�
* -# L_RSA^F_SET_RSA_PRAMS^ISC_ERR_INVALID_INPUT : �Է� �Ķ���� ����
*/
ISC_API ISC_STATUS get_RSA_UNIT_from_PKCS1_RSA_PRIVATE_KEY(ISC_RSA_UNIT **rsa, PKCS1_RSA_PRIVATE_KEY *pkcs1);

/*!
* \brief
* PKCS1_RSA_PUBLIC_KEY ����ü�κ��� ISC_RSA_UNIT�� ���ϴ� �Լ�
* \param rsa
* ISC_RSA_UNIT ����ü
* \param out
* PKCS1_RSA_PUBLIC_KEY ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# L_PKCS1^F_GET_RSA_UNIT_FROM_PUB_KEY : �⺻ �����ڵ�
* -# L_RSA^F_SET_RSA_PRAMS^ISC_ERR_INVALID_INPUT : e�� n�� NULL�� ���
*/
ISC_API ISC_STATUS get_RSA_UNIT_from_PKCS1_RSA_PUBLIC_KEY(ISC_RSA_UNIT **rsa, PKCS1_RSA_PUBLIC_KEY *pkcs1);

/*!
* \brief
* ISC_RSA_UNIT ����ü�κ��� PKCS1_RSA_PRIVATE_KEY�� ���ϴ� �Լ�
* \param rsa
* ISC_RSA_UNIT ����ü
* \param out
* PKCS1_RSA_PRIVATE_KEY ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# L_PKCS1^F_SET_RSA_UNIT_TO_P1_PRIV_KEY : �⺻ �����ڵ�
*/
ISC_API ISC_STATUS set_RSA_UNIT_to_PKCS1_RSA_PRIVATE_KEY(ISC_RSA_UNIT *rsa, PKCS1_RSA_PRIVATE_KEY **pkcs1);

/*!
* \brief
* ISC_RSA_UNIT ����ü�κ��� PKCS1_RSA_PUBLIC_KEY�� ���ϴ� �Լ�
* \param rsa
* ISC_RSA_UNIT ����ü
* \param out
* PKCS1_RSA_PUBLIC_KEY ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# L_PKCS1^F_SET_RSA_UNIT_TO_P1_PUB_KEY : �⺻ �����ڵ�
*/
ISC_API ISC_STATUS set_RSA_UNIT_to_PKCS1_RSA_PUBLIC_KEY(ISC_RSA_UNIT *rsa, PKCS1_RSA_PUBLIC_KEY **pkcs1);
   
/*!
* \brief
* PBKDF
* \param password
* �н�����
* \param passwordLen
* �н����� ����
* \param salt
* SALT ��
* \param dk_buf
* PBKDF�� ���� ������ Ű
* \param dkLen
* ������ Ű�� ����
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_PBKDF^ISC_ERR_INVALID_OUTPUT : �Է� �Ķ���� ����
*/
ISC_API int PBKDF(uint8* password, int passwordLen, uint8* salt, uint8* dk_buf, int dkLen);

/*!
* \brief
* ���Ϸκ��� PEM���� ���ڵ��� PKCS1 ������(����Ű/����Ű)�� �о ISC_RSA_UNIT �����ϴ� �������ִ� �Լ�
* ����Ű�� ��� ��ȣȭ�� PKCS1 �Ǵ� �� PKCS1 PEM �����͸� �д´�.
* ����Ű�� ��� �� PKCS1 �����͸� ó���Ѵ�.
* ����Ű�� ��� ��ȣȭ �Ǿ��ִ� ��� password �Ķ���͸� ����Ͽ� ��ȣȭ �Ѵ�.
* \param rsa
* PKCS1 ISC_RSAŰ ����ü
* \param password 
* ����Ű�� ��� PEM ������ ��ȣȭ �Ǿ� �ִ� ��� ��ȣȭ�� �ÿ��� ����Ű password
* ����Ű PEM �����Ͱ� ���̰ų� ����Ű PEM�� ��� ������ �ʴ´�.
* \param passwordLen 
* password�� ����
* \param fileName
* File �̸� ���ڿ��� ������, Ex)"D:\\test.pem"
* \returns
* -# ISC_SUCCESS : ����
* -# L_PKCS1^ISC_ERR_READ_FROM_FILE : �⺻ �����ڵ�
* -# L_PKCS1^ISC_ERR_INVALID_INPUT : �Է� �Ķ���� ����
* -# readPEM_from_Binary �Լ��κ��� �߻��� ���� �ڵ�
*/
ISC_API ISC_STATUS readPKCS1_from_File(ISC_RSA_UNIT **rsa, uint8* password, int passwordLen, const char* fileName);
/*!
* \brief
* ���̳ʸ� �����ͷκ��� PEM���� ���ڵ��� PKCS1 ������(����Ű/����Ű)�� �о ISC_RSA_UNIT �����ϴ� �������ִ� �Լ�
* ����Ű�� ��� ��ȣȭ�� PKCS1 �Ǵ� �� PKCS1 PEM �����͸� �д´�.
* ����Ű�� ��� �� PKCS1 �����͸� ó���Ѵ�.
* ����Ű�� ��� ��ȣȭ �Ǿ��ִ� ��� password �Ķ���͸� ����Ͽ� ��ȣȭ �Ѵ�.
* \param rsa
* PKCS1 ISC_RSAŰ ����ü
* \param password 
* ����Ű�� ��� PEM ������ ��ȣȭ �Ǿ� �ִ� ��� ��ȣȭ�� �ÿ��� ����Ű password
* ����Ű PEM �����Ͱ� ���̰ų� ����Ű PEM�� ��� ������ �ʴ´�.
* \param passwordLen 
* password�� ����
* \param pemBytes
* PEM���� ���ڵ��� ���̳ʸ��� ����Ű�� ������
* \param pemLength
* PEM���� ���ڵ��� ���̳ʸ��� ����
* \returns
* -# ISC_SUCCESS : ����
* -# L_PKCS1^ISC_ERR_READ_FROM_BINARY : �⺻ �����ڵ�
* -# L_PKCS1^ISC_ERR_INVALID_INPUT : �Է� �Ķ���� ����
* -# L_PKCS1^ISC_ERR_MALLOC : �Ҵ� ����
*/
ISC_API ISC_STATUS readPKCS1_from_Binary(ISC_RSA_UNIT **rsa, uint8* password, int passwordLen, uint8* pemBytes, int pemLength);

/*!
 * \brief
 * ���̳ʸ� �����ͷκ��� PEM���� ���ڵ��� PKCS1 ������(����Ű/����Ű)�� �о ISC_RSA_UNIT || ISC_ECDSA_UNIT �����ϴ� �������ִ� �Լ�
 * ����Ű�� ��� ��ȣȭ�� PKCS1 �Ǵ� �� PKCS1 PEM �����͸� �д´�.
 * ����Ű�� ��� �� PKCS1 �����͸� ó���Ѵ�.
 * ����Ű�� ��� ��ȣȭ �Ǿ��ִ� ��� password �Ķ���͸� ����Ͽ� ��ȣȭ �Ѵ�.
 * \param unit
 * PKCS1 ISC_RSA || ISC_ECDSA Ű ����ü
 * \param alg
 * RSA/ECDSA �˰��� ����. ASYMMETRIC_RSA_KEY || ASYMMETRIC_ECDSA_KEY
 * \param password
 * ����Ű�� ��� PEM ������ ��ȣȭ �Ǿ� �ִ� ��� ��ȣȭ�� �ÿ��� ����Ű password
 * ����Ű PEM �����Ͱ� ���̰ų� ����Ű PEM�� ��� ������ �ʴ´�.
 * \param passwordLen
 * password�� ����
 * \param pemBytes
 * PEM���� ���ڵ��� ���̳ʸ��� ����Ű�� ������
 * \param pemLength
 * PEM���� ���ڵ��� ���̳ʸ��� ����
 * \returns
 * -# ISC_SUCCESS : ����
 * -# L_PKCS1^ISC_ERR_READ_FROM_BINARY : �⺻ �����ڵ�
 * -# L_PKCS1^ISC_ERR_INVALID_INPUT : �Է� �Ķ���� ����
 * -# L_PKCS1^ISC_ERR_MALLOC : �Ҵ� ����
 */
ISC_API ISC_STATUS readPKCS1_from_Binary_ex(void **unit, int alg, uint8* password, int passwordLen, uint8* inPEMData, int inPEMDataLen);
    
/*!
* \brief
* ISC_RSA_UNIT ����Ű ����ü�� PKCS1 PEM���� ���ڵ��� �� ���Ϸ� ���� �Լ�
* password�� NULL�� �ƴϸ� ��ȣȭ�� PKCS1 PEM�� �����ϰ�, NULL�� ��� �� PKCS1 PEM�� �����Ѵ�.
* \param rsa
* ������ ISC_RSA_UNIT ����ü
* \param password 
* ��ȣȭ�� PKCS1 PEM�� �����Ϸ��� ��� ����� ����Ű �н�����, NULL�̸� �� PKCS1 PEM�� �����Ѵ�.
* \param passwordLen 
* password�� ����, password�� NULL�� ��� 0�� ����
* \param fileName
* File �̸� ���ڿ��� ������, Ex)"D:\\test.pem"
* \returns
* -# ���ۿ� ������ ���� : ����
* -# -1 : ����
*/
ISC_API int writePKCS1PrivateKey_to_File(ISC_RSA_UNIT *rsa, uint8* password, int passwordLen, const char* fileName);

/*!
* \brief
* ISC_RSA_UNIT ����Ű ����ü�� PKCS1 PEM���� ���ڵ��� �� ���̳ʸ��� ���� �Լ�
* password�� NULL�� �ƴϸ� ��ȣȭ�� PKCS1 PEM�� �����ϰ�, NULL�� ��� �� PKCS1 PEM�� �����Ѵ�.
* \param rsa
* ������ ISC_RSA_UNIT ����ü
* \param password 
* ��ȣȭ�� PKCS1 PEM�� �����Ϸ��� ��� ����� ����Ű �н�����, NULL�̸� �� PKCS1 PEM�� �����Ѵ�.
* \param passwordLen 
* password�� ����, password�� NULL�� ��� 0�� ����
* \param pemBytes
* ���̳ʸ��� ������ ������ ���� ������
* \returns
* -# ���ۿ� ������ ���� : ����
* -# -1 : ����
*/
ISC_API int writePKCS1PrivateKey_to_Binary(ISC_RSA_UNIT *rsa, uint8* password, int passwordLen, uint8** pemBytes);

/*!
* \brief
* ISC_RSA_UNIT ����Ű ����ü�� PKCS1 PEM���� ���ڵ��� �� ���Ϸ� ���� �Լ�
* oid�� �����Ǹ� oid�� �����ϰ� �ִ� ������ PEM�� �����ϰ�, NULL�� ��� �Ϲ�PKCS1������ PEM�� �����Ѵ�.
* \param rsa
* ������ ISC_RSA_UNIT ����ü
* \param oid 
* ����Ű�� OID, NULL�̸� oid�� ���Ե��� ���� �Ϲ�PKCS1������ PEM�� �����Ѵ�.
* \param fileName
* File �̸� ���ڿ��� ������, Ex)"D:\\test.pem"
* \returns
* -# ���ۿ� ������ ���� : ����
* -# -1 : ����
*/
ISC_API int writePKCS1PublicKey_to_File(ISC_RSA_UNIT *rsa, OBJECT_IDENTIFIER *oid, const char* fileName);

/*!
* \brief
* ISC_RSA_UNIT ����Ű ����ü�� PKCS1 PEM���� ���ڵ��� �� ���̳ʸ��� ���� �Լ�
* oid�� �����Ǹ� oid�� �����ϰ� �ִ� ������ PEM�� �����ϰ�, NULL�� ��� �Ϲ�PKCS1������ PEM�� �����Ѵ�.
* \param rsa
* ������ ISC_RSA_UNIT ����ü
* \param oid 
* ����Ű�� OID, NULL�̸� oid�� ���Ե��� ���� �Ϲ�PKCS1������ PEM�� �����Ѵ�.
* \param pemBytes
* ���̳ʸ��� ������ ������ ���� ������
* \returns
* -# ���ۿ� ������ ���� : ����
* -# -1 : ����
*/
ISC_API int writePKCS1PublicKey_to_Binary(ISC_RSA_UNIT *rsa, OBJECT_IDENTIFIER *oid, uint8** pemBytes);
    
/*!
* \brief
* RSAES_OAEP_PARAM ����ü�� �����ϴ� �Լ�
* \returns
* ������ RSAES_OAEP_PARAM ����ü�� ������
*/
ISC_API RSAES_OAEP_PARAM *new_RSAES_OAEP_PARAM(void);

/*!
* \brief
* RSAES_OAEP_PARAM ����ü�� �޸� ���� �Լ�
* \param rsaesoaepParam
* �޸𸮸� ������ ASN1_UNIT ����ü�� ������
*/
ISC_API void free_RSAES_OAEP_PARAM(RSAES_OAEP_PARAM *param);

/*!
* \brief
* RSAES_OAEP_PARAM ����ü�� ���� �ʱ�ȭ�ϴ� �Լ�
* \param rsaesoaepParam
* ���� �ʱ�ȭ �� RSAES_OAEP_PARAM ����ü�� ������
*/
ISC_API void clean_RSAES_OAEP_PARAM(RSAES_OAEP_PARAM *param);

/*!
* \brief
* RSAES_OAEP_PARAM ����ü�� �����ϴ� �Լ�
* \param param
* ������ ���� RSAES_OAEP_PARAM ����ü�� ������
* \returns
* ����� RSAES_OAEP_PARAM ����ü�� ������
*/
ISC_API RSAES_OAEP_PARAM *dup_RSAES_OAEP_PARAM(RSAES_OAEP_PARAM *param);

/*!
* \brief
* RSAES_OAEP_PARAM ����ü�� hashAlgorithm�� �Է�
* \param param
* RSAES_OAEP_PARAM ����ü ������
* \param index
* OAEP-PSSDigestAlgorithms�� OID index
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_RSAES_OAEP_PARAM_hashAlgorithm(RSAES_OAEP_PARAM* param, int index);

/*!
* \brief
* RSAES_OAEP_PARAM ����ü�� hashAlgorithm�� �Է�
* \param param
* RSAES_OAEP_PARAM ����ü ������
* \param oid
* OAEP-PSSDigestAlgorithms�� OID
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_RSAES_OAEP_PARAM_hashAlgorithm_OID(RSAES_OAEP_PARAM* param, OBJECT_IDENTIFIER *oid);

/*!
* \brief
* RSAES_OAEP_PARAM ����ü�� maskGenAlgorithm�� �Է�
* \param param
* RSAES_OAEP_PARAM ����ü ������
* \param index
* PKCS1MGFAlgorithms�� OID index
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_RSAES_OAEP_PARAM_maskGenAlgorithm(RSAES_OAEP_PARAM* param, int index);

/*!
* \brief
* RSAES_OAEP_PARAM ����ü�� maskGenAlgorithm�� �Է�
* \param param
* RSAES_OAEP_PARAM ����ü ������
* \param oid
* PKCS1MGFAlgorithms�� OID
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_RSAES_OAEP_PARAM_maskGenAlgorithm_OID(RSAES_OAEP_PARAM* param, OBJECT_IDENTIFIER *oid);

/*!
* \brief
* RSAES_OAEP_PARAM ����ü�� pSourceAlgorithm�� �Է�
* \param param
* RSAES_OAEP_PARAM ����ü ������
* \param index
* PKCS1pSourceAlgorithms�� OID index
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_RSAES_OAEP_PARAM_pSourceAlgorithm(RSAES_OAEP_PARAM* param, int index, uint8* salt, int saltLen);

/*!
* \brief
* RSAES_OAEP_PARAM ����ü�� pSourceAlgorithm�� �Է�
* \param param
* RSAES_OAEP_PARAM ����ü ������
* \param oid
* PKCS1pSourceAlgorithms�� OID
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_RSAES_OAEP_PARAM_pSourceAlgorithm_OID(RSAES_OAEP_PARAM* param, OBJECT_IDENTIFIER *oid, uint8* salt, int saltLen);

/*!
* \brief
* RSAES_OAEP_PARAM ����ü�� Sequence�� Encode �Լ�
* \param st
* RSAES_OAEP_PARAM ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# RSAES_OAEP_PARAM_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS RSAES_OAEP_PARAM_to_Seq (RSAES_OAEP_PARAM *st, SEQUENCE **seq);

/*!
* \brief
* Sequence�� RSAES_OAEP_PARAM ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param st
* RSAES_OAEP_PARAM ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# Seq_to_RSAES_OAEP_PARAM()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_RSAES_OAEP_PARAM (SEQUENCE *seq, RSAES_OAEP_PARAM **st);


/*!
* \brief
* RSASSA_PSS_PARAM ����ü�� �����ϴ� �Լ�
* \returns
* ������ RSASSA_PSS_PARAM ����ü�� ������
*/
ISC_API RSASSA_PSS_PARAM *new_RSASSA_PSS_PARAM(void);

/*!
* \brief
* RSASSA_PSS_PARAM ����ü�� �޸� ���� �Լ�
* \param param
* �޸𸮸� ������ RSASSA_PSS_PARAM ����ü�� ������
*/
ISC_API void free_RSASSA_PSS_PARAM(RSASSA_PSS_PARAM *param);

/*!
* \brief
* RSASSA_PSS_PARAM ����ü�� ���� �ʱ�ȭ�ϴ� �Լ�
* \param param
* ���� �ʱ�ȭ �� RSASSA_PSS_PARAM ����ü�� ������
*/
ISC_API void clean_RSASSA_PSS_PARAM(RSASSA_PSS_PARAM *param);

/*!
* \brief
* RSASSA_PSS_PARAM ����ü�� �����ϴ� �Լ�
* \param param
* ������ ���� RSASSA_PSS_PARAM ����ü�� ������
* \returns
* ����� RSASSA_PSS_PARAM ����ü�� ������
*/
ISC_API RSASSA_PSS_PARAM *dup_RSASSA_PSS_PARAM(RSASSA_PSS_PARAM *param);

/*!
* \brief
* RSASSA_PSS_PARAM ����ü�� hashAlgorithm�� �Է�
* \param param
* RSASSA_PSS_PARAM ����ü ������
* \param index
* OAEP-PSSDigestAlgorithms�� OID idex
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_RSASSA_PSS_PARAM_hashAlgorithm(RSASSA_PSS_PARAM* param, int index);

/*!
* \brief
* RSASSA_PSS_PARAM ����ü�� hashAlgorithm�� �Է�
* \param param
* RSASSA_PSS_PARAM ����ü ������
* \param oid
* OAEP-PSSDigestAlgorithms�� OID
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_RSASSA_PSS_PARAM_hashAlgorithm_OID(RSASSA_PSS_PARAM* param, OBJECT_IDENTIFIER *oid);

/*!
* \brief
* RSASSA_PSS_PARAM ����ü�� maskGenAlgorithm�� �Է�
* \param param
* RSASSA_PSS_PARAM ����ü ������
* \param index
* PKCS1MGFAlgorithms�� OID index
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_RSASSA_PSS_PARAM_maskGenAlgorithm(RSASSA_PSS_PARAM* param, int index);

/*!
* \brief
* RSASSA_PSS_PARAM ����ü�� maskGenAlgorithm�� �Է�
* \param param
* RSASSA_PSS_PARAM ����ü ������
* \param oid
* PKCS1MGFAlgorithms�� OID
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_RSASSA_PSS_PARAM_maskGenAlgorithm_OID(RSASSA_PSS_PARAM* param, OBJECT_IDENTIFIER *oid);

/*!
* \brief
* RSASSA_PSS_PARAM ����ü�� pSourceAlgorithm�� �Է�
* \param param
* RSASSA_PSS_PARAM ����ü ������
* \param filedNum
* the trailer field number
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_RSASSA_PSS_PARAM_trailerField(RSASSA_PSS_PARAM* param, uint8 filedNum);


/*!
* \brief
* RSASSA_PSS_PARAM ����ü�� Sequence�� Encode �Լ�
* \param st
* RSASSA_PSS_PARAM ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# RSASSA_PSS_PARAM_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS RSASSA_PSS_PARAM_to_Seq (RSASSA_PSS_PARAM *src, SEQUENCE **dst);

/*!
* \brief
* Sequence�� RSAES_OAEP_PARAM ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param st
* RSASSA_PSS_PARAM ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# Seq_to_RSASSA_PSS_PARAM()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_RSASSA_PSS_PARAM (SEQUENCE *src, RSASSA_PSS_PARAM **dst);


/*!
* \brief
* X509_ALGO_IDENTIFIER ����ü�� RSAES_OAEP_PARAM�� �Է�
* \param x509Algo
* X509_ALGO_IDENTIFIER ����ü ������
* \param param
* RSAES_OAEP_PARAM ����ü ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS  set_X509_ALGO_IDENTIFIER_with_RSAES_OAEP_PARAM(X509_ALGO_IDENTIFIER *x509Algo, RSAES_OAEP_PARAM *param);

/*!
* \brief
* X509_ALGO_IDENTIFIER ����ü�� RSASSA_PSS_PARAM�� �Է�
* \param x509Algo
* X509_ALGO_IDENTIFIER ����ü ������
* \param param
* RSASSA_PSS_PARAM ����ü ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_X509_ALGO_IDENTIFIER_with_RSASSA_PSS_PARAM(X509_ALGO_IDENTIFIER *x509Algo, RSASSA_PSS_PARAM *param);

    
/*!
 * \brief
 * ISC_ECDSA_UNIT ����Ű ����ü�� PEM���� ���ڵ��� �� ���Ϸ� ���� �Լ� - RFC5480 ����
 * oid�� �����Ǹ� oid�� �����ϰ� �ִ� ������ PEM�� �����ϰ�, NULL�� ��� �Ϲ� ������ PEM�� �����Ѵ�.
 * \param ecdsa
 * ������ ISC_ECDSA_UNIT ����ü
 * \param fileName
 * File �̸� ���ڿ��� ������, Ex)"D:\\test.pem"
 * \returns
 * -# ���ۿ� ������ ���� : ����
 * -# -1 : ����
 */
ISC_API int writeECDSAPublicKey_to_File(ISC_ECDSA_UNIT *ecdsa, const char* fileName);

/*!
 * \brief
 * ISC_ECDSA_UNIT ����Ű ����ü�� PEM���� ���ڵ��� �� ���̳ʸ��� ���� �Լ� - RFC5480 ����
 * oid�� �����Ǹ� oid�� �����ϰ� �ִ� ������ PEM�� �����ϰ�, NULL�� ��� PEM�� �����Ѵ�.
 * \param ecdsa
 * ������ ISC_ECDSA_UNIT ����ü
 * \param pemBytes
 * ���̳ʸ��� ������ ������ ���� ������
 * \returns
 * -# ���ۿ� ������ ���� : ����
 * -# -1 : ����
 */
ISC_API int writeECDSAPublicKey_to_Binary(ISC_ECDSA_UNIT *ecdsa, uint8** pemBytes);

/*!
 * \brief
 * ISC_ECDSA_UNIT ����Ű ����ü�� PKCS1 PEM���� ���ڵ��� �� ���Ϸ� ���� �Լ�
 * password�� NULL�� �ƴϸ� ��ȣȭ�� PKCS1 PEM�� �����ϰ�, NULL�� ��� �� PKCS1 PEM�� �����Ѵ�.
 * \param rsa
 * ������ ISC_ECDSA_UNIT ����ü
 * \param password
 * ��ȣȭ�� PKCS1 PEM�� �����Ϸ��� ��� ����� ����Ű �н�����, NULL�̸� �� PKCS1 PEM�� �����Ѵ�.
 * \param passwordLen
 * password�� ����, password�� NULL�� ��� 0�� ����
 * \param fileName
 * File �̸� ���ڿ��� ������, Ex)"D:\\test.pem"
 * \returns
 * -# ���ۿ� ������ ���� : ����
 * -# -1 : ����
 */
ISC_API int writeECDSAPrivateKey_to_File(ISC_ECDSA_UNIT *ecdsa, uint8* password, int passwordLen, const char* fileName);

/*!
 * \brief
 * ISC_ECDSA_UNIT ����Ű ����ü�� PKCS1 PEM���� ���ڵ��� �� ���̳ʸ��� ���� �Լ�
 * password�� NULL�� �ƴϸ� ��ȣȭ�� PKCS1 PEM�� �����ϰ�, NULL�� ��� �� PKCS1 PEM�� �����Ѵ�.
 * \param rsa
 * ������ ISC_ECDSA_UNIT ����ü
 * \param password
 * ��ȣȭ�� PKCS1 PEM�� �����Ϸ��� ��� ����� ����Ű �н�����, NULL�̸� �� PKCS1 PEM�� �����Ѵ�.
 * \param passwordLen
 * password�� ����, password�� NULL�� ��� 0�� ����
 * \param pemBytes
 * ���̳ʸ��� ������ ������ ���� ������
 * \returns
 * -# ���ۿ� ������ ���� : ����
 * -# -1 : ����
 */
ISC_API int writeECDSAPrivateKey_to_Binary(ISC_ECDSA_UNIT *ecdsa, uint8* password, int passwordLen, uint8** pemBytes);

/*!
 * \brief
 * get Asymmetric key Type
 * \param asymmkey
 * Sequence of key
 * \param typeAsymmKey
 * type of Asymmetric-key
 * \returns
 * -# 0 : success
 * -# -1 : fail
 */
ISC_API int getAsymmkeyType_from_sequence(SEQUENCE* asymmkey, int* typeAsymmKey);

/*!
 * \brief
 * get Asymmetric key Type
 * \param asymmkey
 * buffer of key-array
 * \param length_asymmkey
 * length of key-array
 * \param typeAsymmKey
 * type of Asymmetric-key
 * \returns
 * -# 0 : success
 * -# -1 : fail
 */
ISC_API int getAsymmkeyType(uint8* asymmkey, int length_asymmkey, int* typeAsymmKey);
    
#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(PKCS1_RSA_PRIVATE_KEY*, new_PKCS1_RSA_PRIVATE_KEY, (void), (), NULL);
INI_RET_LOADLIB_PKI(PKCS1_RSA_PUBLIC_KEY*, new_PKCS1_RSA_PUBLIC_KEY, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_PKCS1_RSA_PRIVATE_KEY, (PKCS1_RSA_PRIVATE_KEY *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, free_PKCS1_RSA_PUBLIC_KEY, (PKCS1_RSA_PUBLIC_KEY *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_PKCS1_RSA_PRIVATE_KEY, (PKCS1_RSA_PRIVATE_KEY *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_PKCS1_RSA_PUBLIC_KEY, (PKCS1_RSA_PUBLIC_KEY *unit), (unit) );
INI_RET_LOADLIB_PKI(ISC_STATUS, PKCS1_RSA_PRIVATE_KEY_to_Seq, (PKCS1_RSA_PRIVATE_KEY *unit, SEQUENCE** out), (unit,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, PKCS1_RSA_PUBLIC_KEY_to_Seq, (PKCS1_RSA_PUBLIC_KEY *unit, SEQUENCE** out), (unit,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_PKCS1_RSA_PRIVATE_KEY, (SEQUENCE* in, PKCS1_RSA_PRIVATE_KEY **out), (in,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_PKCS1_RSA_PUBLIC_KEY, (SEQUENCE* in, PKCS1_RSA_PUBLIC_KEY **out), (in,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, get_RSA_UNIT_from_PKCS1_RSA_PRIVATE_KEY, (ISC_RSA_UNIT **rsa, PKCS1_RSA_PRIVATE_KEY *pkcs1), (rsa,pkcs1), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, get_RSA_UNIT_from_PKCS1_RSA_PUBLIC_KEY, (ISC_RSA_UNIT **rsa, PKCS1_RSA_PUBLIC_KEY *pkcs1), (rsa,pkcs1), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSA_UNIT_to_PKCS1_RSA_PRIVATE_KEY, (ISC_RSA_UNIT *rsa, PKCS1_RSA_PRIVATE_KEY **pkcs1), (rsa,pkcs1), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSA_UNIT_to_PKCS1_RSA_PUBLIC_KEY, (ISC_RSA_UNIT *rsa, PKCS1_RSA_PUBLIC_KEY **pkcs1), (rsa,pkcs1), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, PBKDF, (uint8* password, int passwordLen, uint8* salt, uint8* dk_buf, int dkLen), (password,passwordLen,salt,dk_buf,dkLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, readPKCS1_from_File, (ISC_RSA_UNIT **rsa, uint8* password, int passwordLen, const char* fileName), (rsa,password,passwordLen,fileName), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, readPKCS1_from_Binary, (ISC_RSA_UNIT **rsa, uint8* password, int passwordLen, uint8* pemBytes, int pemLength), (rsa,password,passwordLen,pemBytes,pemLength), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, writePKCS1PrivateKey_to_File, (ISC_RSA_UNIT *rsa, uint8* password, int passwordLen, const char* fileName), (rsa,password,passwordLen,fileName), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, writePKCS1PrivateKey_to_Binary, (ISC_RSA_UNIT *rsa, uint8* password, int passwordLen, uint8** pemBytes), (rsa,password,passwordLen,pemBytes), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, writePKCS1PublicKey_to_File, (ISC_RSA_UNIT *rsa, OBJECT_IDENTIFIER *oid, const char* fileName), (rsa,oid,fileName), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, writePKCS1PublicKey_to_Binary, (ISC_RSA_UNIT *rsa, OBJECT_IDENTIFIER *oid, uint8** pemBytes), (rsa,oid,pemBytes), ISC_FAIL);
INI_RET_LOADLIB_PKI(RSAES_OAEP_PARAM*, new_RSAES_OAEP_PARAM, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_RSAES_OAEP_PARAM, (RSAES_OAEP_PARAM *param), (param) );
INI_VOID_LOADLIB_PKI(void, clean_RSAES_OAEP_PARAM, (RSAES_OAEP_PARAM *param), (param) );
INI_RET_LOADLIB_PKI(RSAES_OAEP_PARAM*, dup_RSAES_OAEP_PARAM, (RSAES_OAEP_PARAM *param), (param), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSAES_OAEP_PARAM_hashAlgorithm, (RSAES_OAEP_PARAM* param, int index), (param,index), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSAES_OAEP_PARAM_hashAlgorithm_OID, (RSAES_OAEP_PARAM* param, OBJECT_IDENTIFIER *oid), (param,oid), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSAES_OAEP_PARAM_maskGenAlgorithm, (RSAES_OAEP_PARAM* param, int index), (param,index), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSAES_OAEP_PARAM_maskGenAlgorithm_OID, (RSAES_OAEP_PARAM* param, OBJECT_IDENTIFIER *oid), (param,oid), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSAES_OAEP_PARAM_pSourceAlgorithm, (RSAES_OAEP_PARAM* param, int index, uint8* salt, int saltLen), (param,index,salt,saltLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSAES_OAEP_PARAM_pSourceAlgorithm_OID, (RSAES_OAEP_PARAM* param, OBJECT_IDENTIFIER *oid, uint8* salt, int saltLen), (param,oid,salt,saltLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, RSAES_OAEP_PARAM_to_Seq, (RSAES_OAEP_PARAM *st, SEQUENCE **seq), (st,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_RSAES_OAEP_PARAM, (SEQUENCE *seq, RSAES_OAEP_PARAM **st), (seq,st), ISC_FAIL);
INI_RET_LOADLIB_PKI(RSASSA_PSS_PARAM*, new_RSASSA_PSS_PARAM, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_RSASSA_PSS_PARAM, (RSASSA_PSS_PARAM *param), (param) );
INI_VOID_LOADLIB_PKI(void, clean_RSASSA_PSS_PARAM, (RSASSA_PSS_PARAM *param), (param) );
INI_RET_LOADLIB_PKI(RSASSA_PSS_PARAM*, dup_RSASSA_PSS_PARAM, (RSASSA_PSS_PARAM *param), (param), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSASSA_PSS_PARAM_hashAlgorithm, (RSASSA_PSS_PARAM* param, int index), (param,index), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSASSA_PSS_PARAM_hashAlgorithm_OID, (RSASSA_PSS_PARAM* param, OBJECT_IDENTIFIER *oid), (param,oid), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSASSA_PSS_PARAM_maskGenAlgorithm, (RSASSA_PSS_PARAM* param, int index), (param,index), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSASSA_PSS_PARAM_maskGenAlgorithm_OID, (RSASSA_PSS_PARAM* param, OBJECT_IDENTIFIER *oid), (param,oid), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSASSA_PSS_PARAM_trailerField, (RSASSA_PSS_PARAM* param, uint8 filedNum), (param,filedNum), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, RSASSA_PSS_PARAM_to_Seq, (RSASSA_PSS_PARAM *src, SEQUENCE **dst), (src,dst), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_RSASSA_PSS_PARAM, (SEQUENCE *src, RSASSA_PSS_PARAM **dst), (src,dst), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_ALGO_IDENTIFIER_with_RSAES_OAEP_PARAM, (X509_ALGO_IDENTIFIER *x509Algo, RSAES_OAEP_PARAM *param), (x509Algo,param), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_ALGO_IDENTIFIER_with_RSASSA_PSS_PARAM, (X509_ALGO_IDENTIFIER *x509Algo, RSASSA_PSS_PARAM *param), (x509Algo,param), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, writeECDSAPublicKey_to_File, (ISC_ECDSA_UNIT *ecdsa, const char* fileName), (ecdsa, fileName), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, writeECDSAPublicKey_to_Binary, (ISC_ECDSA_UNIT *ecdsa, uint8** pemBytes), (ecdsa, pemBytes), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, writeECDSAPrivateKey_to_File, (ISC_ECDSA_UNIT *ecdsa, uint8* password, int passwordLen, const char* fileName), (ecdsa,password,passwordLen,fileName), (x509Algo,param), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, writeECDSAPrivateKey_to_Binary, (ISC_ECDSA_UNIT *ecdsa, uint8* password, int passwordLen, uint8** pemBytes), (ecdsa,password,passwordLen,pemBytes), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, getAsymmkeyType_from_sequence, (SEQUENCE* asymmkey, int* typeAsymmKey), (asymmkey, typeAsymmKey), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, getAsymmkeyType, (uint8* asymmkey, int length_asymmkey, int* typeAsymmKey), (asymmkey, length_asymmkey, typeAsymmKey), ISC_FAIL); 
#endif

#ifdef  __cplusplus
}
#endif
#endif
