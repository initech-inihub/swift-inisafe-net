/*!
* \file rsa.h
* \brief rsa �������
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_RSA_H
#define HEADER_RSA_H

#include "biginteger.h"
#include "digest.h"
#include "foundation.h"

#ifdef ISC_NO_RSA
#error ISC_RSA is disabled.
#endif

/* Flag Definition
 |---------------------------------------------------------------|
 |-------------Algorithm Identification-----------|-------|-------|
 | 4bits | 4bits | 4bits | 4bits | 4bits | 4bits | 4bits | 4bits |
 |---------------------------------------------------------------|
---------------------------------------------------------------------------------
ISC_RSA Alias				0x20000000 ------------------------------------------------ */
#define ISC_RSA				0x20000000   /*!< ISC_RSA �˰��� ID */

/*SHA1withRSA <-- ISC_RSA | ISC_SHA1 (0x25000100) */

/*Pram type */
#define ISC_RSA_N_VALUE_HAVE         0x01   /*!< modulas Value �� �����*/
#define ISC_RSA_E_VALUE_HAVE		 0x02   /*!< e Value �� �����*/
#define ISC_RSA_PUBLIC_VALUE_HAVE	 0x03   /*!< e and n Value �� �����*/
#define ISC_RSA_D_VALUE_HAVE		 0x04   /*!< d Value �� �����*/
#define ISC_RSA_PRIVATE_VALUE_HAVE	 0x05	/*!< d and n Value �� �����*/
#define ISC_RSA_CRT_VALUE_HAVE       0x08   /*!< CRT Value �� �����*/
#define ISC_RSA_FULL_VALUE_HAVE		 0x1F   /*!< ALL Value �� ����� Value*/

/* encode Identification 

|	1byte	|	1byte	|	1byte	|	1byte	|
|-----------------------------------------------|
|	 MGF 	|	SALT	|	MGF		|  PADDING	|
|-----------------------------------------------|

*/

#define ISC_RSA_PADDING_MASK			0x000000FF
#define ISC_RSA_NO_ENCODE				0x00	/*!< ISC_RSA No Encode*/
#define ISC_RSASSA_PKCS1_v1_5_ENCODE	0x01	/*!< ISC_RSA ���� PKCS1 v1.5 ENCODE*/
#define ISC_RSASSA_PSS_ENCODE			0x02	/*!< ISC_RSA ���� PSS ENCODE*/

#define ISC_RSAES_OAEP_v2_0_ENCODE		0x08	/*!< ISC_RSA ��ȣȭ OAEP v2.0 ENCODE*/
#define ISC_RSAES_OAEP_v2_1_ENCODE		0x10	/*!< ISC_RSA ��ȣȭ OAEP v2.1 ENCODE*/
#define ISC_RSAES_PKCS1_v1_5_ENCODE		0x20	/*!< ISC_RSA ��ȣȭ PKCS1 v1.5 ENCODE*/

#define ISC_RSA_MGF_MASK				0xFF00FF00
#define ISC_RSA_MGF_SHA1				ISC_SHA1	/*!< MGF ISC_SHA1 �˰���*/
#define ISC_RSA_MGF_SHA224				ISC_SHA224	/*!< MGF ISC_SHA224 �˰���*/
#define ISC_RSA_MGF_SHA256				ISC_SHA256	/*!< MGF ISC_SHA256 �˰���*/
#define ISC_RSA_MGF_SHA384				ISC_SHA384	/*!< MGF ISC_SHA384 �˰���*/
#define ISC_RSA_MGF_SHA512				ISC_SHA512	/*!< MGF ISC_SHA512 �˰���*/
#define ISC_RSA_MGF_MD5					ISC_MD5	/*!< MGF ISC_MD5 �˰���*/

#define ISC_RSASSA_SALT_MASK			0x00FF0000
#define ISC_RSASSA_PSS_SALT_16			0x100000 /*!< PSS Salt ���� 16*/
#define ISC_RSASSA_PSS_SALT_20			0x140000 /*!< PSS Salt ���� 20*/
#define ISC_RSASSA_PSS_SALT_28			0x1C0000 /*!< PSS Salt ���� 28*/
#define ISC_RSASSA_PSS_SALT_32			0x200000 /*!< PSS Salt ���� 32*/
#define ISC_RSASSA_PSS_SALT_48			0x300000 /*!< PSS Salt ���� 48*/
#define ISC_RSASSA_PSS_SALT_64			0x400000 /*!< PSS Salt ���� 64*/

#define ISC_RSAES_PKCS1_v1_5_KEYPAIR	1	/*!< ISC_RSA ��ȣȭ PKCS1 v1.5 Ű����*/
#define ISC_RSAES_PKCS1_v2_0_KEYPAIR	2	/*!< ISC_RSA ��ȣȭ PKCS1 v2.0 Ű����*/

#define ISC_RSA_SIGN					1	/*!< ISC_RSA ����*/
#define ISC_RSA_VERIFY					0	/*!< ISC_RSA ����*/
#define ISC_RSA_ENCRYPTION				0	/*!< ISC_RSA ����Ű ��ȣȭ*/
#define ISC_RSA_DECRYPTION				1	/*!< ISC_RSA ����Ű ��ȣȭ*/

/* Ư���� ��쿡 �Ʒ����� ����ϼ���. */
#define ISC_RSA_PUBLIC_ENCRYPTION		0  /*!< ISC_RSA ����Ű ��ȣȭ*/
#define ISC_RSA_PRIVATE_ENCRYPTION		1  /*!< ISC_RSA ����Ű ��ȣȭ*/

#define ISC_RSA_PUBLIC_DECRYPTION		0	/*!< ISC_RSA ����Ű ��ȣȭ*/
#define ISC_RSA_PRIVATE_DECRYPTION		1  /*!< ISC_RSA ����Ű ��ȣȭ*/

/*������ ����� ��� �����ϴ� �κ� */
#define ISC_RSAES_PROVEN_MODE			1    /*!<  0: ����� ���, 1: ������� */
#define ISC_RSASSA_PROVEN_MODE			1    /*!<  0: ����� ���, 1: ������� */

/* test rsaes oaep encryption */
/*
#define RSAES_VECTORTEST
*/

/*!
* \brief
* ISC_RSA �˰����� ���� ����ü
*/
struct isc_rsa_st
{
	int encode; 	/*!< ���ڵ� ���*/
	int param_type;	 	/*!< ����� Parameter�� ����*/
	ISC_DIGEST_UNIT *d_unit;	/*!< ISC_DIGEST_UNIT*/
	ISC_BIGINT *e;	/*!< ����Ű ���� e*/
	ISC_BIGINT *d;	/*!< ���Ű ���� e*/
	ISC_BIGINT *n;	/*!< Modulas n*/
	ISC_BIGINT *p;	/*!< �Ҽ� p*/
	ISC_BIGINT *dp; /*!< CRT ��*/
	ISC_BIGINT *q;  /*!< �Ҽ� q*/
	ISC_BIGINT *dq;  /*!< CRT ��*/
	ISC_BIGINT *qInv;  /*!< CRT ��*/
	int is_private;  /*!< Public : 0 , Private : 1*/
	ISC_BIGINT_POOL *pool; /*!< ���� ȿ���� ���� Ǯ */
	int use_crt;	/*<! CRT ������ ������� ���� */
	int pss_salt_length; /*<! PSS ���� ����� salt ����, 0 ���� �� �ؽ� �˰����� ���̸� ��� */
#ifdef ISC_RSA_BLINDING
	ISC_BIGINT *r_e;  /*!< r^(e)*/
	ISC_BIGINT *r_Inv;  /*!< r^(-1) mod n*/
#endif
};


#ifdef  __cplusplus
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_RSA_UNIT ����ü�� �޸� �Ҵ�
* \returns
* ISC_RSA_UNIT ����ü
*/
ISC_API ISC_RSA_UNIT *ISC_New_RSA(void);

/*!
* \brief
* ISC_RSA_UNIT �޸� ���� �Լ�
* \param unit
* �޸� ������ ISC_RSA_UNIT
*/
ISC_API void ISC_Free_RSA(ISC_RSA_UNIT *unit);

/*!
* \brief
* ISC_RSA_UNIT �޸� �ʱ�ȭ �Լ�
* \param unit
* �ʱ�ȭ �� ISC_RSA_UNIT
*/
ISC_API void ISC_Clean_RSA(ISC_RSA_UNIT *unit);

/*!
* \brief
* ISC_RSA_UNIT ����ü�� ������
* \returns
* ISC_RSA_UNIT ����ü
*/
ISC_API ISC_RSA_UNIT *ISC_Dup_RSA(ISC_RSA_UNIT *src);

/*!
* \brief
* ISC_RSA Parameter �Է�
* \param rsa
* Parameter�� �Էµ� ISC_RSA_UNIT
* \param n
* modulas n.
* \param e
* ����Ű Exponent
* \param d
* ���Ű Exponent
* \param p
* prime p.
* \param q
* prime q.
* \param dp
* CRT Value dp.
* \param dq
* CRT Value dq.
* \param inv_q
* CRT Value inv_q.
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# LOCATION^ISC_F_SET_RSA_PRAMS^ISC_ERR_INVALID_INPUT : e�� n�� NULL�� ���
* -# LOCATION^ISC_F_SET_RSA_PRAMS^ISC_ERR_SUB_OPERATION_FAILURE : ���� �Լ� ����
*/
ISC_API ISC_STATUS ISC_Set_RSA_Params(ISC_RSA_UNIT *rsa,
				   const ISC_BIGINT *n,
				   const ISC_BIGINT *e,
				   const ISC_BIGINT *d,
				   const ISC_BIGINT *p,
				   const ISC_BIGINT *q,
				   const ISC_BIGINT *dp,
				   const ISC_BIGINT *dq,
				   const ISC_BIGINT *inv_q);

/*!
* \brief
* ISC_RSA Public Parameter ���� �Է�
* \param rsa
* Parameter�� �Էµ� ISC_RSA_UNIT
* \param n
* modulas n.
* \param e
* ����Ű Exponent
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# LOCATION^ISC_F_SET_RSA_PUBLIC_PRAMS^ISC_ERR_INVALID_INPUT : e�� n�� NULL�� ���
*/
ISC_API ISC_STATUS ISC_Set_RSA_Public_Params(ISC_RSA_UNIT *rsa,  const ISC_BIGINT* n, const ISC_BIGINT* e);

/*!
* \brief
* RSA ���ڼ��� �˰��� �ʱ�ȭ
* \param rsa
* �ʱ�ȭ �� ISC_RSA_UNIT
* \param digest_alg
* RSA�� �Բ� ���Ǵ� DIGEST Algorithm ID (digest.h ����)
* \param encode
* ���ڵ� Ÿ�� | MGF �ؽ� �˰��� | SALT ���� (ISC_RSASSA_PSS_ENCODE | ISC_RSA_MGF_SHA256 | ISC_RSASSA_PSS_SALT_32)
* \param sign
* (ISC_RSA_SIGN)1 : ����, (ISC_RSA_VERIFY)0 : ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_RSA^ISC_F_INIT_RSASSA^ISC_ERR_INVALID_RSA_ENCODING : �������� �ʴ� ���ڵ� Ÿ��
* -# ISC_L_RSA^ISC_F_INIT_RSASSA^ISC_ERR_NOT_PROVEN_ALGORITHM : ������忡�� ����� �˰��� ��� 
* -# ISC_L_RSA^ISC_F_INIT_RSASSA^ISC_ERR_NOT_SUPPORTED : �������� �ʴ� Ű ���� �Է�
* -# ISC_L_RSA^ISC_F_INIT_RSASSA^ISC_ERR_INIT_FAILURE : RSASSA INIT ����
* -# ISC_L_RSA^ISC_F_INIT_RSASSA^ISC_ERR_SUB_OPERATION_FAILURE : ISC_DIGEST Algorithm �ʱ�ȭ ����
*/
ISC_API ISC_STATUS ISC_Init_RSASSA(ISC_RSA_UNIT *rsa, int digest_alg, int encode, int sign);

/*!
* \brief
* RSA ���ڼ��� �޽��� �Է�(Update) �Լ�
* \param rsa
* ISC_RSA_UNIT ����ü ������
* \param data
* �Էµ� ������(������ �Է� ����)
* \param length
* �������� ����
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_UPDATE_RSASSA^ISC_ERR_NULL_INPUT : �Էµ� ISC_RSA_UNIT�� NULL�� ���
* -# ISC_L_RSA^ISC_F_UPDATE_RSASSA^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ����(DIGEST) ����
*/
ISC_API ISC_STATUS ISC_Update_RSASSA(ISC_RSA_UNIT *rsa, const uint8 *data, int length);

/*!
* \brief
* RSA ���ڼ����� ���� ���� / ���� �Լ�
* \param rsa
* ISC_RSA_UNIT ����ü ������
* \param signature
* ���� ������
* \param sLen
* ������ ������ ������, ���� ������ ��� ������ ������ ���̰� ��ȯ
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_RSA^ISC_F_FINAL_RSASSA^ISC_ERR_NULL_INPUT : �Էµ� ISC_RSA_UNIT�� NULL�� ���
* -# ISC_L_RSA^ISC_F_FINAL_RSASSA^ISC_ERR_NOT_SUPPORTED : �������� �ʴ� �˰��� Ű ���� �Է�
* -# ISC_L_RSA^ISC_F_FINAL_RSASSA^ISC_ERR_NO_PRIVATE_VALUE : ���Ű�� ���� ���� ���� �õ�
* -# ISC_L_RSA^ISC_F_FINAL_RSASSA^ISC_ERR_NO_PUBLIC_VALUE : ����Ű�� ���� ���� ���� �õ�
* -# ISC_Sign_RSASSA()�� �����ڵ�
* -# ISC_Verify_RSASSA()�� �����ڵ�
*/
ISC_API ISC_STATUS ISC_Final_RSASSA(ISC_RSA_UNIT *rsa, uint8 *signature, int *sLen);

/*!
* \brief
* RSA ���ڼ����� ���� ����
* \param rsa
* ISC_RSA_UNIT ����ü ������
* \param signature
* ����
* \param sLen
* ������ ������ ������, ���� ������ ��� ������ ������ ���̰� ��ȯ
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_MALLOC : ���� ������ �޸� �Ҵ� ����
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ������ ����
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_NOT_PROVEN_ALGORITHM : ������忡�� ����� ��� �˰��� ���
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_NOT_SUPPORTED : �������� �ʴ� ���ڵ� Ÿ�� �Է�
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_MESSAGE_TOO_LONG : �޽����� Modulas���� ŭ
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_ENCODING_FAILURE : ���ڵ� ����
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY to BIGINT ��ȯ ����
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_INVALID_ENCODE_MODE : �߸��� ���ڵ� Ÿ�� �Է�
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_MESSAGE_TOO_LONG : �޽����� n���� ŭ
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_INVALID_KEY_PAIR : Ű�� ��ġ ����
* -# LOCATION^ISC_F_SIGN_RSASSA^ISC_ERR_SIGN_FAILURE : ���� ����
*/
ISC_API ISC_STATUS ISC_Sign_RSASSA(ISC_RSA_UNIT *rsa, uint8 *signature, int *sLen);

/*!
* \brief
* RSA ���ڼ����� ���� ����
* \param rsa
* ISC_RSA_UNIT ����ü ������
* \param signature
* ����
* \param sLen
* ������ ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_RSA^ISC_F_VERIFY_RSASSA^ISC_ERR_MALLOC : ���� ������ �޸� �Ҵ� ����
* -# ISC_L_RSA^ISC_F_VERIFY_RSASSA^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ����(DIGEST/BIGINT) ����
* -# ISC_L_RSA^ISC_F_VERIFY_RSASSA^ISC_ERR_INVALID_INPUT : �߸��� �Է°� �Է�
* -# ISC_L_RSA^ISC_F_VERIFY_RSASSA^ISC_ERR_SIGNATURE_TOO_LONG : ������ Modulas���� ŭ
* -# ISC_L_RSA^ISC_F_VERIFY_RSASSA^ISC_ERR_NOT_PROVEN_ALGORITHM : ������忡�� ����� �˰��� ���
* -# ISC_L_RSA^ISC_F_VERIFY_RSASSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY to BIGINT ��ȯ ����
* -# ISC_L_RSA^ISC_F_VERIFY_RSASSA^ISC_ERR_DECODING_FAILURE : ���� ���ڵ� ����
*/
ISC_API ISC_STATUS ISC_Verify_RSASSA(ISC_RSA_UNIT *rsa, uint8 *signature, int sLen);

/*!
* \brief
* ������ ����Ű e�� ����� RSA Parameters ���� �Լ� (�ؽ� �˰��� �Է� ����)
* \param rsa
* ISC_RSA_UNIT ����ü ������
* \param e_value
* ISC_RSA ����Ű Exponent
* \param bits
* ISC_RSA Bits Length
* \param version
* PKCS#1 v1.5 : 1
* PKCS#1 v2.0 : 2
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# LOCATION^ISC_F_GENERATE_RSA_PARAMS_EX^ISC_ERR_INVALID_INPUT : �Է� �Ķ���� ����
* -# LOCATION^ISC_F_GENERATE_RSA_PARAMS_EX^ISC_ERR_NOT_SUPPORTED: �������� �ʴ� �˰���
* -# LOCATION^ISC_F_GENERATE_RSA_PARAMS_EX^ISC_ERR_GET_BIGINT_POOL_FAIL: BIGINT POOL ���� ����
* -# LOCATION^ISC_F_GENERATE_RSA_PARAMS_EX^ISC_ERR_MALLOC: �޸� �Ҵ� ����
* -# LOCATION^ISC_F_GENERATE_RSA_PARAMS_EX^ISC_ERR_IS_BIGINT_PRIME: �Ҽ� �Ǻ� ����
* -# LOCATION^ISC_F_GENERATE_RSA_PARAMS_EX^ISC_ERR_KEY_GEN_FAIL: Ű ��ȿ�� ���� ����
*/
ISC_API ISC_STATUS ISC_Generate_RSA_Params_Ex(ISC_RSA_UNIT *rsa, ISC_BIGINT *e_value, int bits, int version);

/*!
* \brief
* ������ ����Ű e�� ����� ISC_RSA Parameters ���� �Լ�
* \param rsa
* ISC_RSA_UNIT ����ü ������
* \param e_value
* ISC_RSA ����Ű Exponent
* \param bits
* ISC_RSA Bits Length
* \param version
* PKCS#1 v1.5 : 1
* PKCS#1 v2.0 : 2
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_RSA^ISC_F_GENERATE_RSA_PARAMS^ISC_ERR_INVALID_INPUT : �߸��� �Է°� �Է�
* -# ISC_L_RSA^ISC_F_GENERATE_RSA_PARAMS^ISC_ERR_GET_BIGINT_POOL_FAIL : BIGINT POOL ���� ����
* -# ISC_L_RSA^ISC_F_GENERATE_RSA_PARAMS^ISC_ERR_MALLOC : �޸� �Ҵ� ����
* -# ISC_L_RSA^ISC_F_GENERATE_RSA_PARAMS^ISC_ERR_IS_BIGINT_PRIME : �Ҽ� �Ǻ� ����
* -# ISC_L_RSA^ISC_F_GENERATE_RSA_PARAMS^ISC_ERR_KEY_GEN_FAIL : Ű ��ȿ�� ���� ����
*/
ISC_API ISC_STATUS ISC_Generate_RSA_Params(ISC_RSA_UNIT *rsa, ISC_BIGINT *e_value, int bits, int version);


/*!
* \brief
* RSA ��ȣȭ �˰��� �ʱ�ȭ
* \param rsa
* �ʱ�ȭ �� ISC_RSA_UNIT
* \param encode
* ���ڵ� Ÿ�� | MGF �ؽ� �˰��� (ISC_RSAES_OAEP_v2_1_ENCODE | ISC_RSA_MGF_SHA256)
* \param encryption
* (ISC_RSA_PRIVATE_DECRYPTION)1 : ��ȣȭ, (ISC_RSA_ENCRYPTION )0 : ��ȣȭ
* \param digest_algo
* �е��� ����� �ؽ� �˰��� �Է�(default(ISC_SHA1)�� ����ϰ��� �Ҷ��� "0"�Է�)
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_RSA^ISC_F_INIT_RSAES^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_RSA^ISC_F_INIT_RSAES^ISC_ERR_INVALID_RSA_ENCODING : �߸��� ���ڵ� �Է�
* -# ISC_L_RSA^ISC_F_INIT_RSAES^ISC_ERR_NOT_SUPPORTED : �������� �ʴ� Ű ���� �Է�
* -# ISC_L_RSA^ISC_F_INIT_RSAES^ISC_ERR_NOT_PROVEN_ALGORITHM : ������忡�� ����� �˰��� ���
* -# ISC_L_RSA^ISC_F_INIT_RSAES^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ����(DIGEST) ����
*/
ISC_API ISC_STATUS ISC_Init_RSAES(ISC_RSA_UNIT *rsa, int encode, int encryption, int digest_algo);

/*!
* \brief
* RSA ��ȣȭ �Լ�
* \param rsa
* ISC_RSA_UNIT ����ü ������
* \param out
* ��� ����
* \param outLen
* ��� ������ ���� ������, �Լ� �����Ŀ� ��� ���ۿ� ����� ���̰� �Էµ�
* \param in
* �Է�
* \param inLen
* �Է� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_INVALID_INPUT : �߸��� �Է°� �Է�
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_NO_PRIVATE_VALUE : ����Ű ������ ����
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_NO_PUBLIC_VALUE : ����Ű ������ ����
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_NOT_SUPPORTED : �������� �ʴ� Ű ���� ���
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_MALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ����(BIGINT) ����
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_NOT_PROVEN_ALGORITHM : ������忡�� ����� �˰��� ���
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_INVALID_RSA_ENCODING : �߸��� ���ڵ� �Է�
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_ENCODING_FAILURE : ���ڵ� ����
* -# ISC_L_RSA^ISC_F_ENCRYPT_RSAES^ISC_ERR_MESSAGE_TOO_LONG : �Է°�(���ڵ� �� �Է°�)�� modulas���� ŭ
*/
ISC_API ISC_STATUS ISC_Encrypt_RSAES(ISC_RSA_UNIT *rsa, uint8 *out, int *outLen, const uint8 *in, int inLen);

/*!
* \brief
* RSA ��ȣȭ �Լ�
* \param rsa
* ISC_RSA_UNIT ����ü ������
* \param out
* ��� ����
* \param outLen
* ��� ������ ����, �Լ� �����Ŀ� ��� ���ۿ� ����� ���̰� �Էµ�
* \param in
* �Է�
* \param inLen
* �Է� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_RSA^ISC_F_DECRYPT_RSAES^ISC_ERR_NO_PRIVATE_VALUE : ����Ű ������ ����
* -# ISC_L_RSA^ISC_F_DECRYPT_RSAES^ISC_ERR_NO_PUBLIC_VALUE : ����Ű ������ ����
* -# ISC_L_RSA^ISC_F_DECRYPT_RSAES^ISC_ERR_NOT_SUPPORTED : �������� �ʴ� Ű ���� �Է�
* -# ISC_L_RSA^ISC_F_DECRYPT_RSAES^ISC_ERR_MALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_RSA^ISC_F_DECRYPT_RSAES^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ����(BIGINT) ����
* -# ISC_L_RSA^ISC_F_DECRYPT_RSAES^ISC_ERR_MESSAGE_TOO_LONG : �Է°�(���ڵ� �� �Է°�)�� modulas���� ŭ
* -# ISC_L_RSA^ISC_F_DECRYPT_RSAES^ISC_ERR_INVALID_KEY_PAIR : Ű�� ��ġ ����
* -# ISC_L_RSA^ISC_F_DECRYPT_RSAES^ISC_ERR_NOT_PROVEN_ALGORITHM : ������忡�� ����� �˰��� ���
* -# ISC_L_RSA^ISC_F_DECRYPT_RSAES^ISC_ERR_DECODING_FAILURE : ���ڵ� ����
*/
ISC_API ISC_STATUS ISC_Decrypt_RSAES(ISC_RSA_UNIT *rsa, uint8 *out, int *outLen, const uint8 *in, int inLen);

/*!
* \brief
* RSA�� Modulas ���̸� ��ȯ
* \param rsa
* ISC_RSA_UNIT ����ü ������
* \returns
* -# Modulas ����
* -# ISC_INVALID_SIZE : RSA Ű ���� �������� ����
*/
ISC_API int ISC_Get_RSA_Length(ISC_RSA_UNIT* rsa);

/*!
* \brief
* EMSA PKCS1 v1.5 ���ڵ�
* \param EM
* EncodedMessage�� ���� ������
* \param emLen
* EncodedMessage ����
* \param mHash
* �ؽð�
* \param mHashLen
* �ؽ� ����
* \param digest_algo
* ISC_DIGEST �˰��� ID
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
*/
ISC_API ISC_STATUS ISC_Add_EMSA_PKCS1_v1_5_Encode(uint8 *EM, int emLen, const uint8 *mHash, int mHashLen, int digest_algo);

/*!
* \brief
* EMSA PKCS1 v1.5 ���ڵ� üũ
* \param EM
* EncodedMessage�� ���� ������
* \param emLen
* EncodedMessage ����
* \param nLen
* Modulas ����
* \param mHash
* �ؽð�
* \param mHashLen
* �ؽ� ����
* \param digest_algo
* ISC_DIGEST �˰��� ID
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_RSA^ISC_F_CHECK_PKCS1_v1_5_ENCODE^ISC_ERR_ENCODING_FAILURE : ���ڵ� �� ����
* -# ISC_L_RSA^ISC_F_CHECK_PKCS1_v1_5_ENCODE^ISC_ERR_MALLOC : �޸� �Ҵ� ����
* -# ISC_L_RSA^ISC_F_CHECK_PKCS1_v1_5_ENCODE^ISC_ERR_COMPARE_FAIL : ���ڵ��� �� ����
*/
ISC_API ISC_STATUS ISC_Check_EMSA_PKCS1_v1_5_Encode(const uint8 *EM, int emLen, int nLen, const uint8 *mHash, int mHashLen, int digest_algo);


/*!
* \brief
* PKCS1 PSS ���ڵ�
* \param rsa
* ISC_RSA_UNIT ����ü ������
* \param EM
* EncodedMessage�� ���� ������
* \param emLen
* EncodedMessage ����
* \param mHash
* �ؽð�
* \param mHashLen
* �ؽ� ����
* \param saltLen
* Salt ����
* \param d_unit
* ISC_DIGEST_UNIT ����ü ������ 
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_RSA^ISC_F_ADD_RSASSA_ENCODING^ISC_ERR_INVALID_INPUT : �Է� �Ķ���� ����
* -# ISC_L_RSA^ISC_F_ADD_RSASSA_ENCODING^ISC_ERR_SUB_OPERATION_FAILURE ���� ISC_DIGEST /PKCS1_MGF1 �Լ� ����
* -# ISC_L_RSA^ISC_F_ADD_RSASSA_ENCODING^ISC_ERR_ENCODING_FAILURE : ���ڵ� ���� 
*/
ISC_API ISC_STATUS ISC_Add_RSASSA_PKCS1_PSS_Encode(ISC_RSA_UNIT* rsa, uint8 *EM, int emLen, const uint8 *mHash, int mHashLen, int saltLen, ISC_DIGEST_UNIT *d_unit);

/*!
* \brief
* PKCS1 PSS ���ڵ� üũ
* \param rsa
* ISC_RSA_UNIT ����ü ������
* \param EM
* EncodedMessage�� ���� ������
* \param emLen
* EncodedMessage ����
* \param mHash
* �ؽð�
* \param mHashLen
* �ؽ� ����
* \param saltLen
* Salt ����
* \param d_unit
* ISC_DIGEST_UNIT ����ü ������ 
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_RSA^ISC_F_CHECK_RSASSA_PKCS1_PSS_ENCODE^ISC_ERR_SUB_OPERATION_FAILURE : ���� ISC_DIGEST /PKCS1_MGF1 �Լ� ����
* -# ISC_FAIL : ISC_BIGINT ���� �Լ� ���� 
*/
ISC_API ISC_STATUS ISC_Check_RSASSA_PKCS1_PSS_Encode(ISC_RSA_UNIT* rsa, uint8 *EM, int emLen, const uint8 *mHash, int mHashLen, int saltLen, ISC_DIGEST_UNIT *d_unit);

/*!
* \brief
* RSAES OAEP ���ڵ�
* \param rsa
* ISC_RSA_UNIT ����ü ������
* \param in
* �Է°� ������
* \param inLen
* �Է°��� ����
* \param out
* ��°� ������
* \param outLen
* ��°� �������� ����
* \param lable
* ���̺�
* \param lableLen
* ���̺� ����
* \param version
* OAEP Version v2.1 (1) , OAEP Version v2.0 (0)
* \returns
* -# ���ڵ��� �޽����� ����
* -# 0 : Encoding Fail
*/
ISC_API int ISC_Encode_RSAES_OAEP_PADDING(ISC_RSA_UNIT *rsa, const uint8 *in, int inLen, uint8 *out, int outLen,  const uint8 *lable, int lableLen, int version);

/*!
* \brief
* RSAES OAEP ���ڵ�
* \param rsa
* ISC_RSA_UNIT ����ü ������
* \param in
* �Է°� ������
* \param inLen
* �Է°��� ����
* \param out
* ��°� ������
* \param outLen
* ��°� �������� ����
* \param lable
* ���̺�
* \param lableLen
* ���̺� ����
* \param version
* OAEP Version v2.1 (1) , OAEP Version v2.0 (0)
* \returns
* -# ���ڵ��� �޽����� ����
* -# 0 : Decoding Fail
*/
ISC_API int ISC_Decode_RSAES_OAEP_PADDING(ISC_RSA_UNIT* rsa, const uint8 *in, int inLen, uint8 *out, int outLen, const uint8 *lable, int lableLen, int version);

/*!
* \brief
* RSAES PKCS1 ���ڵ�
* \param rsa
* ISC_RSA_UNIT ����ü ������
* \param in
* �Է°� ������
* \param inLen
* �Է°��� ����
* \param out
* ��°� ������
* \param outLen
* ��°� �������� ����
* \returns
* -# ���ڵ��� �޽����� ����
* -# 0 : Encoding Fail
*/
ISC_API int ISC_Encode_RSAES_PKCS1_PADDING(ISC_RSA_UNIT *rsa, const uint8 *in, int inLen, uint8 *out, int outLen);

/*!
* \brief
* RSAES PKCS1 ���ڵ�
* \param rsa
* ISC_RSA_UNIT ����ü ������
* \param in
* �Է°� ������
* \param inLen
* �Է°��� ����
* \param out
* ��°� ������
* \param outLen
* ��°� �������� ����
* \returns
* -# ���ڵ��� �޽����� ����
* -# 0 : Decoding Fail
*/
ISC_API int ISC_Decode_RSAES_PKCS1_PADDING(ISC_RSA_UNIT* rsa, const uint8 *in, int inLen, uint8 *out, int outLen);

/*!
* \brief
* ISC_RSA PSS ������ salt ���� ����
* \param rsa
* ISC_RSA_UNIT ����ü ������
* \param saltLen
* salt�� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
*/
ISC_INTERNAL ISC_STATUS isc_Set_RSASSA_PKCS1_PSS_SALT_Length(ISC_RSA_UNIT* rsa, int saltLen);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_RSA_UNIT*, ISC_New_RSA, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_RSA, (ISC_RSA_UNIT *unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_RSA, (ISC_RSA_UNIT *unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_RSA_UNIT*, ISC_Dup_RSA, (ISC_RSA_UNIT *src), (src), NULL );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_RSA_Params, (ISC_RSA_UNIT *rsa, const ISC_BIGINT *n, const ISC_BIGINT *e, const ISC_BIGINT *d, const ISC_BIGINT *p, const ISC_BIGINT *q, const ISC_BIGINT *dp, const ISC_BIGINT *dq, const ISC_BIGINT *inv_q), (rsa, n, e, d, p, q, dp, dq, inv_q), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_RSA_Public_Params, (ISC_RSA_UNIT *rsa,  const ISC_BIGINT* n, const ISC_BIGINT* e), (rsa, n, e), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_RSASSA, (ISC_RSA_UNIT *rsa, int digest_alg, int padding, int sign), (rsa, digest_alg, padding, sign), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Update_RSASSA, (ISC_RSA_UNIT *rsa, const uint8 *data, int length), (rsa, data, length), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Final_RSASSA, (ISC_RSA_UNIT *rsa, uint8 *signature, int *sLen), (rsa, signature, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Sign_RSASSA, (ISC_RSA_UNIT *rsa, uint8 *signature, int *sLen), (rsa, signature, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Verify_RSASSA, (ISC_RSA_UNIT *rsa, uint8 *signature, int sLen), (rsa, signature, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_RSA_Params, (ISC_RSA_UNIT *rsa, ISC_BIGINT *e_value, int bits, int version), (rsa, e_value, bits, version), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_RSAES, (ISC_RSA_UNIT *rsa, int encode, int encryption, int digest_algo), (rsa, encode, encryption, digest_algo), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Encrypt_RSAES, (ISC_RSA_UNIT *rsa, uint8 *out, int *outLen, const uint8 *in, int inLen), (rsa, out, outLen, in, inLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Decrypt_RSAES, (ISC_RSA_UNIT *rsa, uint8 *out, int *outLen, const uint8 *in, int inLen), (rsa, out, outLen, in, inLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(int, ISC_Get_RSA_Length, (ISC_RSA_UNIT* rsa), (rsa), 0 );

#endif

#ifdef  __cplusplus
}
#endif
#endif


