/*!
* \file pkcs5.h
* \brief PKCS5 �˰���
* PBE ����� ��ȣȭ/��ȣȭ ǥ��
* \remarks
* PBES1, PBES2, KISA_PBES
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_PKCS5_H
#define HEADER_PKCS5_H

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/foundation.h>

#include "asn1.h"
#include "pkcs8.h"

#define IV_DEFALUT		0		/*!< KISA_PBES�� �ʱ⺤��: ������ ���Ͱ� */
#define IV_GENERATE		1		/*!< KISA_PBES�� �ʱ⺤��: �⺻��(ISC_SHA1�̿�) */


#ifdef  __cplusplus
extern "C" {
#endif

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* PBES1_KISA ENCRYPT �Լ�
* \param message
* �޽���
* \param messageLen
* �޼����� ����
* \param password
* �н�����
* \param passwordLen
* �н����� ����
* \param salt
* SALT ��
* \param saltLen
* SALT�� ����
* \param iter
* �ߺ���
* \param out
* ��ȣ��
* \param outLen
* ��ȣ���� ����
* \param enc_alg
* ��ȣȭ ��ũ���� �˰��� ID
* \param hash_alg
* ��ȣȭ �ؽ� �˰��� ID
* \param iv_opt
* �ʱ� ���� ID
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ENC_PBES1_KISA^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_ENC_PBES1_KISA^ISC_ERR_INVALID_INPUT : input error
* -# PBKDF1()�� ���� �ڵ�\n
* -# ISC_Init_DIGEST()�� ���� �ڵ�\n
* -# ISC_Update_DIGEST()�� ���� �ڵ�\n
* -# ISC_Final_DIGEST()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS encrypt_PBES1_KISA(uint8* message, int messageLen, uint8* password, int passwordLen,
				  uint8* salt, int saltLen, int iter, uint8* out, int* outLen,
				  int enc_alg, int hash_alg, int iv_opt);

/*!
* \brief
* PBES1_GPKI DECRYPT �Լ�
* \param ciphertext
* ��ȣ��
* \param ciphertextLen
* ��ȣ���� ����
* \param password
* �н�����
* \param passwordLen
* �н����� ����
* \param salt
* SALT ��
* \param saltLen
* SALT�� ����
* \param iter
* �ߺ���
* \param out
* ��ȣ��
* \param outLen
* ��ȣ���� ����
* \param enc_alg
* ��ȣȭ ��ũ���� �˰��� ID
* \param hash_alg
* ��ȣȭ �ؽ� �˰��� ID
* \param iv_opt
* �ʱ� ���� ID
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_DEC_PBES1_KISA^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_DEC_PBES1_KISA^ISC_ERR_INVALID_INPUT : input error
* -# PBKDF1()�� ���� �ڵ�\n
* -# ISC_Init_DIGEST()�� ���� �ڵ�\n
* -# ISC_Update_DIGEST()�� ���� �ڵ�\n
* -# ISC_Final_DIGEST()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS decrypt_PBES1_KISA(uint8* ciphertext, int ciphertextLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg, int iv_opt);

/*!
* \brief
* PBES1_GPKI ENCRYPT �Լ�
* \param message
* �޽���
* \param messageLen
* �޼����� ����
* \param password
* �н�����
* \param passwordLen
* �н����� ����
* \param salt
* SALT ��
* \param saltLen
* SALT�� ����
* \param iter
* �ߺ���
* \param out
* ��ȣ��
* \param outLen
* ��ȣ���� ����
* \param enc_alg
* ��ȣȭ ��ũ���� �˰��� ID
* \param hash_alg
* ��ȣȭ �ؽ� �˰��� ID
* \param iv_opt
* �ʱ� ���� ID
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ENC_PBES1_KISA^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_ENC_PBES1_KISA^ISC_ERR_INVALID_INPUT : input error
* -# PBKDF1()�� ���� �ڵ�\n
* -# ISC_Init_DIGEST()�� ���� �ڵ�\n
* -# ISC_Update_DIGEST()�� ���� �ڵ�\n
* -# ISC_Final_DIGEST()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS encrypt_PBES1_GPKI(uint8* message, int messageLen, uint8* password, int passwordLen,
				  uint8* salt, int saltLen, int iter, uint8* out, int* outLen,
				  int enc_alg, int hash_alg);

/*!
* \brief
* PBES1_KISA DECRYPT �Լ�
* \param ciphertext
* ��ȣ��
* \param ciphertextLen
* ��ȣ���� ����
* \param password
* �н�����
* \param passwordLen
* �н����� ����
* \param salt
* SALT ��
* \param saltLen
* SALT�� ����
* \param iter
* �ߺ���
* \param out
* ��ȣ��
* \param outLen
* ��ȣ���� ����
* \param enc_alg
* ��ȣȭ ��ũ���� �˰��� ID
* \param hash_alg
* ��ȣȭ �ؽ� �˰��� ID
* \param iv_opt
* �ʱ� ���� ID
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_DEC_PBES1_KISA^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_DEC_PBES1_KISA^ISC_ERR_INVALID_INPUT : input error
* -# PBKDF1()�� ���� �ڵ�\n
* -# ISC_Init_DIGEST()�� ���� �ڵ�\n
* -# ISC_Update_DIGEST()�� ���� �ڵ�\n
* -# ISC_Final_DIGEST()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS decrypt_PBES1_GPKI(uint8* ciphertext, int ciphertextLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg);

/*!
* \brief
* PBES1 ENCRYPT �Լ�
* \param message
* �޽���
* \param messageLen
* �޼����� ����
* \param password
* �н�����
* \param passwordLen
* �н����� ����
* \param salt
* SALT ��
* \param saltLen
* SALT�� ����
* \param iter
* �ߺ���
* \param out
* ��ȣ��
* \param outLen
* ��ȣ���� ����
* \param enc_alg
* ��ȣȭ ��ũ���� �˰��� ID
* \param hash_alg
* ��ȣȭ �ؽ� �˰��� ID
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ENCRYPT_PBES1^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_ENCRYPT_PBES1^ISC_ERR_INVALID_INPUT : input error
* -# PBKDF1()�� ���� �ڵ�\n
* -# ISC_BLOCK_CIPHER()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS encrypt_PBES1(uint8* message, int messageLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg);

/*!
* \brief
* PBES1 DECRYPT �Լ�
* \param ciphertext
* ��ȣ��
* \param ciphertextLen
* ��ȣ���� ����
* \param password
* �н�����
* \param passwordLen
* �н����� ����
* \param salt
* SALT ��
* \param saltLen
* SALT�� ����
* \param iter
* �ߺ���
* \param out
* ��ȣ��
* \param outLen
* ��ȣ���� ����
* \param enc_alg
* ��ȣȭ ��ũ���� �˰��� ID
* \param hash_alg
* ��ȣȭ �ؽ� �˰��� ID
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_DECRYPT_PBES1^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_DECRYPT_PBES1^ISC_ERR_INVALID_INPUT : input error
* -# PBKDF1()�� ���� �ڵ�\n
* -# ISC_BLOCK_CIPHER()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS decrypt_PBES1(uint8* ciphertext, int ciphertextLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg);

/*!
* \brief
* PBES2 ENCRYPT �Լ�
* \param message
* �޽���
* \param messageLen
* �޼����� ����
* \param password
* �н�����
* \param passwordLen
* �н����� ����
* \param salt
* SALT ��
* \param saltLen
* SALT�� ����
* \param iter
* �ߺ���
* \param out
* ��ȣ��
* \param outLen
* ��ȣ���� ����
* \param iv
* �ʱ⺤��
* \param ivLen
* �ʱ⺤���� ����
* \param enc_alg
* ��ȣȭ ��ũ���� �˰��� ID
* \param hash_alg
* ��ȣȭ �ؽ� �˰��� ID
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_ENCRYPT_PBES2^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_ENCRYPT_PBES2^ISC_ERR_INVALID_INPUT : input error
* -# PBKDF2()�� ���� �ڵ�\n
* -# ISC_BLOCK_CIPHER()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS encrypt_PBES2(uint8* message, int messageLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, uint8** iv, int* ivLen, int enc_alg, int hash_alg);

/*!
* \brief
* PBES2 DECRYPT �Լ�
* \param message
* ��ȣ��
* \param messageLen
* ��ȣ���� ����
* \param password
* �н�����
* \param passwordLen
* �н����� ����
* \param salt
* SALT ��
* \param saltLen
* SALT�� ����
* \param iter
* �ߺ���
* \param out
* ��
* \param outLen
* ���� ����
* \param iv
* �ʱ⺤��
* \param enc_alg
* ��ȣȭ ��ũ���� �˰��� ID
* \param hash_alg
* ��ȣȭ �ؽ� �˰��� ID
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_DECRYPT_PBES2^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_DECRYPT_PBES2^ISC_ERR_INVALID_INPUT : input error
* -# PBKDF2()�� ���� �ڵ�\n
* -# ISC_BLOCK_CIPHER()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS decrypt_PBES2(uint8* message, int messageLen,uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen,  uint8* iv,  int enc_alg, int hash_alg);

/*!
* \brief
* PBKDF1
* \param password
* �н�����
* \param passwordLen
* �н����� ����
* \param salt
* SALT ��
* \param saltLen
* SALT�� ����
* \param iter
* �ߺ���
* \param hash_alg
* ��ȣȭ �ؽ� �˰��� ID
* \param out
* PBKDF1�� ���� ������ Ű
* \param outLen
* ������ Ű�� ����
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
* -# LOCATION^F_PBKDF1^ISC_ERR_INVALID_OUTPUT : input error
* -# PBKDF2()�� ���� �ڵ�\n
* -# ISC_Init_DIGEST()�� ���� �ڵ�\n
* -# ISC_Update_DIGEST()�� ���� �ڵ�\n
* -# ISC_Final_DIGEST()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS PBKDF1(uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int hash_alg, uint8* out, int outLen);
/*!
* \brief
* PBKDF2
* \param password
* �н�����
* \param passwordLen
* �н����� ����
* \param salt
* SALT ��
* \param saltLen
* SALT�� ����
* \param iter
* �ߺ���
* \param hash_alg
* ��ȣȭ �ؽ� �˰��� ID
* \param key
* PBKDF2�� ���� ������ Ű
* \param keyLen
* ������ Ű�� ����
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_PBKDF2^ISC_ERR_INVALID_OUTPUT : input error
* -# PBKDF2()�� ���� �ڵ�\n
* -# ISC_Init_HMAC()�� ���� �ڵ�\n
* -# ISC_Update_HMAC()�� ���� �ڵ�\n
* -# ISC_Final_HMAC()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS PBKDF2(uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int hash_alg, uint8* key, int keyLen);

/*!
* \brief
* PBE ENCRYPT �Լ�
* \param priv_unit
* encryption�� ����� P8_PRIV_KEY_INFO ����ü
* \param p8_out
* decrypt�� ������ ����� P8_ENCRYPTED_KEY ����ü
* \param password
* �н�����
* \param passwordLen
* �н����� ����
* \param salt
* SALT ��
* \param saltLen
* SALT�� ����
* \param iter
* �ߺ���
* \param oid_index
* PBE���� OBJECT IDENTIFIER�� ID
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
* -# LOCATION^F_ENC_PKCS5^ISC_ERR_NULL_INPUT : Null Input
* -# LOCATION^F_ENC_PKCS5^ISC_ERR_INVALID_OUTPUT : input error
* -# encrypt_PBES1_KISA()�� ���� �ڵ�\n
* -# encrypt_PBES1()�� ���� �ڵ�\n
* -# encrypt_PBES2()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS encrypt_PKCS5(P8_PRIV_KEY_INFO* priv_unit, P8_ENCRYPTED_KEY** p8_out, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int oid_index);

/*!
* \brief
* PBE ENCRYPT �Լ�
* \param priv_unit
* encryption�� ����� P8_PRIV_KEY_INFO ����ü
* \param p8_out
* decrypt�� ������ ����� P8_ENCRYPTED_KEY ����ü
* \param password
* �н�����
* \param passwordLen
* �н����� ����
* \param salt
* SALT ��
* \param saltLen
* SALT�� ����
* \param iter
* �ߺ���
* \param oid_index
* PBE���� OBJECT IDENTIFIER�� ID
* \param alg_index
* ��ȣ�˰��� ���� OBJECT IDENTIFIER�� ID
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
* -# LOCATION^F_ENC_PKCS5^ISC_ERR_NULL_INPUT : Null Input
* -# LOCATION^F_ENC_PKCS5^ISC_ERR_INVALID_OUTPUT : input error
* -# encrypt_PBES1_KISA()�� ���� �ڵ�\n
* -# encrypt_PBES1()�� ���� �ڵ�\n
* -# encrypt_PBES2()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS encrypt_PKCS5_ex(P8_PRIV_KEY_INFO* priv_unit, P8_ENCRYPTED_KEY** p8_out, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int oid_index, int alg_index);

/*!
* \brief
* PBE ENCRYPT �Լ�
* \param priv_unit
* encryption�� ����� P8_PRIV_KEY_INFO ����ü
* \param p8_out
* decrypt�� ������ ����� P8_ENCRYPTED_KEY ����ü
* \param password
* �н�����
* \param passwordLen
* �н����� ����
* \param salt
* SALT ��
* \param saltLen
* SALT�� ����
* \param iter
* �ߺ���
* \param oid_index
* PBE���� OBJECT IDENTIFIER�� ID
* \param alg_index
* ��ȣ�˰��� ���� OBJECT IDENTIFIER�� ID
* \param prf_alg_index
* PBKDF2�� prf �˰����� OBJECT IDENTIFIER�� ID
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
* -# LOCATION^F_ENC_PKCS5^ISC_ERR_NULL_INPUT : Null Input
* -# LOCATION^F_ENC_PKCS5^ISC_ERR_INVALID_OUTPUT : input error
* -# encrypt_PBES1_KISA()�� ���� �ڵ�\n
* -# encrypt_PBES1()�� ���� �ڵ�\n
* -# encrypt_PBES2()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS encrypt_PKCS5_Apply_PBES2(P8_PRIV_KEY_INFO* priv_unit, P8_ENCRYPTED_KEY** p8_out, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int oid_index, int alg_index, int prf_alg_index);

/*!
* \brief
* PBE DECRYPT �Լ�
* \param unit
* decrypt�� ����� P8_ENCRYPTED_KEY ����ü
* \param priv_unit
* decrypt�� ������ ����� P8_PRIV_KEY_INFO ����ü
* \param password
* �н�����
* \param passwordLen
* �н����� ����
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
* -# LOCATION^F_DEC_PKCS5^ISC_ERR_NULL_INPUT : Null Input
* -# decrypt_PBES1_KISA()�� ���� �ڵ�\n
* -# decrypt_PBES1()�� ���� �ڵ�\n
* -# decrypt_PBES2()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS decrypt_PKCS5(P8_ENCRYPTED_KEY* unit, P8_PRIV_KEY_INFO** priv_unit, uint8* password, int passwordLen);

/*!
* \brief
* PBE ENCRYPT �Լ�
* \param priv_unit
* encryption�� ����� P8_PRIV_KEY_INFO ����ü
* \param p8_out
* decrypt�� ������ ����� P8_ENCRYPTED_KEY ����ü
* \param password
* �н�����
* \param passwordLen
* �н����� ����
* \param salt
* SALT ��
* \param saltLen
* SALT�� ����
* \param iter
* �ߺ���
* \param oid_index
* PBE���� OBJECT IDENTIFIER�� ID
* \param alg_index
* ��ȣ�˰��� ���� OBJECT IDENTIFIER�� ID
* \param prf_alg_index
* PBKDF2�� prf �˰����� OBJECT IDENTIFIER�� ID
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
* -# LOCATION^F_ENC_PKCS5^ISC_ERR_NULL_INPUT : Null Input
* -# LOCATION^F_ENC_PKCS5^ISC_ERR_INVALID_OUTPUT : input error
* -# encrypt_PBES1_KISA()�� ���� �ڵ�\n
* -# encrypt_PBES1()�� ���� �ڵ�\n
* -# encrypt_PBES2()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS encrypt_PKCS5_Apply_PBES2(P8_PRIV_KEY_INFO* priv_unit, P8_ENCRYPTED_KEY** p8_out, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int oid_index, int alg_index, int prf_alg_index);

#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(ISC_STATUS, encrypt_PBES1_KISA, (uint8* message, int messageLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg, int iv_opt), (message,messageLen,password,passwordLen,salt,saltLen,iter,out,outLen,enc_alg,hash_alg,iv_opt), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, decrypt_PBES1_KISA, (uint8* ciphertext, int ciphertextLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg, int iv_opt), (ciphertext,ciphertextLen,password,passwordLen,salt,saltLen,iter,out,outLen,enc_alg,hash_alg,iv_opt), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encrypt_PBES1_GPKI, (uint8* message, int messageLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg), (message,messageLen,password,passwordLen,salt,saltLen,iter,out,outLen,enc_alg,hash_alg), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, decrypt_PBES1_GPKI, (uint8* ciphertext, int ciphertextLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg), (ciphertext,ciphertextLen,password,passwordLen,salt,saltLen,iter,out,outLen,enc_alg,hash_alg), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encrypt_PBES1, (uint8* message, int messageLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg), (message,messageLen,password,passwordLen,salt,saltLen,iter,out,outLen,enc_alg,hash_alg), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, decrypt_PBES1, (uint8* ciphertext, int ciphertextLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, int enc_alg, int hash_alg), (ciphertext,ciphertextLen,password,passwordLen,salt,saltLen,iter,out,outLen,enc_alg,hash_alg), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encrypt_PBES2, (uint8* message, int messageLen, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, uint8** iv, int* ivLen, int enc_alg, int hash_alg), (message,messageLen,password,passwordLen,salt,saltLen,iter,out,outLen,iv,ivLen,enc_alg,hash_alg), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, decrypt_PBES2, (uint8* message, int messageLen,uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, uint8* out, int* outLen, uint8* iv, int enc_alg, int hash_alg), (message,messageLen,password,passwordLen,salt,saltLen,iter,out,outLen,iv,enc_alg,hash_alg), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, PBKDF1, (uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int hash_alg, uint8* out, int outLen), (password,passwordLen,salt,saltLen,iter,hash_alg,out,outLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, PBKDF2, (uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int hash_alg, uint8* key, int keyLen), (password,passwordLen,salt,saltLen,iter,hash_alg,key,keyLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encrypt_PKCS5, (P8_PRIV_KEY_INFO* priv_unit, P8_ENCRYPTED_KEY** p8_out, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int oid_index), (priv_unit,p8_out,password,passwordLen,salt,saltLen,iter,oid_index), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encrypt_PKCS5_ex, (P8_PRIV_KEY_INFO* priv_unit, P8_ENCRYPTED_KEY** p8_out, uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int oid_index, int alg_index), (priv_unit,p8_out,password,passwordLen,salt,saltLen,iter,oid_index,alg_index), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, decrypt_PKCS5, (P8_ENCRYPTED_KEY* unit, P8_PRIV_KEY_INFO** priv_unit, uint8* password, int passwordLen), (unit,priv_unit,password,passwordLen), ISC_FAIL);

#endif

#ifdef  __cplusplus
}
#endif
#endif

