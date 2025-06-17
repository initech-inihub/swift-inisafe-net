/*!
* \file self_test.h
* \brief �ڰ����� �������
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_SELF_TEST_H
#define HEADER_SELF_TEST_H

#include "stdio.h"
#include "foundation.h"
#include "rsa.h"
#include "biginteger.h"
#include "drbg.h"

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO
/*!
* \brief
* �ڰ� �׽�Ʈ
* \returns
* -# TEST_SUCCESS : Success\n
* -# ISC_L_SELF_TEST^ISC_F_LIB_INTEGRITY_CHECK^ISC_ERR_MEM_ALLOC : ���Ἲ���� ����
* -# ISC_L_SELF_TEST^ISC_F_LIB_INTEGRITY_CHECK^ISC_ERR_READ_FROM_FILE : ���Ἲ���� ����
* -# ISC_L_SELF_TEST^ISC_F_LIB_INTEGRITY_CHECK^ISC_ERR_INIT_FAILURE : ���Ἲ���� ����
* -# ISC_L_SELF_TEST^ISC_F_LIB_INTEGRITY_CHECK^ISC_ERR_UPDATE_FAILURE : ���Ἲ���� ����
* -# ISC_L_SELF_TEST^ISC_F_LIB_INTEGRITY_CHECK^ISC_ERR_FINAL_FAILURE : ���Ἲ���� ����
* -# ISC_L_SELF_TEST^ISC_F_CONTEXT_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : ���������� ����
* -# ISC_L_SELF_TEST^ISC_F_VERSION_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : �������� ����
* -# ISC_L_SELF_TEST^ISC_F_ENTROPY_CHECK^ISC_ERR_ENTROPY_FAIL : ��Ʈ���� ���� ����
* -# ISC_L_SELF_TEST^ISC_F_DRBG_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : DRBG ����
* -# ISC_L_SELF_TEST^ISC_F_HMAC_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : HMAC ����
* -# ISC_L_SELF_TEST^ISC_F_DIGEST_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : �ؽ� ����
* -# ISC_L_SELF_TEST^ISC_F_SYMMETIC_KEY_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : ��� ��ȣŰ ���� ����
* -# ISC_L_SELF_TEST^ISC_F_SYMMETIC_ALGORITHM_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : ��Ͼ�ȣ ����
* -# ISC_L_SELF_TEST^ISC_F_ASYMMETIC_KEY_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : ����Ű ��ȣŰ���� ����
* -# ISC_L_SELF_TEST^ISC_F_RSAES_OAEP_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : ����Ű ��ȣ ����
* -# ISC_L_SELF_TEST^ISC_F_KCDSA_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : ���ڼ��� ����
* -# ISC_L_SELF_TEST^ISC_F_ECDSA_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : ECDSA ����
* -# ISC_L_SELF_TEST^ISC_F_ECDH_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : ECDH ����
* -# ISC_L_SELF_TEST^ISC_F_SYMMETIC_MAC_ALGORITHM_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : ��Ͼ�ȣ ��м�/���� ����
* -# ISC_L_SELF_TEST^ISC_F_PBKDF_CHECK^ISC_ERR_SUB_OPERATION_FAILURE : Ű���� ����
*/
ISC_API ISC_STATUS ISC_Crypto_Self_Test();

#else

ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Crypto_Self_Test, (void), (), ISC_ERR_GET_ADRESS_LOADLIBRARY );

#endif

/*!
* \brief
* ���Ἲ���� �Լ�
* \returns
* -# ISC_F_LIB_INTEGRITY_CHECK :����
* -# ISC_SUCCESS : �׽�Ʈ ���
*/
ISC_INTERNAL ISC_STATUS isc_Verify_DLL();
ISC_INTERNAL ISC_STATUS isc_Verify_Dat();

/*!
* \brief
* ���������� �Լ�
* \returns
* -# ISC_F_CONTEXT_CHECK :����
* -# ISC_SUCCESS : �׽�Ʈ ���
*/
ISC_INTERNAL ISC_STATUS isc_Context_Check();

/*!
* \brief
* ���������Լ�
* \returns
* -# ISC_F_VERSION_CHECK :����
* -# ISC_SUCCESS : �׽�Ʈ ���
*/
ISC_INTERNAL ISC_STATUS isc_Version_Check();

/*!
* \brief
* ��Ʈ���� ���� �Լ�
* \returns
* -# ISC_F_ENTROPY_CHECK :����
* -# ISC_SUCCESS : �׽�Ʈ ���
*/
ISC_INTERNAL ISC_STATUS isc_Entropy_Check();

/*!
* \brief
* ���������� ���� �Լ�
* \returns
* -# ISC_F_DRBG_CHECK :����
* -# ISC_SUCCESS : �׽�Ʈ ���
*/
ISC_INTERNAL ISC_STATUS isc_DRBG_Check();

/*!
* \brief
* hmac �����Լ�
* \returns
* -# ISC_F_HMAC_CHECK :����
* -# ISC_SUCCESS : �׽�Ʈ ���
*/
ISC_INTERNAL ISC_STATUS isc_HMAC_Check();

/*!
* \brief
* �ؽ��Լ� �����Լ�
* \returns
* -# ISC_F_DIGEST_CHECK :����
* -# ISC_SUCCESS : �׽�Ʈ ���
*/
ISC_INTERNAL ISC_STATUS isc_DIGEST_Check();

/*!
* \brief
* ��Ͼ�ȣ ���� �����Լ�
* \returns
* -# ISC_F_SYMMETIC_KEY_CHECK :����
* -# ISC_SUCCESS : �׽�Ʈ ���
*/
ISC_INTERNAL ISC_STATUS isc_Sym_Key_Check();

/*!
* \brief
* ��Ͼ�ȣ �˰��� �����Լ�
* \returns
* -# ISC_F_SYMMETIC_ALGORITHM_CHECK :����
* -# ISC_SUCCESS : �׽�Ʈ ���
*/
ISC_INTERNAL ISC_STATUS isc_Sym_Check();

/*!
* \brief
* ��Ͼ�ȣ ��м�/���� �˰��� �����Լ�
* \returns
* -# ISC_F_SYMMETIC_MAC_ALGORITHM_CHECK :����
* -# ISC_SUCCESS : �׽�Ʈ ���
*/
ISC_INTERNAL ISC_STATUS isc_Sym_MAC_Check();

/*!
* \brief
* ����Ű ���� �����Լ�
* \returns
* -# ISC_F_ASYMMETIC_KEY_CHECK :����
* -# ISC_SUCCESS : �׽�Ʈ ���
*/
ISC_INTERNAL ISC_STATUS isc_Asym_Key_Check();

/*!
* \brief
* RSA ��ȣȭ �˰��� �����Լ�
* \returns
* -# ISC_F_RSAES_OAEP_CHECK :����
* -# ISC_SUCCESS : �׽�Ʈ ���
*/
ISC_INTERNAL ISC_STATUS isc_RSAES_Check();

/*!
* \brief
* RSA ���� �˰��� �����Լ�
* \returns
* -# ISC_F_RSASSA_CHECK :����
* -# ISC_SUCCESS : �׽�Ʈ ���
*/
ISC_INTERNAL ISC_STATUS isc_RSASSA_Check();

/*!
* \brief
* KCDSA ���� �˰��� �����Լ�
* \returns
* -# ISC_F_KCDSA_CHECK :����
* -# ISC_SUCCESS : �׽�Ʈ ���
*/
ISC_INTERNAL ISC_STATUS isc_KCDSA_Check();

/*!
* \brief
* DH Ű���� �˰��� �����Լ�
* \returns
* -# ISC_F_DH_CHECK :����
* -# ISC_SUCCESS : �׽�Ʈ ���
*/
ISC_INTERNAL ISC_STATUS isc_DH_Check();

/*!
* \brief
* ECDH Ű���� �˰��� �����Լ�
* \returns
* -# ISC_F_ECDH_CHECK :����
* -# ISC_SUCCESS : �׽�Ʈ ���
*/
ISC_INTERNAL ISC_STATUS isc_ECDH_Check();

/*!
* \brief
* ECDSA Ű���� �˰��� �����Լ�
* \returns
* -# ISC_F_ECDSA_CHECK :����
* -# ISC_SUCCESS : �׽�Ʈ ���
*/
ISC_INTERNAL ISC_STATUS isc_ECDSA_Check();

/*!
* \brief
* ECKCDSA Ű���� �˰��� �����Լ�
* \returns
* -# ISC_F_ECKCDSA_CHECK :����
* -# ISC_SUCCESS : �׽�Ʈ ���
*/
ISC_INTERNAL ISC_STATUS isc_ECKCDSA_Check();

/*!
* \brief
* PBKDF Ű���� �˰��� �����Լ�
* \returns
* -# ISC_F_PBKDF_CHECK :����
* -# ISC_SUCCESS : �׽�Ʈ ���
*/
ISC_INTERNAL ISC_STATUS isc_PBKDF_Check();

ISC_INTERNAL int SearchProcessLoadedDll(char * pOutBuffer);
ISC_INTERNAL int SearchProcessLoadedDat(char *pOutBuffer);
ISC_INTERNAL int isc_Find_Crypto_Modul_From_Path(char *path, char *out);
ISC_INTERNAL ISC_STATUS check_digest_sha();
ISC_INTERNAL ISC_STATUS check_digest_lsh();
ISC_INTERNAL int isc_Find_Dat_From_Path(char *path, char *out);

#ifdef  __cplusplus
}
#endif

#endif/* HEADER_SELF_TEST_H */
