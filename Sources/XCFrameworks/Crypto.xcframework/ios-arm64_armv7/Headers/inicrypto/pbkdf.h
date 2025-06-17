#ifndef HEADER_PBKDF_H
#define HEADER_PBKDF_H

#include "foundation.h"

#ifdef ISC_NO_PBKDF
#error HMAC is disabled.
#endif
																			   
#ifdef  __cplusplus																   
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* �н����带 �Է¹޾� Ű�����ϴ� �Լ�(PKCS#5 PBKDF2)
* \param password
* �н�����
* \param passwordLen
* �н����� ����
* \param salt
* SALT ��
* \param saltLen
* SALT�� ���� (Byte)
* \param iter
* �ݺ�Ƚ��
* \param hash_alg
* ��ȣȭ �ؽ� �˰��� ID
* \param key
* PBKDF2�� ���� ������ Ű
* \param keyLen
* ������ Ű�� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# LOCATION^ISC_F_PBKDF2^ISC_ERR_NOT_PROVEN_ALGORITHM : ������忡�� ����� ��� �˰��� ��� ����
* -# LOCATION^ISC_F_PBKDF2^ISC_ERR_NULL_INPUT : password, salt, iter�� NULL�϶�
* -# LOCATION^ISC_F_PBKDF2^ISC_ERR_INVALID_INPUT : ��ȿ���� ���� �ؽ� �˰��� �Է�
* -# LOCATION^ISC_F_PBKDF2^ISC_ERR_MEM_ALLOC : �޸� ���� �Ҵ� ����
* -# LOCATION^ISC_F_PBKDF2^ISC_ERR_OPERATE_FUNCTION : HMAC ���� ����
*/
ISC_API ISC_STATUS ISC_PBKDF2(uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int hash_alg, uint8* key, int keyLen);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_PBKDF2, (uint8* password, int passwordLen, uint8* salt, int saltLen, int iter, int hash_alg, uint8* key, int keyLen), (password, passwordLen, salt, saltLen, iter, hash_alg, key, keyLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );


#endif

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_PBKDF_H */


