/*!
* \file desmac.h
* \brief
* ISC_DES MAC ��� ����
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_DES_MAC_H
#define HEADER_DES_MAC_H

#include "foundation.h"
#include "mem.h"


#define ISC_DES_MAC_PROVEN_MODE  1    /*!<  0: ����� ���, 1: ������� */

#ifdef ISC_NO_DES_MAC
#error ISC_DES_MAC is disabled.
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_DES_MAC �˰��� 
* \param key
* ISC_DES_MAC�� ���Ǵ� Key��
* \param in
* �Է� ��
* \param inLen
* �Է� ���� ����
* \param output
* ��� �� (ISC_DES_MAC�� ���̴� 64bits)
* \returns
* -# ISC_SUCCESS : Success\n
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_DES_MAC^ISC_F_DES_MAC^ISC_ERR_MEMORY_ALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_DES_MAC^ISC_F_DES_MAC^ISC_ERR_NOT_PROVEN_ALGORITHM : ������忡�� ����� �˰��� ���
* -# ISC_L_DES_MAC^ISC_F_DES_MAC^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_DES_MAC^ISC_F_DES_MAC^ISC_ERR_INIT_BLOCKCIPHER_FAIL : INIT BlockCipher ����
* -# ISC_L_DES_MAC^ISC_F_DES_MAC^ISC_ERR_UPDATE_BLOCKCIPHER_FAIL : UPDATE BlockCipher ����
* -# ISC_L_DES_MAC^ISC_F_DES_MAC^ISC_ERR_FINAL_BLOCKCIPHER_FAIL : FINAL BlockCipher ����
*/
ISC_API ISC_STATUS ISC_DES_MAC(uint8 *key, uint8 *in, int inLen, uint8 *output);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_DES_MAC, (uint8 *key, uint8 *in, int inLen, uint8 *output), (key, in, inLen, output), ISC_ERR_GET_ADRESS_LOADLIBRARY );

#endif


#ifdef  __cplusplus
}
#endif

#endif /*HEADER_DES_MAC_H*/
