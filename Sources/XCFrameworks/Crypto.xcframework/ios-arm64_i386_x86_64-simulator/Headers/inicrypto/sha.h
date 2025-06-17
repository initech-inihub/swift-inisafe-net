/*!
* \file sha.h
* \brief SHA �˰���(1, 224, 256, 384, 512) �������
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_SHA_H
#define HEADER_SHA_H

#if defined(ISC_NO_SHA) || (defined(ISC_NO_SHA1) && (defined(ISC_NO_SHA256) && (defined(ISC_NO_SHA512))))
#error SHA is disabled.
#endif

#define ISC_SHA1_PROVEN_MODE  	1    /*!<  0: ����� ���, 1: ������� */
#define ISC_SHA224_PROVEN_MODE  1    /*!<  0: ����� ���, 1: ������� */

#include "foundation.h"
#include "mem.h"

/*--------------------------------------------------*/
#define ISC_SHA1_NAME				"SHA1"
#define ISC_SHA1_BLOCK_SIZE			64
#define ISC_SHA1_DIGEST_LENGTH		20
#define ISC_SHA1_INIT				isc_Init_SHA1
#define ISC_SHA1_UPDATE				isc_Update_SHA1
#define ISC_SHA1_FINAL				isc_Final_SHA1
#define ISC_SHA1_STATE_SIZE			sizeof(ISC_SHA1_STATE)
/*--------------------------------------------------*/

/*--------------------------------------------------*/
#define ISC_SHA224_NAME				"SHA224"
#define ISC_SHA224_BLOCK_SIZE		64
#define ISC_SHA224_DIGEST_LENGTH	28
#define ISC_SHA224_INIT				isc_Init_SHA224
#define ISC_SHA224_UPDATE			isc_Update_SHA224
#define ISC_SHA224_FINAL			isc_Final_SHA224
#define ISC_SHA224_STATE_SIZE		sizeof(ISC_SHA224_STATE)
/*--------------------------------------------------*/

/*--------------------------------------------------*/
#define ISC_SHA256_NAME				"SHA256"
#define ISC_SHA256_BLOCK_SIZE		64
#define ISC_SHA256_DIGEST_LENGTH	32
#define ISC_SHA256_INIT				isc_Init_SHA256
#define ISC_SHA256_UPDATE			isc_Update_SHA256
#define ISC_SHA256_FINAL			isc_Final_SHA256
#define ISC_SHA256_STATE_SIZE		sizeof(ISC_SHA256_STATE)
/*--------------------------------------------------*/

/*--------------------------------------------------*/
#define ISC_SHA384_NAME				"SHA384"
#define ISC_SHA384_BLOCK_SIZE		128
#define ISC_SHA384_DIGEST_LENGTH	48
#define ISC_SHA384_INIT				isc_Init_SHA384
#define ISC_SHA384_UPDATE			isc_Update_SHA384
#define ISC_SHA384_FINAL			isc_Final_SHA384
#define ISC_SHA384_STATE_SIZE		sizeof(ISC_SHA384_STATE)
/*--------------------------------------------------*/

/*--------------------------------------------------*/
#define ISC_SHA512_NAME				"SHA512"
#define ISC_SHA512_BLOCK_SIZE		128
#define ISC_SHA512_DIGEST_LENGTH	64
#define ISC_SHA512_INIT				isc_Init_SHA512
#define ISC_SHA512_UPDATE			isc_Update_SHA512
#define ISC_SHA512_FINAL			isc_Final_SHA512
#define ISC_SHA512_STATE_SIZE		sizeof(ISC_SHA512_STATE)
/*--------------------------------------------------*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* ISC_SHA1���� ���̴� ������ ��� �ִ� ����ü
*/
typedef struct isc_sha1_state_st {
	uint64 len;
	uint32 len2;
	uint32 state[5];
	uint8 buf[ISC_SHA1_BLOCK_SIZE];
	uint8 dataBuf[ISC_SHA1_BLOCK_SIZE];
	uint8 dataBufLen;
} ISC_SHA1_STATE;

/*!
* \brief
* ISC_SHA256���� ���̴� ������ ��� �ִ� ����ü
*/
typedef struct isc_sha256_state_st {
	uint64 len;
	uint32 len2;
	uint32 state[8];
	uint8 buf[ISC_SHA256_BLOCK_SIZE];
	uint8 dataBuf[ISC_SHA256_BLOCK_SIZE];
	uint8 dataBufLen;
} ISC_SHA256_STATE;

/*!
* \brief
* ISC_SHA224���� ���̴� ������ ��� �ִ� ����ü
*/
typedef ISC_SHA256_STATE ISC_SHA224_STATE;

/*!
* \brief
* ISC_SHA512���� ���̴� ������ ��� �ִ� ����ü
*/
typedef struct isc_sha512_state_st {
	uint64 len;
	uint32 len2;
	uint64 state[8];
	uint8 buf[ISC_SHA512_BLOCK_SIZE];
	uint8 dataBuf[ISC_SHA512_BLOCK_SIZE];
	uint8 dataBufLen;
} ISC_SHA512_STATE;

/*!
* \brief
* ISC_SHA384���� ���̴� ������ ��� �ִ� ����ü
*/
typedef ISC_SHA512_STATE ISC_SHA384_STATE;

/*!
* \brief
* ISC_SHA1 �ʱ�ȭ �Լ�
* \param sha1
* ISC_SHA1_STATE ����ü�� ������
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# LOCATION^ISC_F_INIT_SHA1^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
*/
ISC_INTERNAL ISC_STATUS isc_Init_SHA1(ISC_SHA1_STATE *sha1);

/*!
* \brief
* ISC_SHA1 ������Ʈ �Լ�
* \param sha1
* ISC_SHA1_STATE ����ü�� ������
* \param data
* �ؽ��� �� �޽����� ������
* \param count
* �ؽ��� �� �޽����� ����
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_UPDATE_SHA1^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_UPDATE_SHA1^ISC_ERR_SUB_OPERATION_FAILURE : ���� update �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Update_SHA1(ISC_SHA1_STATE *sha1, const uint8 *data, uint32 count);

/*!
* \brief
* ISC_SHA1 ���̳� �Լ�
* \param sha1
* ISC_SHA1_STATE ����ü�� ������
* \param md
* �ؽ��� ����� ������ ������ ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_FINAL_SHA1^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_FINAL_SHA1^ISC_ERR_SUB_OPERATION_FAILURE : ���� final �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Final_SHA1(ISC_SHA1_STATE *sha1, uint8 *md);


/*!
* \brief
* ISC_SHA224 �ʱ�ȭ �Լ�
* \param sha224
* ISC_SHA224_STATE ����ü�� ������
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# LOCATION^ISC_F_INIT_SHA224^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
*/
ISC_INTERNAL ISC_STATUS isc_Init_SHA224(ISC_SHA224_STATE *sha224);

/*!
* \brief
* ISC_SHA224 ������Ʈ �Լ�
* \param sha224
* ISC_SHA224_STATE ����ü�� ������
* \param data
* �ؽ��� �� �޽����� ������
* \param count
* �ؽ��� �� �޽����� ����
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_UPDATE_SHA224^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
*/
ISC_INTERNAL ISC_STATUS isc_Update_SHA224(ISC_SHA224_STATE *sha224, const uint8 *data, uint32 count);

/*!
* \brief
* ISC_SHA224 ���̳� �Լ�
* \param sha224
* ISC_SHA224_STATE ����ü�� ������
* \param md
* �ؽ��� ����� ������ ������ ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_FINAL_SHA224^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_FINAL_SHA224^ISC_ERR_FINAL_FAILURE : ���� final �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Final_SHA224(ISC_SHA224_STATE *sha224, uint8 *md);


/*!
* \brief
* ISC_SHA256 �ʱ�ȭ �Լ�
* \param sha256
* ISC_SHA256_STATE ����ü�� ������
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# LOCATION^ISC_F_INIT_SHA256^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
*/
ISC_INTERNAL ISC_STATUS isc_Init_SHA256(ISC_SHA256_STATE *sha256);

/*!
* \brief
* ISC_SHA256 ������Ʈ �Լ�
* \param sha256
* ISC_SHA256_STATE ����ü�� ������
* \param data
* �ؽ��� �� �޽����� ������
* \param count
* �ؽ��� �� �޽����� ����
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_UPDATE_SHA256^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_UPDATE_SHA256^ISC_ERR_SUB_OPERATION_FAILURE
*/
ISC_INTERNAL ISC_STATUS isc_Update_SHA256(ISC_SHA256_STATE *sha256, const uint8 *data, uint32 count);

/*!
* \brief
* ISC_SHA256 ���̳� �Լ�
* \param sha256
* ISC_SHA256_STATE ����ü�� ������
* \param md
* �ؽ��� ����� ������ ������ ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_FINAL_SHA256^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_FINAL_SHA256^ISC_ERR_SUB_OPERATION_FAILURE : ���� final �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Final_SHA256(ISC_SHA256_STATE *sha256, uint8 *md);


/*!
* \brief
* ISC_SHA384 �ʱ�ȭ �Լ�
* \param sha384
* ISC_SHA384_STATE ����ü�� ������
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# LOCATION^ISC_F_INIT_SHA384^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
*/
ISC_INTERNAL ISC_STATUS isc_Init_SHA384(ISC_SHA384_STATE *sha384);

/*!
* \brief
* ISC_SHA384 ������Ʈ �Լ�
* \param sha384
* ISC_SHA384_STATE ����ü�� ������
* \param data
* �ؽ��� �� �޽����� ������
* \param count
* �ؽ��� �� �޽����� ����
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_UPDATE_SHA384^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
*/
ISC_INTERNAL ISC_STATUS isc_Update_SHA384(ISC_SHA384_STATE *sha384, const uint8 *data, uint32 count);

/*!
* \brief
* ISC_SHA384 ���̳� �Լ�
* \param sha384
* ISC_SHA384_STATE ����ü�� ������
* \param md
* �ؽ��� ����� ������ ������ ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_FINAL_SHA384^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_FINAL_SHA512^ISC_ERR_SUB_OPERATION_FAILURE : ���� final �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Final_SHA384(ISC_SHA384_STATE *sha384, uint8 *md);


/*!
* \brief
* ISC_SHA512 �ʱ�ȭ �Լ�
* \param sha512
* ISC_SHA512_STATE ����ü�� ������
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# LOCATION^ISC_F_INIT_SHA512^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
*/
ISC_INTERNAL ISC_STATUS isc_Init_SHA512(ISC_SHA512_STATE *sha512);

/*!
* \brief
* ISC_SHA512 ������Ʈ �Լ�
* \param sha512
* ISC_SHA512_STATE ����ü�� ������
* \param data
* �ؽ��� �� �޽����� ������
* \param dataLen
* �ؽ��� �� �޽����� ����
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_UPDATE_SHA512^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_UPDATE_SHA512^ISC_ERR_SUB_OPERATION_FAILURE : ���� update �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Update_SHA512(ISC_SHA512_STATE *sha512, const uint8 *data, uint32 dataLen);

/*!
* \brief
* ISC_SHA512 ���̳� �Լ�
* \param sha512
* ISC_SHA512_STATE ����ü�� ������
* \param md
* �ؽ��� ����� ������ ������ ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_FINAL_SHA512^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_FINAL_SHA512^ISC_ERR_SUB_OPERATION_FAILURE : ���� final �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Final_SHA512(ISC_SHA512_STATE *sha512, uint8 *md);

#ifdef  __cplusplus
}
#endif

#endif/* HEADER_SHA_H */


