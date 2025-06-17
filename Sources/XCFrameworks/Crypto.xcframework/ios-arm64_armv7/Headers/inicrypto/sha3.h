/*!
* \file sha3.h
* \brief SHA3 �˰���(224, 256, 384, 512) �������
* \author
* Copyright (c) 2021 by \<INITech\>
*/

#ifndef HEADER_SHA3_H
#define HEADER_SHA3_H


#define ISC_SHA3_PROVEN_MODE  	1    /*!<  0: ����� ���, 1: ������� */

#include "foundation.h"
#include "mem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ISC_SHA3_ROUND		    24
#define ISC_SHA3_SUFFIX		    0x06
#define ISC_SHA3_SPONGE_BIT     1600	/* state ũ�� (��Ʈ) */
#define ISC_SHA3_STATE_SIZE     200		/* state ũ�� (����Ʈ) */

/*--------------------------------------------------*/
#define ISC_SHA3_224_NAME				"SHA3-224"
#define ISC_SHA3_224_BLOCK_SIZE			144
#define ISC_SHA3_224_DIGEST_LENGTH		28
#define ISC_SHA3_224_INIT				isc_Init_SHA3_224
#define ISC_SHA3_224_UPDATE				isc_Update_SHA3_224
#define ISC_SHA3_224_FINAL				isc_Final_SHA3_224
#define ISC_SHA3_224_STATE_SIZE			sizeof(ISC_SHA3_STATE)
/*--------------------------------------------------*/

/*--------------------------------------------------*/
#define ISC_SHA3_256_NAME				"SHA3-256"
#define ISC_SHA3_256_BLOCK_SIZE			136
#define ISC_SHA3_256_DIGEST_LENGTH		32
#define ISC_SHA3_256_INIT				isc_Init_SHA3_256
#define ISC_SHA3_256_UPDATE				isc_Update_SHA3_256
#define ISC_SHA3_256_FINAL				isc_Final_SHA3_256
#define ISC_SHA3_256_STATE_SIZE			sizeof(ISC_SHA3_STATE)
/*--------------------------------------------------*/

/*--------------------------------------------------*/
#define ISC_SHA3_384_NAME				"SHA3-384"
#define ISC_SHA3_384_BLOCK_SIZE			104
#define ISC_SHA3_384_DIGEST_LENGTH		48
#define ISC_SHA3_384_INIT				isc_Init_SHA3_384
#define ISC_SHA3_384_UPDATE				isc_Update_SHA3_384
#define ISC_SHA3_384_FINAL				isc_Final_SHA3_384
#define ISC_SHA3_384_STATE_SIZE			sizeof(ISC_SHA3_STATE)
/*--------------------------------------------------*/

/*--------------------------------------------------*/
#define ISC_SHA3_512_NAME				"SHA3-512"
#define ISC_SHA3_512_BLOCK_SIZE			72
#define ISC_SHA3_512_DIGEST_LENGTH		64
#define ISC_SHA3_512_INIT				isc_Init_SHA3_512
#define ISC_SHA3_512_UPDATE				isc_Update_SHA3_512
#define ISC_SHA3_512_FINAL				isc_Final_SHA3_512
#define ISC_SHA3_512_STATE_SIZE			sizeof(ISC_SHA3_STATE)
/*--------------------------------------------------*/


#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* ISC_SHA3���� ���̴� ������ ��� �ִ� ����ü
*/
typedef struct isc_sha3_state_st {
	int bitSize;		/* ��� �ؽð� ����(��Ʈ) */
	int outLen;			/* ��� �ؽð� ����(����Ʈ) */
	int Capacity;		/* �ؽð� ���� * 2 */
	int Rate;			/* ��� ũ�� */
	int end_offset;		
	uint8 state[ISC_SHA3_STATE_SIZE]; 
} ISC_SHA3_STATE;

/*!
* \brief
* SHA3 sponge ������ keccak absorb �Լ�
* \param sha3
* ISC_SHA3_STATE ����ü�� ������
* \param input
* �ؽ��� �� �޽����� ������
* \param inLen
* �ؽ��� �� �޽����� ����
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_UPDATE_SHA3_224^ISC_ERR_INVALID_INPUT : �Է°� ����
*/
ISC_INTERNAL ISC_STATUS keccak_absorb(ISC_SHA3_STATE *sha3, uint8* input, int inLen);

/*!
* \brief
* SHA3 sponge ������ keccak squeeze �Լ�
* \param sha3
* ISC_SHA3_STATE ����ü�� ������
* \param output
* �ؽ��� ����� ������ ������ ������
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS keccak_squeeze(ISC_SHA3_STATE *sha3, uint8* output);

/*!
* \brief
* ISC_SHA3_224 �ʱ�ȭ �Լ�
* \param sha3_224
* ISC_SHA3_STATE ����ü�� ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_SHA3_224^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
*/
ISC_INTERNAL ISC_STATUS isc_Init_SHA3_224(ISC_SHA3_STATE *sha3_224);

/*!
* \brief
* ISC_SHA3_224 ������Ʈ �Լ�
* \param sha3_224
* ISC_SHA3_STATE ����ü�� ������
* \param input
* �ؽ��� �� �޽����� ������
* \param inLen
* �ؽ��� �� �޽����� ����
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_SHA3_224^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_UPDATE_SHA3_224^ISC_ERR_INVALID_INPUT : �Է°� ����
* -# LOCATION^ISC_F_UPDATE_SHA3_224^ISC_ERR_UPDATE_FAILURE : absorb �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Update_SHA3_224(ISC_SHA3_STATE *sha3_224, uint8 *input, int inLen);

/*!
* \brief
* ISC_SHA3_224 ���̳� �Լ�
* \param sha3_224
* ISC_SHA3_STATE ����ü�� ������
* \param output
* �ؽ��� ����� ������ ������ ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_FINAL_SHA3_224^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
*/
ISC_INTERNAL ISC_STATUS isc_Final_SHA3_224(ISC_SHA3_STATE *sha3_224, uint8 *output);

/*!
* \brief
* ISC_SHA3_256 �ʱ�ȭ �Լ�
* \param sha3_256
* ISC_SHA3_STATE ����ü�� ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_SHA3_256^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
*/
ISC_INTERNAL ISC_STATUS isc_Init_SHA3_256(ISC_SHA3_STATE *sha3_256);

/*!
* \brief
* ISC_SHA3_256 ������Ʈ �Լ�
* \param sha3_256
* ISC_SHA3_STATE ����ü�� ������
* \param input
* �ؽ��� �� �޽����� ������
* \param inLen
* �ؽ��� �� �޽����� ����
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_SHA3_256^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_UPDATE_SHA3_256^ISC_ERR_INVALID_INPUT : �Է°� ����
* -# LOCATION^ISC_F_UPDATE_SHA3_256^ISC_ERR_UPDATE_FAILURE : absorb �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Update_SHA3_256(ISC_SHA3_STATE *sha3_256, uint8 *input, int inLen);

/*!
* \brief
* ISC_SHA3_256 ���̳� �Լ�
* \param sha3_256
* ISC_SHA3_STATE ����ü�� ������
* \param output
* �ؽ��� ����� ������ ������ ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_FINAL_SHA3_256^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
*/
ISC_INTERNAL ISC_STATUS isc_Final_SHA3_256(ISC_SHA3_STATE *sha3_256, uint8 *output);

/*!
* \brief
* ISC_SHA3_384 �ʱ�ȭ �Լ�
* \param sha3_384
* ISC_SHA3_STATE ����ü�� ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_SHA3_384^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
*/
ISC_INTERNAL ISC_STATUS isc_Init_SHA3_384(ISC_SHA3_STATE *sha3_384);

/*!
* \brief
* ISC_SHA3_384 ������Ʈ �Լ�
* \param sha3_384
* ISC_SHA3_STATE ����ü�� ������
* \param input
* �ؽ��� �� �޽����� ������
* \param inLen
* �ؽ��� �� �޽����� ����
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_SHA3_384^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_UPDATE_SHA3_384^ISC_ERR_INVALID_INPUT : �Է°� ����
* -# LOCATION^ISC_F_UPDATE_SHA3_384^ISC_ERR_UPDATE_FAILURE : absorb �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Update_SHA3_384(ISC_SHA3_STATE *sha3_384, uint8 *input, int inLen);

/*!
* \brief
* ISC_SHA3_384 ���̳� �Լ�
* \param sha3_384
* ISC_SHA3_STATE ����ü�� ������
* \param output
* �ؽ��� ����� ������ ������ ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_FINAL_SHA3_384^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
*/
ISC_INTERNAL ISC_STATUS isc_Final_SHA3_384(ISC_SHA3_STATE *sha3_384, uint8 *output);

/*!
* \brief
* ISC_SHA3_512 �ʱ�ȭ �Լ�
* \param sha3_512
* ISC_SHA3_STATE ����ü�� ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_SHA3_512^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
*/
ISC_INTERNAL ISC_STATUS isc_Init_SHA3_512(ISC_SHA3_STATE *sha3_512);

/*!
* \brief
* ISC_SHA3_512 ������Ʈ �Լ�
* \param sha3_512
* ISC_SHA3_STATE ����ü�� ������
* \param input
* �ؽ��� �� �޽����� ������
* \param inLen
* �ؽ��� �� �޽����� ����
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_SHA3_512^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_UPDATE_SHA3_512^ISC_ERR_INVALID_INPUT : �Է°� ����
* -# LOCATION^ISC_F_UPDATE_SHA3_512^ISC_ERR_UPDATE_FAILURE : absorb �Լ� ����
*/
ISC_INTERNAL ISC_STATUS isc_Update_SHA3_512(ISC_SHA3_STATE *sha3_512, uint8 *input, int inLen);

/*!
* \brief
* ISC_SHA3_512 ���̳� �Լ�
* \param sha3_512
* ISC_SHA3_STATE ����ü�� ������
* \param output
* �ؽ��� ����� ������ ������ ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_FINAL_SHA3_512^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
*/
ISC_INTERNAL ISC_STATUS isc_Final_SHA3_512(ISC_SHA3_STATE *sha3_512, uint8 *output);


#ifdef  __cplusplus
}
#endif

#endif/* HEADER_SHA3_H */

