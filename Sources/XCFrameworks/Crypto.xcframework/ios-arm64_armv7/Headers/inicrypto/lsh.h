/*!
* \file lsh.h
* \brief LSH �˰���(256, 512) �������
* \author
* Copyright (c) 2021 by \<INITech\>
*/

#ifndef HEADER_LSH_H
#define HEADER_LSH_H

#ifdef ISC_NO_LSH
#error LSH is disabled.
#endif

#include "foundation.h"
#include "mem.h"
#include "utils.h"
#include "isc_endian.h"

/* LSH Constants */
#define ISC_LSH_TYPE_256_256				0x0000020
#define ISC_LSH_TYPE_256_224				0x000001C

#define ISC_LSH_TYPE_512_512				0x0010040
#define ISC_LSH_TYPE_512_384				0x0010030
#define ISC_LSH_TYPE_512_256				0x0010020
#define ISC_LSH_TYPE_512_224				0x001001C


/* LSH Constants */
#define ISC_LSH256_BLOCK_SIZE			128
/* #define LSH256_HASH_VAL_MAX_BYTE_LEN	32 */

#define ISC_LSH512_BLOCK_SIZE			256
/* #define LSH512_HASH_VAL_MAX_BYTE_LEN	64 */


/*----------------------------------------------------------------------------------------------------*/
#define ISC_LSH256_224_NAME					"LSH256_224"
#define ISC_LSH256_224_BLOCK_SIZE			ISC_LSH256_BLOCK_SIZE
#define ISC_LSH256_224_DIGEST_LENGTH		ISC_LSH_TYPE_256_224
#define ISC_LSH256_224_INIT					isc_Init_LSH256_224
#define ISC_LSH256_224_UPDATE				isc_Update_LSH256_224
#define ISC_LSH256_224_FINAL				isc_Final_LSH256_224
#define ISC_LSH256_224_STATE_SIZE			sizeof(ISC_LSH256_STATE)
/*----------------------------------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------------------------------*/
#define ISC_LSH256_256_NAME					"LSH256_256"
#define ISC_LSH256_256_BLOCK_SIZE			ISC_LSH256_BLOCK_SIZE
#define ISC_LSH256_256_DIGEST_LENGTH		ISC_LSH_TYPE_256_256
#define ISC_LSH256_256_INIT					isc_Init_LSH256_256
#define ISC_LSH256_256_UPDATE				isc_Update_LSH256_256
#define ISC_LSH256_256_FINAL				isc_Final_LSH256_256
#define ISC_LSH256_256_STATE_SIZE			sizeof(ISC_LSH256_STATE)
/*----------------------------------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------------------------------*/
#define ISC_LSH512_224_NAME					"LSH512_224"
#define ISC_LSH512_224_BLOCK_SIZE			ISC_LSH512_BLOCK_SIZE
#define ISC_LSH512_224_DIGEST_LENGTH		(ISC_LSH_TYPE_512_224 & 0xffff)
#define ISC_LSH512_224_INIT					isc_Init_LSH512_224
#define ISC_LSH512_224_UPDATE				isc_Update_LSH512_224
#define ISC_LSH512_224_FINAL				isc_Final_LSH512_224
#define ISC_LSH512_224_STATE_SIZE			sizeof(ISC_LSH512_STATE)
/*----------------------------------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------------------------------*/
#define ISC_LSH512_256_NAME					"LSH512_256"
#define ISC_LSH512_256_BLOCK_SIZE			ISC_LSH512_BLOCK_SIZE
#define ISC_LSH512_256_DIGEST_LENGTH		(ISC_LSH_TYPE_512_256 & 0xffff)
#define ISC_LSH512_256_INIT					isc_Init_LSH512_256
#define ISC_LSH512_256_UPDATE				isc_Update_LSH512_256
#define ISC_LSH512_256_FINAL				isc_Final_LSH512_256
#define ISC_LSH512_256_STATE_SIZE			sizeof(ISC_LSH512_STATE)
/*----------------------------------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------------------------------*/
#define ISC_LSH512_384_NAME					"LSH512_384"
#define ISC_LSH512_384_BLOCK_SIZE			ISC_LSH512_BLOCK_SIZE
#define ISC_LSH512_384_DIGEST_LENGTH		(ISC_LSH_TYPE_512_384 & 0xffff)
#define ISC_LSH512_384_INIT					isc_Init_LSH512_384
#define ISC_LSH512_384_UPDATE				isc_Update_LSH512_384
#define ISC_LSH512_384_FINAL				isc_Final_LSH512_384
#define ISC_LSH512_384_STATE_SIZE			sizeof(ISC_LSH512_STATE)
/*----------------------------------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------------------------------*/
#define ISC_LSH512_512_NAME					"LSH512_512"
#define ISC_LSH512_512_BLOCK_SIZE			ISC_LSH512_BLOCK_SIZE
#define ISC_LSH512_512_DIGEST_LENGTH		(ISC_LSH_TYPE_512_512 & 0xffff)
#define ISC_LSH512_512_INIT					isc_Init_LSH512_512
#define ISC_LSH512_512_UPDATE				isc_Update_LSH512_512
#define ISC_LSH512_512_FINAL				isc_Final_LSH512_512
#define ISC_LSH512_512_STATE_SIZE			sizeof(ISC_LSH512_STATE)
/*----------------------------------------------------------------------------------------------------*/

#ifdef __cplusplus
extern "C" {
#endif

	/*!
	* \brief
	* ISC_LSH256_224, ISC_LSH256_256���� ���̴� ������ ��� �ִ� ����ü
	*/
	typedef struct isc_lsh256_state_st {
		uint32_t algtype;
		uint32_t remain_databitlen;
		uint32_t cv_l[8];
		uint32_t cv_r[8];
		uint8_t last_block[ISC_LSH256_BLOCK_SIZE];
	} ISC_LSH256_STATE;


	/*!
	* \brief
	* ISC_LSH512_224, ISC_LSH512_256, ISC_LSH512_384, ISC_LSH512_512���� ���̴� ������ ��� �ִ� ����ü
	*/
	typedef struct isc_lsh512_state_st {
		uint32_t algtype;
		uint32_t remain_databitlen;
		uint64_t cv_l[8];
		uint64_t cv_r[8];
		uint8_t last_block[ISC_LSH512_BLOCK_SIZE];
	} ISC_LSH512_STATE;

	/*!
	* \brief
	* ISC_LSH256_224 �ʱ�ȭ �Լ�
	* \param state
	* ISC_LSH256_STATE ����ü�� ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_INIT_LSH256_224^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	* -# ISC_Crypto_Initialize()�� �����ڵ�
	*/
    ISC_INTERNAL ISC_STATUS isc_Init_LSH256_224(void *state);

	/*!
	* \brief
	* ISC_LSH256_224 ������Ʈ �Լ�
	* \param state
	* ISC_LSH256_STATE ����ü�� ������
	* \param data
	* �ؽ��� �� �޽����� ������
	* \param count
	* �ؽ��� �� �޽����� ����
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_UPDATE_LSH256_224^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	*/
    ISC_INTERNAL ISC_STATUS isc_Update_LSH256_224(void *state, const uint8 *data, uint32 count);

	/*!
	* \brief
	* ISC_LSH256_224 ���̳� �Լ�
	* \param state
	* ISC_LSH256_STATE ����ü�� ������
	* \param md
	* �ؽ��� ����� ������ ������ ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -#  LOCATION^ISC_F_FINAL_LSH256_224^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	*/
    ISC_INTERNAL ISC_STATUS isc_Final_LSH256_224(void *state, uint8 *md);


	/*!
	* \brief
	* ISC_LSH256_256 �ʱ�ȭ �Լ�
	* \param state
	* ISC_LSH256_STATE ����ü�� ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_INIT_LSH256_256^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	* -# ISC_Crypto_Initialize()�� �����ڵ�
	*/
    ISC_INTERNAL ISC_STATUS isc_Init_LSH256_256(void *state);

	/*!
	* \brief
	* ISC_LSH256_256 ������Ʈ �Լ�
	* \param state
	* ISC_LSH256_STATE ����ü�� ������
	* \param data
	* �ؽ��� �� �޽����� ������
	* \param count
	* �ؽ��� �� �޽����� ����
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_UPDATE_LSH256_256^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	*/
    ISC_INTERNAL ISC_STATUS isc_Update_LSH256_256(void *state, const uint8 *data, uint32 count);

	/*!
	* \brief
	* ISC_LSH256_256 ���̳� �Լ�
	* \param state
	* ISC_LSH256_STATE ����ü�� ������
	* \param md
	* �ؽ��� ����� ������ ������ ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -#  LOCATION^ISC_F_FINAL_LSH256_256^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	*/
    ISC_INTERNAL ISC_STATUS isc_Final_LSH256_256(void *state, uint8 *md);


	/*!
	* \brief
	* ISC_LSH512_224 �ʱ�ȭ �Լ�
	* \param state
	* ISC_LSH512_STATE ����ü�� ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_INIT_LSH512_224^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	* -# ISC_Crypto_Initialize()�� �����ڵ�
	*/
    ISC_INTERNAL ISC_STATUS isc_Init_LSH512_224(void *state);

	/*!
	* \brief
	* ISC_LSH512_224 ������Ʈ �Լ�
	* \param state
	* ISC_LSH512_STATE ����ü�� ������
	* \param data
	* �ؽ��� �� �޽����� ������
	* \param count
	* �ؽ��� �� �޽����� ����
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_UPDATE_LSH512_224^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	*/
    ISC_INTERNAL ISC_STATUS isc_Update_LSH512_224(void *state, const uint8 *data, uint32 count);

	/*!
	* \brief
	* ISC_LSH512_224 ���̳� �Լ�
	* \param state
	* ISC_LSH512_STATE ����ü�� ������
	* \param md
	* �ؽ��� ����� ������ ������ ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -#  LOCATION^ISC_F_FINAL_LSH512_224^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	*/
    ISC_INTERNAL ISC_STATUS isc_Final_LSH512_224(void *state, uint8 *md);


	/*!
	* \brief
	* ISC_LSH512_256 �ʱ�ȭ �Լ�
	* \param state
	* ISC_LSH512_STATE ����ü�� ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_INIT_LSH512_256^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	* -# ISC_Crypto_Initialize()�� �����ڵ�
	*/
    ISC_INTERNAL ISC_STATUS isc_Init_LSH512_256(void *state);

	/*!
	* \brief
	* ISC_LSH512_256 ������Ʈ �Լ�
	* \param state
	* ISC_LSH512_STATE ����ü�� ������
	* \param data
	* �ؽ��� �� �޽����� ������
	* \param count
	* �ؽ��� �� �޽����� ����
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_UPDATE_LSH512_256^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	*/
    ISC_INTERNAL ISC_STATUS isc_Update_LSH512_256(void *state, const uint8 *data, uint32 count);

	/*!
	* \brief
	* ISC_LSH512_256 ���̳� �Լ�
	* \param state
	* ISC_LSH512_STATE ����ü�� ������
	* \param md
	* �ؽ��� ����� ������ ������ ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -#  LOCATION^ISC_F_FINAL_LSH512_256^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	*/
    ISC_INTERNAL ISC_STATUS isc_Final_LSH512_256(void *state, uint8 *md);


	/*!
	* \brief
	* ISC_LSH512_384 �ʱ�ȭ �Լ�
	* \param state
	* ISC_LSH512_STATE ����ü�� ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_INIT_LSH512_384^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	* -# ISC_Crypto_Initialize()�� �����ڵ�
	*/
    ISC_INTERNAL ISC_STATUS isc_Init_LSH512_384(void *state);

	/*!
	* \brief
	* ISC_LSH512_384 ������Ʈ �Լ�
	* \param state
	* ISC_LSH512_STATE ����ü�� ������
	* \param data
	* �ؽ��� �� �޽����� ������
	* \param count
	* �ؽ��� �� �޽����� ����
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_UPDATE_LSH512_384^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	*/
    ISC_INTERNAL ISC_STATUS isc_Update_LSH512_384(void *state, const uint8 *data, uint32 count);

	/*!
	* \brief
	* ISC_LSH512_384 ���̳� �Լ�
	* \param state
	* ISC_LSH512_STATE ����ü�� ������
	* \param md
	* �ؽ��� ����� ������ ������ ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -#  LOCATION^ISC_F_FINAL_LSH512_384^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	*/
    ISC_INTERNAL ISC_STATUS isc_Final_LSH512_384(void *state, uint8 *md);


	/*!
	* \brief
	* ISC_LSH512_512 �ʱ�ȭ �Լ�
	* \param state
	* ISC_LSH512_STATE ����ü�� ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_INIT_LSH512_512^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	* -# ISC_Crypto_Initialize()�� �����ڵ�
	*/
    ISC_INTERNAL ISC_STATUS isc_Init_LSH512_512(void *state);

	/*!
	* \brief
	* ISC_LSH512_512 ������Ʈ �Լ�
	* \param state
	* ISC_LSH512_STATE ����ü�� ������
	* \param data
	* �ؽ��� �� �޽����� ������
	* \param count
	* �ؽ��� �� �޽����� ����
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_UPDATE_LSH512_512^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	*/
    ISC_INTERNAL ISC_STATUS isc_Update_LSH512_512(void *state, const uint8 *data, uint32 count);

	/*!
	* \brief
	* ISC_LSH512_512 ���̳� �Լ�
	* \param state
	* ISC_LSH512_STATE ����ü�� ������
	* \param md
	* �ؽ��� ����� ������ ������ ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -#  LOCATION^ISC_F_FINAL_LSH512_512^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	*/
    ISC_INTERNAL ISC_STATUS isc_Final_LSH512_512(void *state, uint8 *md);

		/*!
	* \brief
	* ISC_LSH256 �ʱ�ȭ �Լ�
	* \param algType
	* ISC_LSH256 �˰��� Ÿ��(224, 256)
	* \param state
	* ISC_LSH256_STATE ����ü�� ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_INIT_LSH256_xxx^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	* -# ISC_Crypto_Initialize()�� �����ڵ�
	*/
    ISC_INTERNAL ISC_STATUS lsh256_init(const uint32_t algType, ISC_LSH256_STATE *state);

	/*!
	* \brief
	* ISC_LSH256 ������Ʈ �Լ�
	* \param algType
	* ISC_LSH256 �˰��� Ÿ��(224, 256)
	* \param state
	* ISC_LSH256_STATE ����ü�� ������
	* \param data
	* �ؽ��� �� �޽����� ������
	* \param count
	* �ؽ��� �� �޽����� ����
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_UPDATE_LSH256_xxx^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	*/
    ISC_INTERNAL ISC_STATUS lsh256_update(const uint32_t algType, ISC_LSH256_STATE *state, const uint8 *data, uint32 count);

	/*!
	* \brief
	* ISC_LSH256 ���̳� �Լ�
	* \param algType
	* ISC_LSH256 �˰��� Ÿ��(224, 256)
	* \param state
	* ISC_LSH256_STATE ����ü�� ������
	* \param md
	* �ؽ��� ����� ������ ������ ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -#  LOCATION^ISC_F_FINAL_LSH256_xxx^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	*/
    ISC_INTERNAL ISC_STATUS lsh256_final(const uint32_t algType, ISC_LSH256_STATE *state, uint8 *md);


	/*!
	* \brief
	* ISC_LSH512 �ʱ�ȭ �Լ�
	* \param algType
	* ISC_LSH512 �˰��� Ÿ��(224, 256, 384, 512)
	* \param state
	* ISC_LSH512_STATE ����ü�� ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_INIT_LSH512_224^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	* -# ISC_Crypto_Initialize()�� �����ڵ�
	*/
    ISC_INTERNAL ISC_STATUS lsh512_init(const uint32_t algType, ISC_LSH512_STATE *state);

	/*!
	* \brief
	* ISC_LSH512 ������Ʈ �Լ�
	* \param algType
	* ISC_LSH512 �˰��� Ÿ��(224, 256, 384, 512)
	* \param state
	* ISC_LSH512_STATE ����ü�� ������
	* \param data
	* �ؽ��� �� �޽����� ������
	* \param count
	* �ؽ��� �� �޽����� ����
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_UPDATE_LSH512_xxx^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	*/
    ISC_INTERNAL ISC_STATUS lsh512_update(const uint32_t algType, ISC_LSH512_STATE *state, const uint8 *data, uint32 count);

	/*!
	* \brief
	* ISC_LSH512 ���̳� �Լ�
	* \param algType
	* ISC_LSH512 �˰��� Ÿ��(224, 256, 384, 512)
	* \param state
	* ISC_LSH512_STATE ����ü�� ������
	* \param md
	* �ؽ��� ����� ������ ������ ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -#  LOCATION^ISC_F_FINAL_LSH512_224^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
	*/
    ISC_INTERNAL ISC_STATUS lsh512_final(const uint32_t algType, ISC_LSH512_STATE *state, uint8 *md);

#ifdef __cplusplus
}
#endif

#endif/* HEADER_LSH_H */

