/*!
* \file hmac.h
* \brief HMAC �������
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_HMAC_H
#define HEADER_HMAC_H

#include "foundation.h"
#include "mem.h"
#include "digest.h"

#ifdef ISC_NO_HMAC
#error HMAC is disabled.
#endif

#define ISC_MAX_HMAC_BLOCK 256 /* HMAC �� ���� ū ������ : ISC_LSH512_BLOCK_SIZE */
#define ISC_OPAD 0x5C
#define ISC_IPAD 0x36

/*Flag Definition
 |---------------------------------------------------------------|
 |------------Algorithm Identification-----------|-------|-------|
 | 4bits | 4bits | 4bits | 4bits | 4bits | 4bits | 4bits | 4bits |
 |---------------------------------------------------------------|
--------------------------------------------------------------------------------- */
/*HMAC Alias					0x10000000 ------------------------------------------------*/
#define ISC_HMAC_NAME			"HMAC"
#define ISC_HMAC_ID				0x10000000
#define ISC_HMAC_SHA1			0x15000100                                                 /*!< ISC_HMAC_SHA1 �˰��� ID*/
#define ISC_HMAC_SHA224			0x15000200												   /*!< ISC_HMAC_SHA224 �˰��� ID*/
#define ISC_HMAC_SHA256			0x15000300												   /*!< ISC_HMAC_SHA256 �˰��� ID*/
#define ISC_HMAC_SHA384			0x15000400												   /*!< ISC_HMAC_SHA384 �˰��� ID*/
#define ISC_HMAC_SHA512			0x15000500												   /*!< ISC_HMAC_SHA512 �˰��� ID*/
#define ISC_HMAC_SHA3_224		0x15000600												   /*!< ISC_HMAC_SHA3_224 �˰��� ID*/
#define ISC_HMAC_SHA3_256		0x15000700												   /*!< ISC_HMAC_SHA3_256 �˰��� ID*/
#define ISC_HMAC_SHA3_384		0x15000800												   /*!< ISC_HMAC_SHA3_384 �˰��� ID*/
#define ISC_HMAC_SHA3_512		0x15000900												   /*!< ISC_HMAC_SHA3_512 �˰��� ID*/
#define ISC_HMAC_MD5			0x16000100												   /*!< ISC_HMAC_MD5 �˰��� ID*/
#define ISC_HMAC_HAS160			0x17000100												   /*!< ISC_HMAC_HAS160 �˰��� ID*/
#define ISC_HMAC_MDC2			0x18000100												   /*!< ISC_HMAC_MDC2 �˰��� ID*/
#define ISC_HMAC_LSH256_224		0x19000100												   /*!< ISC_HMAC_LSH256_224 �˰��� ID*/
#define ISC_HMAC_LSH256_256		0x19000200												   /*!< ISC_HMAC_LSH256_256 �˰��� ID*/
#define ISC_HMAC_LSH512_224		0x19001100												   /*!< ISC_HMAC_LSH512_224 �˰��� ID*/
#define ISC_HMAC_LSH512_256		0x19001200												   /*!< ISC_HMAC_LSH512_256 �˰��� ID*/
#define ISC_HMAC_LSH512_384		0x19001300												   /*!< ISC_HMAC_LSH512_384 �˰��� ID*/
#define ISC_HMAC_LSH512_512		0x19001400												   /*!< ISC_HMAC_LSH512_512 �˰��� ID*/

																				   
#ifdef  __cplusplus																   
extern "C" {
#endif

/*!
* \brief
* HMAC���� ���̴� ������ ��� �ִ� ����ü
*/
struct isc_hmac_unit_st
{
	uint32 algorithm;       /*!< HMAC �˰��� ID*/
	ISC_DIGEST_UNIT *md_unit; /*!< ISC_DIGEST_UNIT ����ü ������*/
	void* state_i;        /*!< HMAC state_i*/
	void* state_o;        /*!< HMAC state_o*/
	uint32 state_length;    /*!< �ؽ� STATE�� ����*/
	uint8 key[ISC_MAX_HMAC_BLOCK];       /*!< HMAC Ű �迭*/ 
	int key_length;       /*!< HMAC Ű�� ����*/ 
	int hmac_status;      /*!< HMAC ���� ���� \n 0:Just Created \n 1:init done(ready to update) \n 2:in update progress \n 3:flushed(final)*/
	int unit_status;
	uint8 isproven;		  /*!< ��ȣȭ ������ ���� �˰��� ���� ���� */
};

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_HMAC_UNIT ���� �Լ�
* \returns
* ������ ISC_HMAC_UNIT�� ������
*/
ISC_API ISC_HMAC_UNIT *ISC_New_HMAC_Unit(void);


/*!
* \brief
* ISC_HMAC_UNIT �ʱ�ȭ �Լ�
* \param unit
* ISC_HMAC_UNIT�� ������
*/
ISC_API void ISC_Clean_HMAC_Unit(ISC_HMAC_UNIT *unit);

/*!
* \brief
* ISC_HMAC_UNIT ����ü �޸� ���� �Լ�
* \param unit
* ISC_HMAC_UNIT�� ������
*/
ISC_API void ISC_Free_HMAC_Unit(ISC_HMAC_UNIT *unit);

/*!
* \brief
* HMAC �ʱ�ȭ �Լ�
* \param unit
* ISC_HMAC_UNIT�� ������
* \param digest_id
* �ؽ� �˰��� ID
* \param key
* HMAC Ű�� ������
* \param keyLen
* HMA Ű�� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_HMAC^ISC_F_INIT_HMAC^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_HMAC^ISC_F_INIT_HMAC^ISC_ERR_INIT_DIGEST_FAIL : INIT DIGEST ����
* -# ISC_L_HMAC^ISC_F_INIT_HMAC^ISC_ERR_SUB_OPERATION_FAILURE : ���� ���� ����
* -# ISC_L_HMAC^ISC_F_INIT_HMAC^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST ����
* -# ISC_L_HMAC^ISC_F_INIT_HMAC^ISC_ERR_FINAL_DIGEST_FAIL : FINAL DIGEST ����
*/
ISC_API ISC_STATUS ISC_Init_HMAC(ISC_HMAC_UNIT *unit, int digest_id, uint8 *key, int keyLen);

/*!
* \brief
* HMAC ������Ʈ �Լ�
* \param unit
* ISC_HMAC_UNIT�� ������
* \param data
* �ؽ��� �� �޽����� ������
* \param len
* �ؽ��� �� �޽����� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_HMAC^ISC_F_UPDATE_HMAC^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_HMAC^ISC_F_UPDATE_HMAC^ISC_ERR_INVALID_INPUT : �߸��� �Է°� �Է�
* -# ISC_L_HMAC^ISC_F_UPDATE_HMAC^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST ����
*/
ISC_API ISC_STATUS ISC_Update_HMAC(ISC_HMAC_UNIT *unit, const uint8 *data, int len);

/*!
* \brief
* HMAC ���̳� �Լ�
* \param unit
* ISC_HMAC_UNIT�� ������
* \param digest
* �ؽ� ����� ������ ������ ������
* \param len
* �ؽ� ����� ���̸� ������ ������ ������
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_HMAC^ISC_F_FINAL_HMAC^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_HMAC^ISC_F_FINAL_HMAC^ISC_ERR_FINAL_DIGEST_FAIL : FINAL DIGEST ����
* -# ISC_L_HMAC^ISC_F_FINAL_HMAC^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST ����
*/
ISC_API ISC_STATUS ISC_Final_HMAC(ISC_HMAC_UNIT *unit, uint8 *digest, int *len);

/*!
* \brief
* ISC_Init_HMAC(), ISC_Update_HMAC(), final_HAMC()�� �� ���� �ϴ� �Լ�
* \param algorithm_id
* �ؽ� �˰��� ID
* \param key
* HMAC Ű�� ������
* \param keyLen
* HMAC Ű�� ����
* \param data
* �ؽ��� �� �޽����� ������
* \param dataLen
* �ؽ��� �� �޽����� ����
* \param digest
* �ؽ� ����� ������ ������ ������
* \param digestLen
* �ؽ� ����� ���̸� ������ ������ ������
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_HMAC^ISC_F_HMAC^ISC_ERR_MEM_ALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_HMAC^ISC_F_HMAC^ISC_ERR_INIT_FAILURE : INIT HMAC ����
* -# ISC_L_HMAC^ISC_F_HMAC^ISC_ERR_UPDATE_FAILURE : UPDATE HMAC ����
* -# ISC_L_HMAC^ISC_F_HMAC^ISC_ERR_FINAL_FAILURE : FINAL HMAC ����
*/
ISC_API ISC_STATUS ISC_HMAC(int algorithm_id,
		 uint8 *key,
		 int keyLen,
		 const uint8 *data,
		 int dataLen,
		 uint8 *digest,
		 int *digestLen);

/*!
* \brief
* HMAC�� �̸��� �����ϴ� �Լ�
* \param algo_id
* �ؽ� �˰��� ID
* \returns
* -# HMAC �̸��� ������ : Success
* -# NULL : Fail
*/
ISC_API char* ISC_Get_HMAC_Name(int algo_id);

/*!
* \brief
* ISC_HMAC_UNIT ���� �Լ�
* \param isproven ��ȣȭ ���� ��� ���� ����
* \returns
* ������ ISC_HMAC_UNIT�� ������
*/
ISC_INTERNAL ISC_HMAC_UNIT *isc_New_HMAC_Unit_Ex(uint8 isproven);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_HMAC_UNIT*, ISC_New_HMAC_Unit, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_HMAC_Unit, (ISC_HMAC_UNIT *unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_HMAC_Unit, (ISC_HMAC_UNIT *unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_HMAC, (ISC_HMAC_UNIT *unit, int digest_id, uint8 *key, int keyLen), (unit, digest_id, key, keyLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Update_HMAC, (ISC_HMAC_UNIT *unit, const uint8 *data, int len), (unit, data, len), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Final_HMAC, (ISC_HMAC_UNIT *unit, uint8 *digest, int *len), (unit, digest, len), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_HMAC, (int algorithm_id, uint8 *key, int keyLen, const uint8 *data, int dataLen, uint8 *digest, int *digestLen), (algorithm_id, key, keyLen, data, dataLen, digest, digestLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(char*, ISC_Get_HMAC_Name, (int algo_id), (algo_id), NULL );

#endif

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_HMAC_H */


