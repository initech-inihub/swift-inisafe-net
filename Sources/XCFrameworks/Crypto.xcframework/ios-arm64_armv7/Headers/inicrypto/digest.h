/*!
* \file digest.h
* \brief ISC_DIGEST �˰����� �������̽� �������
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_DIGEST_H
#define HEADER_DIGEST_H

#include "foundation.h"
#include "mem.h"

#ifndef ISC_NO_SHA
#include "sha.h"
#include "sha3.h"
#endif
#ifndef ISC_NO_HAS160
#include "has160.h"
#endif
#ifndef ISC_NO_MD5
#include "md5.h"
#endif
#if !defined (ISC_NO_MDC2) && !defined(ISC_NO_DES)
#include "mdc2.h"
#endif
#ifndef ISC_NO_LSH
#include "lsh.h"
#endif

/*!
Flag Definition
|---------------------------------------------------------------|
|------------Algorithm Identification-----------|-------|-------|
| 4bits | 4bits | 4bits | 4bits | 4bits | 4bits | 4bits | 4bits |
|---------------------------------------------------------------|
---------------------------------------------------------------------------------
*/
/*SHA Alias					0x05000000 ------------------------------------------------*/
#define ISC_SHA1			0x05000100												   /*!< ISC_SHA1 �˰��� ID*/
#define ISC_SHA224			0x05000200												   /*!< ISC_SHA224 �˰��� ID*/	
#define ISC_SHA256			0x05000300												   /*!< ISC_SHA256 �˰��� ID*/	
#define ISC_SHA384			0x05000400												   /*!< ISC_SHA384 �˰��� ID*/
#define ISC_SHA512			0x05000500                                                 /*!< ISC_SHA512 �˰��� ID*/

#define ISC_SHA3_224		0x05000600												   /*!< ISC_SHA3_224 �˰��� ID*/	
#define ISC_SHA3_256		0x05000700												   /*!< ISC_SHA3_256 �˰��� ID*/	
#define ISC_SHA3_384		0x05000800												   /*!< ISC_SHA3_384 �˰��� ID*/
#define ISC_SHA3_512		0x05000900                                                 /*!< ISC_SHA3_512 �˰��� ID*/

/*MD Alias					0x06000000 ------------------------------------------------*/
#define ISC_MD5				0x06000100                                                 /*!< ISC_MD5 �˰��� ID*/

/*HAS Alias					0x07000000 ------------------------------------------------*/
#define ISC_HAS160			0x07000100                                                 /*!< ISC_HAS160 �˰��� ID*/

/*ISC_DES-Based Alias		0x08000000 ------------------------------------------------*/
#define ISC_MDC2			0x08000100                                                 /*!< ISC_MDC2 �˰��� ID*/

/*LSH Alias					0x09000000 ------------------------------------------------*/
#define ISC_LSH256_224		0x09000100												   /*!< ISC_LSH256_224 �˰��� ID*/
#define ISC_LSH256_256		0x09000200												   /*!< ISC_LSH256_256 �˰��� ID*/

#define ISC_LSH512_224		0x09001100												   /*!< ISC_LSH512_224 �˰��� ID*/
#define ISC_LSH512_256		0x09001200												   /*!< ISC_LSH512_256 �˰��� ID*/
#define ISC_LSH512_384		0x09001300												   /*!< ISC_LSH512_384 �˰��� ID*/
#define ISC_LSH512_512		0x09001400												   /*!< ISC_LSH512_512 �˰��� ID*/

#define ISC_LSH224			ISC_LSH256_224
#define ISC_LSH256			ISC_LSH256_256
#define ISC_LSH384			ISC_LSH512_384
#define ISC_LSH512			ISC_LSH512_512


/*---------------------------------------------------------------------------------*/
#define ISC_MD5_PROVEN_MODE  1    /*!<  0: ����� ���, 1: ������� */
/*---------------------------------------------------------------------------------*/


#define ISC_DEFINE_DIGEST(algo);\
	unit->md_size = algo##_DIGEST_LENGTH;\
	unit->block_size = algo##_BLOCK_SIZE;\
	unit->state_size = algo##_STATE_SIZE;\
	unit->init = (int(*)(void*))algo##_INIT;\
	unit->update = (int(*)(void*, const uint8*, uint32))algo##_UPDATE;\
	unit->final = (int(*)(void*, uint8*))algo##_FINAL;\
	unit->state = NULL;

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* �ؽ����� ���̴� ������ ��� �ִ� ����ü
*/
struct isc_digest_unit_st
{
	uint32 algorithm;												/*!< �ؽ� �˰��� ID*/
	int block_size;												/*!< �ؽ� �˰����� Block Size*/
	int md_size;												/*!< �ؽ� ��� ���� ����*/
	void* state;												/*!< �ؽ��� STATE ����ü ������*/
	int state_size;												/*!< �ؽ��� STATE ũ��*/
	int (*init)(void* state);									/*!< �ؽ��� init �ݹ� �Լ� ������*/
	int (*update)(void* state, const uint8 *data, uint32 count);  /*!< �ؽ��� update �ݹ� �Լ� ������*/
	int (*final)(void* state, uint8 *md);						/*!< �ؽ��� final �ݹ� �Լ� ������*/
	int unit_status;	
	uint8 isproven;												/*!< ��ȣȭ ������ ���� �˰��� ���� ���� */
};

#define ISC_DIGESET_SIZE(unit)	((unit)->md_size)

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_DIGEST_UNIT ���� �Լ�
* \returns
* ������ ISC_DIGEST_UNIT�� ������
*/
ISC_API ISC_DIGEST_UNIT *ISC_New_DIGEST_Unit(void);

/*!
* \brief
* ISC_DIGEST_UNIT �ʱ�ȭ �Լ�
* \param unit
* ISC_DIGEST_UNIT�� ������
*/
ISC_API void ISC_Clean_DIGEST_Unit(ISC_DIGEST_UNIT *unit);

/*!
* \brief
* ISC_DIGEST_UNIT ���� �Լ�
* \param unit
* ISC_DIGEST_UNIT�� ������
*/
ISC_API void ISC_Free_DIGEST_Unit(ISC_DIGEST_UNIT *unit);


/*!
* \brief
* �ؽ� �ʱ�ȭ �Լ�
* \param unit
* ISC_DIGEST_UNIT�� ������
* \param alg_id
* �ؽ� �˰��� ID
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ� 
* -# ISC_L_DIGEST^ISC_F_INIT_DIGEST^ISC_ERR_INIT_FAILURE : NULL �Է°� �Է�
* -# ISC_L_DIGEST^ISC_F_INIT_DIGEST^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ����(isc_Init_DIGEST_Alg) ����
* -# ISC_L_DIGEST^ISC_F_INIT_DIGEST^ISC_ERR_INIT_DIGEST_FAIL : �˰��� �������̽� INIT DIGEST ����
*/
ISC_API ISC_STATUS ISC_Init_DIGEST(ISC_DIGEST_UNIT *unit, int alg_id);

/*!
* \brief
* �ؽ� ������Ʈ �Լ�
* \param unit
* ISC_DIGEST_UNIT�� ������
* \param message
* �ؽ��� �� �޽����� ������
* \param messageLen
* �ؽ��� �� �޽����� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_DIGEST^ISC_F_UPDATE_DIGEST^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_DIGEST^ISC_F_UPDATE_DIGEST^ISC_ERR_INVALID_INPUT : 0���� ���� �޽��� ���� �Է�
* -# ISC_L_DIGEST^ISC_F_UPDATE_DIGEST^ISC_ERR_UPDATE_DIGEST_FAIL : �˰��� �������̽� UPDATE DIGEST ����
*/
ISC_API ISC_STATUS ISC_Update_DIGEST(ISC_DIGEST_UNIT *unit, const uint8 *message, int messageLen);

/*!
* \brief
* �ؽ� ���̳� �Լ�
* \param unit
* ISC_DIGEST_UNIT�� ������
* \param digest
* �ؽ� ����� ������ ������ ������
* \param digestLen
* �ؽ� ����� ���̸� ������ ������ ������
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_DIGEST^ISC_F_FINAL_DIGEST^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_DIGEST^ISC_F_FINAL_DIGEST^ISC_ERR_FINAL_DIGEST_FAIL : �˰��� �������̽� FINAL DIGEST ����
*/
ISC_API ISC_STATUS ISC_Final_DIGEST(ISC_DIGEST_UNIT *unit, uint8 *digest, int *digestLen);

/*!
* \brief
* ISC_Init_DIGEST(), ISC_Update_DIGEST(), ISC_Final_DIGEST()�� �� ���� �ϴ� �Լ�
* \param alg_id
* �ؽ� �˰��� ID
* \param message
* �ؽ� �� �޽����� ������
* \param messageLen
* �ؽ� �� �޽����� ����
* \param digest
* �ؽ� ����� ������ ������ ������
* \param digestLen
* �ؽ� ����� ���̸� ������ ������ ������
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_DIGEST^ISC_F_DIGEST^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_DIGEST^ISC_F_DIGEST^ISC_ERR_MALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_DIGEST^ISC_F_DIGEST^ISC_ERR_INIT_DIGEST_FAIL : ISC_Init_DIGEST() �Լ� ����
* -# ISC_L_DIGEST^ISC_F_DIGEST^ISC_ERR_UPDATE_DIGEST_FAIL : ISC_Update_DIGEST() �Լ� ����
* -# ISC_L_DIGEST^ISC_F_DIGEST^ISC_ERR_FINAL_DIGEST_FAIL : ISC_Final_DIGEST() �Լ� ����
*/
ISC_API ISC_STATUS ISC_DIGEST(int alg_id, uint8 *message, int messageLen, uint8 *digest, int *digestLen);

/*!
* \brief
* �ؽ� �˰����� ID�� �����ϴ� �Լ�
* \param unit
* ISC_DIGEST_UNIT�� ������
* \returns
* -# �ؽ� �˰����� ID : Success
* -# 0 : �ؽ� �˰��� ID �������� ����
*/
ISC_API int ISC_Get_DIGEST_Alg_ID(ISC_DIGEST_UNIT *unit);

/*!
* \brief
* �ؽ� �˰����� �̸��� �����ϴ� �Լ�
* \param algorithm_id
* �ؽ� �˰��� ID
* \returns
* -# �ؽ� �˰����� �̸� : Success
* -# ISC_NULL_STRING : �ؽ� �˰��� �������� ����
*/
ISC_API char *ISC_Get_DIGEST_Alg_Name(int algorithm_id);

/*!
* \brief
* �ؽ� �˰����� ���̵� �����ϴ� �Լ�
* \param algorithm_name
* �ؽ� �˰��� �̸�
* \returns
* -# �ؽ� �˰����� ���̵� : Success
* -# TEST_FAIL : �ڰ� ���迡 ����
* -# 0 : �ؽ� �˰��� ID �������� ����
*/
ISC_API int ISC_Get_DIGEST_Alg_ID_By_Name(const char *algorithm_name);

/*!
* \brief
* �ؽ� �˰��� ����� ���̸� �����ϴ� �Լ�
* \param algorithm_id
* �ؽ� �˰��� ID
* \returns
* -# �ؽ� �˰��� ����� ���� : Success
* -# ISC_INVALID_SIZE : �ؽ� ����� ���� �������� ����
*/
ISC_API int ISC_Get_DIGEST_Length(int algorithm_id);

/*!
* \brief
* �ؽ� �˰��� �ʱ�ȭ �Լ�
* \param unit
* ISC_DIGEST_UNIT�� ������
* \param hash_id
* �ؽ� �˰��� ID
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�Լ� �����ڵ�
* -# ISC_L_DIGEST^ISC_F_INIT_DIGEST_ALG^ISC_ERR_NOT_PROVEN_ALGORITHM : ������忡�� ����� �˰��� ���
* -# ISC_L_DIGEST^ISC_F_INIT_DIGEST_ALG^ISC_ERR_INVALID_ALGORITHM_ID : �߸��� �˰��� ID �Է�
*/
ISC_INTERNAL ISC_STATUS isc_Init_DIGEST_Alg(ISC_DIGEST_UNIT *unit, int hash_id);

/*!
* \brief
* ISC_DIGEST_UNIT ���� �Լ�
* \param isproven ��ȣȭ ���� ��� ���� ����
* \returns
* ������ ISC_DIGEST_UNIT�� ������
*/
ISC_INTERNAL ISC_DIGEST_UNIT *isc_New_DIGEST_Unit_Ex(uint8 isproven);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_DIGEST_UNIT*, ISC_New_DIGEST_Unit, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_DIGEST_Unit, (ISC_DIGEST_UNIT *unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_DIGEST_Unit, (ISC_DIGEST_UNIT *unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_DIGEST, (ISC_DIGEST_UNIT *unit, int alg_id), (unit, alg_id), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Update_DIGEST, (ISC_DIGEST_UNIT *unit, const uint8 *message, int messageLen), (unit, message, messageLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Final_DIGEST, (ISC_DIGEST_UNIT *unit, uint8 *digest, int *digestLen), (unit, digest, digestLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_DIGEST, (int alg_id, uint8 *message, int messageLen, uint8 *digest, int *digestLen), (alg_id, message, messageLen, digest, digestLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, isc_Init_DIGEST_Alg, (ISC_DIGEST_UNIT *unit, int hash_id), (unit, hash_id), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(int, ISC_Get_DIGEST_Alg_ID, (ISC_DIGEST_UNIT *unit), (unit), 0 );
ISC_RET_LOADLIB_CRYPTO(char*, ISC_Get_DIGEST_Alg_Name, (int algorithm_id), (algorithm_id), NULL );
ISC_RET_LOADLIB_CRYPTO(int, ISC_Get_DIGEST_Alg_ID_By_Name, (const char *algorithm_name), (algorithm_name), 0 );
ISC_RET_LOADLIB_CRYPTO(int, ISC_Get_DIGEST_Length, (int algorithm_id), (algorithm_id), 0 );

#endif

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_DIGEST_H */

