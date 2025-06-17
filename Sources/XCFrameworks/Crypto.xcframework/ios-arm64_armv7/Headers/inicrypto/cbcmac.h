/*!
* \file cbcmac.h
* \brief
* CBC MAC ��� ����
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_CBCMAC_H
#define HEADER_CBCMAC_H

#include "foundation.h"
#include "mem.h"

#define ISC_CBC_MAC_PROVEN_MODE    1    /*!<  0: ����� ���, 1: ������� */

#ifdef ISC_NO_CBC_MAC
#error ISC_CBC_MAC is disabled.
#endif

#define ISC_CBC_MAC_STATE_SIZE 64

#define ISC_CBC_MAC_AL_MASK		0x00F00000
#define ISC_CBC_MAC_AL1			0x00100000
#define ISC_CBC_MAC_AL2			0x00200000
#define ISC_CBC_MAC_AL3			0x00300000

/* PAD1 is Zero Padding */
#define ISC_CBC_MAC_PAD_MASK	0x0000000F
#define ISC_CBC_MAC_PAD1		0x00000001
#define ISC_CBC_MAC_PAD2		0x00000002

/*!
* \brief
* ISC_CBC_MAC���� ���̴� ������ ��� �ִ� ����ü
*/
struct isc_cbc_mac_st
{
	ISC_BLOCK_CIPHER_UNIT *cipher;			/*!< ISC_BLOCK_CIPHER_UNIT ����ü ������*/
	uint8 state[ISC_CBC_MAC_STATE_SIZE];	/*!< �� �ܰ躰 ���� �ӽ÷� ����*/
	uint8 buf[ISC_CBC_MAC_STATE_SIZE];		/*!< �ӽ� ����*/
	int bufLen;							/*!< buf�� ���� */
	ISC_BLOCK_CIPHER_UNIT *cipher2;
	int mode;								/* �˰���� �е� ��� */
};

#ifdef  __cplusplus
extern "C" {
#endif


#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_CBC_MAC_UNIT ���� �Լ�
* \returns
* ������ ISC_CBC_MAC_UNIT�� ������
*/
ISC_API ISC_CBC_MAC_UNIT* ISC_New_CBC_MAC_Unit();

/*!
* \brief
* ISC_CBC_MAC_UNIT �ʱ�ȭ �Լ�
* \param unit
* ISC_CBC_MAC_UNIT�� ������
*/
ISC_API void ISC_Clean_CBC_MAC_Unit(ISC_CBC_MAC_UNIT *unit);

/*!
* \brief
* ISC_CBC_MAC_UNIT ���� �Լ�
* \param unit
* ISC_CBC_MAC_UNIT�� ������
*/
ISC_API void ISC_Free_CBC_MAC_Unit(ISC_CBC_MAC_UNIT *unit);

/*!
* \brief
* ISC_CBC_MAC �ʱ�ȭ �Լ�
* \param unit
* ISC_CBC_MAC_UNIT�� ������
* \param block_algo_id
* �� �˰��� ID
* \param key
* ISC_CBC_MAC Ű�� ������
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�Լ��� �����ڵ�
* -# ISC_L_CBC_MAC^ISC_F_INIT_CBC_MAC^ISC_ERR_NOT_PROVEN_ALGORITHM : ������忡�� ����� �˰��� ���
* -# ISC_L_CBC_MAC^ISC_F_INIT_CBC_MAC^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_CBC_MAC^ISC_F_INIT_CBC_MAC^ISC_ERR_INIT_BLOCKCIPHER_FAIL : INIT BLOCKCIPHER ����
*/
ISC_API ISC_STATUS ISC_Init_CBC_MAC(ISC_CBC_MAC_UNIT *unit, int cbc_algo_id, const uint8 *key);

/*!
* \brief
* ISC_CBC_MAC ������Ʈ �Լ�
* \param unit
* ISC_CBC_MAC_UNIT�� ������
* \param in
* �Է°�
* \param inLen
* �Է°��� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_CBC_MAC^ISC_F_UPDATE_CBC_MAC^ISC_ERR_UPDATE_BLOCKCIPHER_FAIL : UPDATE BLOCKCIPHER ����
*/
ISC_API ISC_STATUS ISC_Update_CBC_MAC(ISC_CBC_MAC_UNIT *unit, const uint8* in, int inLen);

/*!
* \brief
* ISC_CBC_MAC final �Լ�
* \param unit
* ISC_CBC_MAC_UNIT�� ������
* \param out
* ��°�
* \param outLen
* ��°��� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_CBC_MAC^ISC_F_UPDATE_CBC_MAC^ISC_ERR_UPDATE_BLOCKCIPHER_FAIL : UPDATE BLOCKCIPHER ����
*/
ISC_API ISC_STATUS ISC_Final_CBC_MAC(ISC_CBC_MAC_UNIT *unit, uint8* out, int* outLen);

/*!
* \brief
* CBC-MAC ���� ó�� �Լ�
* \param block_algo_id
* CBC MAC�� ���� �� ��ȣ�� Algo ID
* \param key
* Ű��
* \param in
* �Է°�
* \param inLen
* �Է°��� ����
* \param out
* ��°� (MAC��)
* \param outLen
* ��°��� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_CBC_MAC^ISC_F_CBC_MAC^ISC_ERR_MEM_ALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_CBC_MAC^ISC_F_CBC_MAC^ISC_ERR_INIT_FAILURE : INIT CBCMAC ����
* -# ISC_L_CBC_MAC^ISC_F_CBC_MAC^ISC_ERR_UPDATE_FAILURE : UPDATE CBCMAC ����
* -# ISC_L_CBC_MAC^ISC_F_CBC_MAC^ISC_ERR_FINAL_FAILURE :  FINAL CBCMAC ����
*/
ISC_API ISC_STATUS ISC_CBC_MAC(int block_algo_id,uint8* key,uint8* in,int inLen,uint8* out, int* outLen);

#else
ISC_RET_LOADLIB_CRYPTO(ISC_CBC_MAC_UNIT*, ISC_New_CBC_MAC_Unit, (void), (), NULL );
ISC_RET_LOADLIB_CRYPTO(void, ISC_Clean_CBC_MAC_Unit, (ISC_CBC_MAC_UNIT *unit), (unit), 0 );
ISC_RET_LOADLIB_CRYPTO(void, ISC_Free_CBC_MAC_Unit, (ISC_CBC_MAC_UNIT *unit), (unit), 0 );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_CBC_MAC, (ISC_CBC_MAC_UNIT *unit, int block_algo_id, const uint8 *key), (unit, block_algo_id, key), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Update_CBC_MAC, (ISC_CBC_MAC_UNIT *unit, const uint8* in, int inLen), (unit, in, inLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Final_CBC_MAC, (ISC_CBC_MAC_UNIT *unit, uint8* out, int* outLen), (unit, out, outLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_CBC_MAC, (int block_algo_id,uint8* key,uint8* in,int inLen,uint8* out, int* outLen), (block_algo_id, key, in, inLen, out, outLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
#endif

#ifdef  __cplusplus
}
#endif

#endif /*HEADER_CBCMAC_H*/
