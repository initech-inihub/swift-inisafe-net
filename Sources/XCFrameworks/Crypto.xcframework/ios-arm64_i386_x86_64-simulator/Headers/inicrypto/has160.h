/*!
* \file has160.h
* \brief ISC_HAS160 �������
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_HAS160_H
#define HEADER_HAS160_H

#ifdef ISC_NO_HAS160
#error ISC_HAS160 is disabled.
#endif

#include "foundation.h"
#include "mem.h"

/*--------------------------------------------------*/
#define ISC_HAS160_NAME				"HAS160"
#define ISC_HAS160_BLOCK_SIZE		64
#define ISC_HAS160_DIGEST_LENGTH	20
#define ISC_HAS160_INIT				isc_Init_HAS160
#define ISC_HAS160_UPDATE			isc_Update_HAS160
#define ISC_HAS160_FINAL			isc_Final_HAS160
#define ISC_HAS160_STATE_SIZE		sizeof(ISC_HAS160_STATE)
/*--------------------------------------------------*/

#define ISC_HAS160_DWORD unsigned int
#define ISC_HAS160_BYTE unsigned char

#define ISC_HAS160_PROVEN_MODE    1    /*!<  0: ����� ���, 1: ������� */

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* ISC_HAS160���� ���̴� ������ ��� �ִ� ����ü
*/
typedef struct isc_has160_state_st{
	uint32 state[5];
	uint32 length[2];
	uint8 data[64];
} ISC_HAS160_STATE;

/*!
* \brief
* ISC_HAS160 �ʱ�ȭ �Լ�
* \param has160
* ISC_HAS160_STATE ����ü�� ������
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_HAS160^ISC_F_INIT_HAS160^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� ���
* -# ISC_Crypto_Initialize()�� �����ڵ�
*/
ISC_INTERNAL ISC_STATUS isc_Init_HAS160(ISC_HAS160_STATE *has160);

/*!
* \brief
* ISC_HAS160 ������Ʈ �Լ�
* \param has160
* ISC_HAS160_STATE ����ü�� ������
* \param data
* �ؽ��� �� �޽����� ������
* \param count
* �ؽ��� �� �޽����� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_HAS160^ISC_F_UPDATE_HAS160^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� ���
*/
ISC_INTERNAL ISC_STATUS isc_Update_HAS160(ISC_HAS160_STATE *has160, const uint8 *data, uint32 count);

/*!
* \brief
* ISC_HAS160 ���̳� �Լ�
* \param has160
* ISC_HAS160_STATE ����ü�� ������
* \param out
* �ؽ� ����� ������ ������ ������
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_HAS160^ISC_F_FINAL_HAS160^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� ���
*/
ISC_INTERNAL ISC_STATUS isc_Final_HAS160(ISC_HAS160_STATE *has160, uint8* out);

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_HAS160_H */


