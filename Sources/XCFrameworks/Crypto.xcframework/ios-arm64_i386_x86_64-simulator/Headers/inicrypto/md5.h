/*!
* \file md5.h
* \brief ISC_MD5 �������
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_MD5_H
#define HEADER_MD5_H

#ifdef ISC_NO_MD5
#error ISC_MD5 is disabled.
#endif

#include "foundation.h"
#include "mem.h"

/*--------------------------------------------------*/
#define ISC_MD5_NAME			"MD5"
#define ISC_MD5_BLOCK_SIZE		64
#define ISC_MD5_DIGEST_LENGTH	16
#define ISC_MD5_INIT			isc_Init_MD5
#define ISC_MD5_UPDATE			isc_Update_MD5
#define ISC_MD5_FINAL			isc_Final_MD5
#define ISC_MD5_STATE_SIZE		sizeof(ISC_MD5_STATE)
/*--------------------------------------------------*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* ISC_MD5���� ���̴� ������ ��� �ִ� ����ü
*/
typedef struct isc_md5_state_st {
	uint8 buff[ISC_MD5_BLOCK_SIZE];
	uint64 len;
	uint32 len2;
	uint32 state[4];
	uint8 dataBuf[ISC_MD5_BLOCK_SIZE];
	uint8 dataBufLen;
} ISC_MD5_STATE;

/*!
* \brief
* ISC_MD5 �ʱ�ȭ �Լ�
* \param state
* ISC_MD5_STATE ����ü�� ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_MD5^ISC_ERR_NULL_INPUT : �ʱⰪ�� NULL�� �Է�
* -# ISC_Crypto_Initialize()�� �����ڵ�
*/
ISC_INTERNAL ISC_STATUS isc_Init_MD5(ISC_MD5_STATE *md5);

/*!
* \brief
* ISC_MD5 ������Ʈ �Լ�
* \param state
* ISC_MD5_STATE ����ü�� ������
* \param data
* �ؽ��� �� �޽����� ������
* \param count
* �ؽ��� �� �޽����� ����
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_UPDATE_MD5^ISC_ERR_NULL_INPUT  : �ʱⰪ�� NULL�� �Է�
* -# LOCATION^ISC_F_UPDATE_MD5^ISC_ERR_SUB_OPERATION_FAILURE : compare ����
*/
ISC_INTERNAL ISC_STATUS isc_Update_MD5(ISC_MD5_STATE *md5, const uint8 *data, uint32 count);

/*!
* \brief
* ISC_MD5 ���̳� �Լ�
* \param state
* ISC_MD5_STATE ����ü�� ������
* \param out
* �ؽ��� ����� ������ ������ ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_FINAL_MD5^ISC_ERR_SUB_OPERATION_FAILURE : compare ����
*/
ISC_INTERNAL ISC_STATUS isc_Final_MD5(ISC_MD5_STATE *md5, uint8 *out);

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_MD5_H */


