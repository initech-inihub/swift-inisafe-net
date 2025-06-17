/*!
* \file mdc2.h
* \brief ISC_MDC2 �������
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_MDC2_H
#define HEADER_MDC2_H

#include "foundation.h"
#include "mem.h"

#define ISC_MDC2_PROVEN_MODE  1    /*!<  0: ����� ���, 1: ������� */

#ifdef ISC_NO_MDC2
#error ISC_MDC2 is disabled.
#endif

#include "des.h"
#include "utils.h"

/*--------------------------------------------------*/
#define ISC_MDC2_NAME				"MDC2"
#define ISC_MDC2_BLOCK_SIZE			8
#define ISC_MDC2_DIGEST_LENGTH		16
#define ISC_MDC2_INIT				isc_Init_MDC2
#define ISC_MDC2_UPDATE				isc_Update_MDC2
#define ISC_MDC2_FINAL				isc_Final_MDC2
#define ISC_MDC2_STATE_SIZE			sizeof(ISC_MDC2_STATE)
/*--------------------------------------------------*/

#define ISC_CH2LONG(ch, lng) \
	(lng =((uint32)(*((ch)++))), \
	lng |= ((uint32)(*((ch)++))) << 8L, \
	lng |= ((uint32)(*((ch)++))) << 16L, \
	lng |= ((uint32)(*((ch)++))) << 24L)

#define ISC_LONG2CH(lng, ch) \
	(*((ch)++) = (uint8)(((lng)) & 0xff), \
	*((ch)++) = (uint8)(((lng) >> 8L) & 0xff), \
	*((ch)++) = (uint8)(((lng) >> 16L) & 0xff), \
	*((ch)++) = (uint8)(((lng) >> 24L) & 0xff))

#ifdef __cplusplus
extern "C" {
#endif

/*!
* \brief
* ISC_MDC2���� ���̴� ������ ��� �ִ� ����ü
* \remarks
* ISC_DES ��ȣȭ ������ ���̴� key �ΰ� ����
*/
typedef struct isc_mdc2_state_st {
	uint32 index;
	uint8 message[8];
	uint8 mdc2DesKey1[8];
	uint8 mdc2DesKey2[8];
	int paddingType;
} ISC_MDC2_STATE;

/*!
* \brief
* ISC_MDC2 �ʱ�ȭ �Լ�
* \param mdc2
* ISC_MDC2_STATE ����ü�� ������
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_ERR_NOT_PROVEN_ALGORITHM : �������¿��� ����� �˰��� ȣ�� 
* -# LOCATION^ISC_F_INIT_MDC2^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
* -# ISC_Crypto_Initialize()�� �����ڵ�
*/
ISC_INTERNAL ISC_STATUS isc_Init_MDC2(ISC_MDC2_STATE *mdc2);

/*!
* \brief
* ISC_MDC2 ������Ʈ �Լ�
* \param mdc2
* ISC_MDC2_STATE ����ü�� ������
* \param data
* �ؽ��� �� �޽����� ������
* \param count
* �ؽ��� �� �޽����� ����
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^UPDATE_MDC2^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
*/
ISC_INTERNAL ISC_STATUS isc_Update_MDC2(ISC_MDC2_STATE *mdc2, const uint8 *data, uint32 count);

/*!
* \brief
* ISC_MDC2 ���̳� �Լ�
* \param mdc2
* ISC_MDC2_STATE ����ü�� ������
* \param md
* �ؽ��� ����� ������ ������ ������
* \returns
* -# ISC_SUCCESS : Success
* -#  LOCATION^ISC_F_FINAL_MDC2^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
*/
ISC_INTERNAL ISC_STATUS isc_Final_MDC2(ISC_MDC2_STATE *mdc2, uint8 *md);

#ifdef __cplusplus
}
#endif

#endif/* HEADER_MDC2_H */

