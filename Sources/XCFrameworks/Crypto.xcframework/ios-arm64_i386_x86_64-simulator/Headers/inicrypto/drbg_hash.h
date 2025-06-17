/*!
* \file drbg_hash.h
* \brief DRBG; Deterministic Random Bit Generator Algorithm
* \remarks
* NIST SP800-90 ������ �������� �ۼ� �Ǿ���.
* \author myoungjoong kim
* Copyright (c) 2012 by \<INITech\>
*/

#ifndef HEADER_DRBG_HASH_H
#define HEADER_DRBG_HASH_H

#include "foundation.h"

#ifdef  __cplusplus
extern "C" {
#endif /* __cplusplus */

/*!
* \brief
* Hash DRBG �ʱ�ȭ �Լ�
* \param drbg
* ISC_DRBG_UNIT ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INIT_HASHDRBG^ISC_ERR_NOT_PROVEN_ALGORITHM : ��������� �˰����� �ƴ�
* -# LOCATION^ISC_F_INIT_HASHDRBG^ISC_ERR_NOT_SUPPORTED : �Է°��� �������� �ʴ� �Ķ������
* -# LOCATION^ISC_F_DIGEST^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
*/
ISC_INTERNAL ISC_STATUS isc_Init_HashDRBG(ISC_DRBG_UNIT *drbg);

/*!
* \brief
* HASH DRBG �ν��Ͻ� �Լ�
* \param drbg
* ISC_DRBG_UNIT ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_INSTANTIATE_HASHDRBG^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
* -# LOCATION^ISC_F_INSTANTIATE_HASHDRBG^ISC_ERR_INPUT_BUF_TOO_BIG : �Է°��� ���� ũ�⺸�� ŭ
* -# LOCATION^ISC_F_INSTANTIATE_HASHDRBG^ISC_ERR_HASH_DF_FAIL : HASH DF ���� ����
*/
ISC_INTERNAL ISC_STATUS isc_Instantiate_HashDRBG(ISC_DRBG_UNIT *drbg);

/*!
* \brief
* HASH DRBG Reseed �Լ�
* \param drbg
* ISC_DRBG_UNIT ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_RESEED_HASHDRBG^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
* -# LOCATION^ISC_F_RESEED_HASHDRBG^ISC_ERR_INPUT_BUF_TOO_BIG : �Է°��� ���� ũ�⺸�� ŭ
* -# LOCATION^ISC_F_RESEED_HASHDRBG^ISC_ERR_HASH_DF_FAIL : HASH DF ���� ����
*/
ISC_INTERNAL ISC_STATUS isc_Reseed_HashDRBG(ISC_DRBG_UNIT *drbg);

/*!
* \brief
* DRBG ���� �Լ�
* \param drbg
* ISC_DRBG_UNIT ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_NULL_INPUT : �ʱ� �Է°��� NULL��
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_INPUT_BUF_TOO_BIG : �Է°��� ���� ũ�⺸�� ŭ
* -# LOCATION^ISC_F_DIGEST^ISC_ERR_MALLOC : �޸� �Ҵ� ����
* -# LOCATION^ISC_F_GENERATE_HASHDRBG^ISC_ERR_HASH_GEN_FAIL : HASH GEN ���� ����
* -# LOCATION^ISC_F_DIGEST^ISC_ERR_INIT_DIGEST_FAIL : �ؽ� �ʱ�ȭ ����
* -# LOCATION^ISC_F_DIGEST^ISC_ERR_UPDATE_DIGEST_FAIL : �ؽ� ������Ʈ ����
* -# LOCATION^ISC_F_DIGEST^ISC_ERR_FINAL_DIGEST_FAIL : �ؽ� FINAL ����
*/
ISC_INTERNAL ISC_STATUS isc_Generate_HashDRBG(ISC_DRBG_UNIT *drbg);

#ifdef  __cplusplus
}
#endif /* __cplusplus */

#endif /* HEADER_DRBG_HASH_H */
