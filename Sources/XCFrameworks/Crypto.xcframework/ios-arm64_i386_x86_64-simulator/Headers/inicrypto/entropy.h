/*!
* \file sha.h
* \brief entropy ���
* \author
* Copyright (c) 2012 by \<INITech\>
*/

#ifndef HEADER_ENTROPY_H
#define HEADER_ENTROPY_H

#if defined(NO_ENTROPY) || defined(ISC_NO_DRBG)
#error entropy is disabled.
#endif

#define ISC_ENTROPY_PROVEN_MODE  1    /*!<  0: ����� ���, 1: ������� */

#include "foundation.h"
#include "mem.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* ENTROPY���� ���̴� ������ ��� �ִ� ����ü
*/

#define ISC_ENTROPY_ALLOC_SIZE		128
#define ISC_ENTROPY_DEVRANDOM_BYTES 64

#define ISC_MAX_ENTROPY_LENGTH		64
#define ISC_MAX_ENTROPY_SAVE		1024

/*!
* \brief
* ENTROPY ��忡 ���� �����ϴ� ������ �޶�����.
*/
#define ISC_ENTROPY_NULL_MODE		0
#define ISC_ENTROPY_FAST_MODE		1
#define ISC_ENTROPY_NORMAL_MODE		2
#define ISC_ENTROPY_SLOW_MODE		3

#define ISC_ENTORPY_SECURITY_STRENGTHS_112	14
#define ISC_ENTORPY_SECURITY_STRENGTHS_128	16
#define ISC_ENTORPY_SECURITY_STRENGTHS_192	24
#define ISC_ENTORPY_SECURITY_STRENGTHS_256	32

struct isc_entropy_st {
	int status;							/* ����ü ���� ���� */
	int collection_mode;				/* entropy�� �����ϴ� ��� */
	uint8 *entropy;						/* ��ȯ�� entropy ������ */
	uint32 e_len;						/* ��ȯ�� entropy ���� */
	uint32 valid_len;					/* ��ȿ�� entropy ���� */
	uint32 buf_len; 					/* buf ������ ���� */
	uint32 buf_index;					/* �Ҵ�� buf�� ���� */
	uint8 *buf;							/* ������ entropy ������ */
#ifdef ISC_DEBUG_PRINT_ENTROPY
	char name[128];					/* for cmvp ��Ʈ���� �׽�Ʈ */
#endif
};

/*!* \brief
 * �Էµ� ���̸�ŭ �ý����� ��Ʈ���Ǹ� �����Ͽ� �ؽ� �� �������ִ� �Լ�
 * \param *out
 * ������ ���� ���� �����ϱ� ���� �迭�� ������
 * \param out_len
 * �����ϱ� ���ϴ� ���� ���� ����(Byte)
 * \param collection_mode
 * ��Ʈ���� ���� ���(FAST, NORMAL, SLOW)
 * \param alg
 * ��Ʈ���Ǹ� �ؽ��� �˰���
 * \returns
 * -# ISC_SUCCESS : Success
 * -# LOCATION^ISC_F_GET_ENTROPY^ISC_ERR_NULL_INPUT: �ʱⰪ�� NULL�� �Է�
 * -# LOCATION^ISC_F_GET_ENTROPY^ISC_ERR_ENTROPY_FAIL: ��Ʈ���� ���� ����
 * -# LOCATION^ISC_F_GET_ENTROPY^ISC_ERR_COMPARE_FAIL: ��µ� ���� �� ����
 */
ISC_INTERNAL ISC_STATUS isc_Get_ENTROPY(uint8 *out, uint32 out_len, uint32 collection_mode, int alg);

/*!* \brief
 * �Էµ� ������ ���̸�ŭ �ý����� ��Ʈ���Ǹ� �����Ͽ� �ؽ� �� �������ִ� �Լ�
 * \param **entropy_input
 * ������ ��Ʈ���Ǹ� �����ϱ� ���� �������ּ�
 * \param *entropy_input_length
 * ������ ��Ʈ������ ����(Byte)
 * \param security_len
 * ��Ʈ������ ���Ȱ��� ���� (���Ȱ��� ���̿� ���� ��Ʈ���� �����ϴ� ���̰� �޶�����)
 * (ISC_ENTORPY_SECURITY_STRENGTHS_112, ISC_ENTORPY_SECURITY_STRENGTHS_128, ISC_ENTORPY_SECURITY_STRENGTHS_192, ISC_ENTORPY_SECURITY_STRENGTHS_256)
 * \param collection_mode
 * ��Ʈ���� ���� ���(ISC_ENTROPY_FAST_MODE, ISC_ENTROPY_NORMAL_MODE, ISC_ENTROPY_SLOW_MODE)
 * \returns 
 * -# ISC_SUCCESS : Success
 * -# LOCATION^ISC_F_GET_ENTROPY_INPUT^ISC_ERR_INVALID_INPUT : �߸��� �Է°� �Է�
 * -# LOCATION^ISC_F_GET_ENTROPY_INPUT^ISC_ERR_ENTROPY_FAIL : ��Ʈ���� ���� ����
 * -# LOCATION^ISC_F_GET_ENTROPY_AND_NONCE_INPUT^ISC_ERR_COMPARE_FAIL: ��Ʈ���� ���Ӽ� ���� ����
 */
ISC_INTERNAL ISC_STATUS isc_Get_ENTROPY_Input(uint8 **entropy_input, int *entropy_input_length, int security_len, int collection_mode);

/*!* \brief
 * �Էµ� ������ ���̸�ŭ �ý����� ��Ʈ���ǿ� Nonce�� ����� �������ִ� �Լ�
 * \param **entropy_input
 * ������ ��Ʈ���Ǹ� �����ϱ� ���� �������ּ�
 * \param *entropy_input_length
 * ������ ��Ʈ������ ����(Byte)
 * \param **nonce_input
 * ������ Nonce�� �����ϱ� ���� �������ּ�
 * \param *nonce_input_length
 * ������ Nonce�� ����(Byte)
 * \param security_len
 * ��Ʈ������ ���Ȱ��� ���� (���Ȱ��� ���̿� ���� ��Ʈ���� �����ϴ� ���̰� �޶�����)
 * (ISC_ENTORPY_SECURITY_STRENGTHS_112, ISC_ENTORPY_SECURITY_STRENGTHS_128, ISC_ENTORPY_SECURITY_STRENGTHS_192, ISC_ENTORPY_SECURITY_STRENGTHS_256)
 * \param collection_mode
 * ��Ʈ���� ���� ���(ISC_ENTROPY_FAST_MODE, ISC_ENTROPY_NORMAL_MODE, ISC_ENTROPY_SLOW_MODE)
 * \returns 
 * -# ISC_SUCCESS : Success
 * -# LOCATION^ISC_F_GET_ENTROPY_AND_NONCE_INPUT^ ISC_ERR_NULL_INPUT: NULL �Է°� �Է�
 * -# LOCATION^ISC_F_GET_ENTROPY_AND_NONCE_INPUT^ISC_ERR_INVALID_INPUT: �߸��� �Է°� �Է�
 * -# LOCATION^ISC_F_GET_ENTROPY_AND_NONCE_INPUT^ISC_ERR_ENTROPY_FAIL: ��Ʈ���� ���� ����
 * -# LOCATION^ISC_F_GET_ENTROPY_AND_NONCE_INPUT^ISC_ERR_COMPARE_FAIL: ��Ʈ���� ���Ӽ� ���� ����
 * -# LOCATION^ISC_F_CHECK_AND_GET_ENTROPY^ISC_ERR_CONDITION_TEST_FAIL : ���Ǻ� �����߻��� ��Ʈ���� ���� ����
 */
ISC_INTERNAL ISC_STATUS isc_Get_ENTROPY_Input_With_Nonce_Input(uint8 **entropy_input, int *entropy_input_length, uint8 **nonce_input, int *nonce_input_length, int security_len, int collection_mode);

/*!* \brief
 * �ý����� ��Ʈ���Ǹ� �����Ͽ� �������ִ� �Լ� 
 * \param *unit
 * ISC_ENTROPY_UNIT ����ü�� ������
 * \returns
 * -# ISC_SUCCESS : Success
 * -# ISC_FAIL : Fail
 */
ISC_INTERNAL ISC_STATUS isc_Collect_ENTROPY(ISC_ENTROPY_UNIT *unit);

/*!* \brief
 * ������ ��Ʈ���Ǹ� ���ۿ� �����ϴ� �Լ�
 * \param *unit
 * ISC_ENTROPY_UNIT ����ü�� ������
 * \param *buf
 * ���ۿ� ����� ������ ��Ʈ����
 * \param len
 * ������ ��Ʈ���� buf�� ����
 * \param add_len
 * ������ ��Ʈ���� ���� ���� ����
 * \returns
 * -# ISC_SUCCESS : Success
 * -# LOCATION^ISC_F_ADD_ENTROPY^ISC_ERR_INVALID_INPUT: �߸��� �Է°� �Է�
 */
ISC_INTERNAL ISC_STATUS isc_Add_ENTROPY(ISC_ENTROPY_UNIT *unit, const void *buf, uint32 len, uint32 add_len);

ISC_INTERNAL void isc_Set_Print_Entropy(ISC_ENTROPY_UNIT *unit, char *name);

#ifdef ISC_DEBUG_PRINT_ENTROPY
ISC_API ISC_ENTROPY_UNIT *isc_New_ENTROPY_Unit(void);
ISC_API void isc_Clean_ENTROPY_Unit(ISC_ENTROPY_UNIT *unit);
ISC_API void isc_Free_ENTROPY_Unit(ISC_ENTROPY_UNIT *unit);
#else 
/*!
  * \brief
  * ISC_ENTROPY_UNIT ����ü�� �޸� �Ҵ�
  * \returns
  * ISC_ENTROPY_UNIT ����ü
  */
ISC_INTERNAL ISC_ENTROPY_UNIT *isc_New_ENTROPY_Unit(void);

/*!
  * \brief
  * ISC_ENTROPY_UNIT �ʱ�ȭ �Լ�
  * \param unit
  * ISC_ENTROPY_UNIT�� ������
  */
ISC_INTERNAL void isc_Clean_ENTROPY_Unit(ISC_ENTROPY_UNIT *unit);

/*!
  * \brief
  * ISC_ENTROPY_UNIT �޸� ���� �Լ�
  * \param unit
  * �޸� ������ ISC_ENTROPY_UNIT
  * \returns
  * -# ISC_SUCCESS : Success
  * -# others : ���� (�����ڵ�)
  */
ISC_INTERNAL void isc_Free_ENTROPY_Unit(ISC_ENTROPY_UNIT *unit);
#endif

#ifdef  __cplusplus
}
#endif

#endif/* HEADER_ENTROPY_H */


