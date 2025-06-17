/*!
* \file dh.h
* \brief dh �������
* \author
* Copyright (c) 2013 by \<INITech\>
*/

#ifndef HEADER_DH_H
#define HEADER_DH_H

#include "biginteger.h"
#include "foundation.h"

#ifdef ISC_NO_HAS160
#define ISC_NO_DH
#endif

#ifdef ISC_NO_DH
#error ISC_DH is disabled.
#endif

#define ISC_DH_PROVEN_MODE  0    /*!<  0: ����� ���, 1: ������� */

/*ISC_DH Alias				0x70000000 ------------------------------------------------ */
#define ISC_DH				0x70000000   /*!< ISC_DH �˰��� ID */

#define ISC_DH_PRIVATE_LEN		32		/*!< q���� ���� �� ����Ʈ ����Ű ���� */

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* ISC_DH �˰����� ���� ����ü
*/
struct isc_dh_params_st {
	ISC_BIGINT *p;					/*!< �Ҽ� p*/
	ISC_BIGINT *q;					/*!< �Ҽ� q*/
	ISC_BIGINT *g;					/*!< Generator g, ������*/
	ISC_BIGINT* j;					/*!< j �� */
	ISC_BIGINT *small_g;			/*!< G���� ����� ���� ���� g�� */	
	int count;						/*!< Ű ���� �������� count���� */				
	uint8* seed;					/*!< ���� seed ����*/
	int seedLen;					/*!< ���� seed ����*/
	ISC_BIGINT *XKEY;				/*!< ISC_BIGINT XKEY�� ������*/
	ISC_BIGINT *XSEED;				/*!< ISC_BIGINT XSEED�� ������*/
	uint8 *oupri;					/*!< XSEED�� ����� ���� �Է°� (OUPRI) */
	int oupri_len;					/*!< oupri�� ���� */
	ISC_BIGINT_POOL *pool;			/*!< ���� ȿ���� ���� Ǯ */
};
typedef struct isc_dh_params_st ISC_DH_PARAMS_UNIT;

struct isc_dh_st {
	ISC_BIGINT *ra;					/*!< a�� ����Ű. �ڽ��� ���Ű */
	ISC_BIGINT *kta;				/*!< a�� ����Ű. �ڽ��� ����Ű */
	ISC_BIGINT_POOL *pool;			/*!< ���� ȿ���� ���� Ǯ */
	ISC_DH_PARAMS_UNIT *params;		/*!< Ű������ ���Ǵ� �Ķ���� */
};

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_DH_UNIT ����ü�� �޸� �Ҵ�
* \returns
* ISC_DH_UNIT ����ü
*/
ISC_API ISC_DH_UNIT* ISC_New_DH(void);

/*!
* \brief
* ISC_DH_UNIT �޸� ���� �Լ�
* \param unit
* �޸� ������ ISC_DH_UNIT
*/
ISC_API void ISC_Free_DH(ISC_DH_UNIT* unit);

/*!
* \brief
* ISC_DH_UNIT �޸� �ʱ�ȭ �Լ�
* \param unit
* �ʱ�ȭ �� ISC_DH_UNIT
*/
ISC_API void ISC_Clean_DH(ISC_DH_UNIT *unit);

/*!
* \brief
* ISC_DH_PARAMS_UNIT ����ü�� �޸� �Ҵ�
* \returns
* ISC_DH_UNIT ����ü
*/
ISC_API ISC_DH_PARAMS_UNIT* ISC_New_DH_Params(void);

/*!
* \brief
* ISC_DH_PARAMS_UNIT �޸� ���� �Լ�
* \param unit
* �޸� ������ ISC_DH_UNIT
*/
ISC_API void ISC_Free_DH_Params(ISC_DH_PARAMS_UNIT* unit);

/*!
* \brief
* ISC_DH_PARAMS_UNIT �޸� �ʱ�ȭ �Լ�
* \param unit
* �ʱ�ȭ �� ISC_DH_UNIT
*/
ISC_API void ISC_Clean_DH_Params(ISC_DH_PARAMS_UNIT *unit);

/*!
* \brief
* DH ����ü�� �Էµ� �Ķ���ͷ� �ʱ�ȭ �Ѵ�.
* \param dh
* �Էµ� Parameter�� ���õ� ISC_DH_UNIT ����ü
* \param ra
* �ڽ��� ����Ű��
* \param kta
* �ڽ��� ����Ű��
* \param params
* Ű������ �ʿ��� ���� �Ķ���Ͱ�
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# LOCATION^ISC_F_INIT_DH^ISC_ERR_INVALID_INPUT : �߸��� �Է°� �Է�
* -# LOCATION^ISC_F_INIT_DH^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : ����Ű�� ktb�� ���� ���� ����
* -# LOCATION^ISC_F_INIT_DH^ISC_ERR_INVALID_KEY_PAIR : ����Ű�� ktb�� ���� ���� ����
* -# ISC_L_DH^ISC_F_INIT_DH_PARAMS^ISC_ERR_SUB_OPERATION_FAILURE : �Էµ� G�� ���� ����
*/
ISC_API ISC_STATUS ISC_Init_DH(ISC_DH_UNIT *dh,
					  const ISC_BIGINT *ra,
					  const ISC_BIGINT *kta,
					  const ISC_DH_PARAMS_UNIT *params);

/*!
* \brief
* DH Parameter�� �Էµ� �Ķ���ͷ� �ʱ�ȭ �Ѵ�.
* \param params
* Parameter�� �Էµ� ISC_DH_PARAMS_UNIT
* \param p
* �Ҽ� p
* \param q
* �Ҽ� q
* \param g
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_DH^ISC_F_INIT_DH_PARAMS^ISC_ERR_INVALID_INPUT : �߸��� �Է°� �Է�
* -# ISC_L_DH^ISC_F_INIT_DH^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : �Էµ� G�� ���� ����
* -# ISC_L_DH^ISC_F_INIT_DH_PARAMS^ISC_ERR_SUB_OPERATION_FAILURE : �Էµ� G�� ���� ����
*/
ISC_API ISC_STATUS ISC_Set_DH_Params(ISC_DH_PARAMS_UNIT *params,
							 const ISC_BIGINT *p,
							 const ISC_BIGINT *q,
							 const ISC_BIGINT *g);

/*!
* \brief
* ������ �Ҽ� p, q�� ���̿� ����� DH Parameters p, q, g ���� �Լ� (�ؽþ˰��� �Է�)
* \param unit
* ISC_DH_UNIT ����ü ������
* \param digest_alg
* HASH �˰���
* \param p_bits
* ISC_DH �Ҽ� p�� ����
* \param q_bits
* ISC_DH �Ҽ� q�� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_NULL_INPUT: NULL �Է°� �Է�
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_NOT_SUPPORTED: �������� �ʴ� Ű����
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_NOT_PROVEN_ALGORITHM: ����� �˰���
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_MEMORY_ALLOC: ���� �޸� �Ҵ� ����
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_RANDOM_GEN_FAILURE: �������� ����
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_BINARY_TO_BIGINT_FAIL: Binary -> Bigint ��ȯ ����
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_IS_BIGINT_PRIME: ���ѼҼ����� ����
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : MOD EXP MONT BIGINT ���� ����
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ����(BIGINT/PRNG_DH) ���� ����
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_MTP_BIGINT_FAIL : MTP BIGINT ���� ����
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_LEFT_SHIFT_BIGINT_FAIL : LEFT SHIFT BIGINT ���� ����
* -# ISC_L_DH^ISC_F_GENERATE_DH_PARAMS^ISC_ERR_GET_RAND_FAIL : �������� ����
*/
ISC_API ISC_STATUS ISC_Generate_DH_Params(ISC_DH_PARAMS_UNIT *unit, int digest_alg, int p_bits, int q_bits);

/*!
* \brief
* �Է¹��� ISC_DH_UNIT�� P, Q, G ���� �̿��� ���Ű ra, ����Ű kta �����Ѵ�. 
* ����Ű ra�� dh ����ü�� �̹� ������, ����Ű�� �������� �ʰ� �ִ� Ű�� ����Ѵ�.
* ����Ű�� ������ ���� �����Ѵ�.
* \param unit
* ISC_DH_UNIT ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_DH^ISC_F_GENERATE_DH_KEY_PAIR^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_DH^ISC_F_GENERATE_DH_KEY_PAIR^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL ���� ����
* -# ISC_L_DH^ISC_F_GENERATE_DH_KEY_PAIR^ISC_ERR_MEM_ALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_DH^ISC_F_GENERATE_DH_KEY_PAIR^ISC_ERR_GET_RAND_FAIL : �������� ����
* -# ISC_L_DH^ISC_F_GENERATE_DH_KEY_PAIR^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : ����Ű ���� ����
* -# ISC_L_DH^ISC_F_GENERATE_DH_KEY_PAIR^ISC_ERR_INVALID_KEY_PAIR : ������ ����Ű ���� ����
* -# ISC_L_DH^ISC_F_GENERATE_DH_KEY_PAIR^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL ���� ����
* -# ISC_L_DH^ISC_F_GENERATE_DH_KEY_PAIR^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ����(BIGINT) ����
* -# ISC_L_DH^ISC_F_GENERATE_DH_KEY_PAIR^ISC_ERR_KEY_GEN_FAIL : Ű ��ȿ�� �˻� ����
*/
ISC_API ISC_STATUS ISC_Generate_DH_Key_Pair(ISC_DH_UNIT *dh);

/*!
* \brief
* �Է¹��� ISC_DH_UNIT�� �ڽ��� ���Ű ra, ������ ����Ű ktb�� �̿��� ����Ű kab�� �����Ѵ�. kab = ktb^ra mod p
* \param key
* ������ uint8���� ����Ű��
* \param key_len
* ������ uint8���� ����Ű�� ����
* \param dh
* ����Ű�� ����� ���� �Ķ���� ��
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_DH^ISC_F_COMPUTE_KEY^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_DH^ISC_F_COMPUTE_KEY^ISC_ERR_MEM_ALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_DH^ISC_F_COMPUTE_KEY^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : ����Ű ���� ����
*/
ISC_API ISC_STATUS ISC_Compute_Key(ISC_DH_UNIT *dh, ISC_BIGINT *pub_key, uint8 *key, int *key_len);

/*!
* \brief
* ISC_DH_PARAMS_UNIT�� q ���̸� ��ȯ
* \param unit
* ISC_DH_PARAMS_UNIT ����ü ������
* \returns
* -# Modulas ����
* -# ISC_INVALID_SIZE : DH q ���� �������� ����
*/
ISC_API int ISC_Get_DH_PARAMS_Length(ISC_DH_PARAMS_UNIT* unit);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_DH_UNIT*, ISC_New_DH, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_DH, (ISC_DH_UNIT* unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_DH, (ISC_DH_UNIT* unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_DH_UNIT*, ISC_New_DH_Params, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_DH_Params, (ISC_DH_PARAMS_UNIT* unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_DH_Params, (ISC_DH_PARAMS_UNIT* unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_DH, (ISC_DH_UNIT *dh, const ISC_BIGINT *ra, const ISC_BIGINT *kta, const ISC_DH_PARAMS_UNIT *params), (dh, ra, kab), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_DH_Params, (ISC_DH_PARAMS_UNIT *params, const ISC_BIGINT* p, const ISC_BIGINT* q, const ISC_BIGINT* g), (params, p, q, g), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_DH_Params, (ISC_DH_PARAMS_UNIT *unit, int digest_alg, int p_bits, int q_bits), (unit, digest_alg, p_bits, q_bits), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_DH_Key_Pair, (ISC_DH_UNIT* dh), (dh), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Compute_Key, (ISC_DH_UNIT *dh, ISC_BIGINT *pub_key, uint8 *key, int *key_len), (dh, pub_key, key, key_len), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(int, ISC_Get_DH_PARAMS_Length, (ISC_DH_PARAMS_UNIT* unit), (unit), 0 );
#endif

#ifdef  __cplusplus
}
#endif

#endif


