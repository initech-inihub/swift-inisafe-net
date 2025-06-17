/*!
* \file kcdsa.h
* \brief kcdsa �������
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_KCDSA_H
#define HEADER_KCDSA_H


#include "biginteger.h"
#include "foundation.h"


#ifdef ISC_NO_HAS160
#define ISC_NO_KCDSA
#endif

#ifdef ISC_NO_KCDSA
#error ISC_KCDSA is disabled.
#endif

#define ISC_KCDSA_SIGN				1			/*!< ISC_KCDSA_SIGN*/
#define ISC_KCDSA_VERIFY			0			/*!< ISC_KCDSA_VERIFY*/

/*ISC_KCDSA Alias				0x40000000 ------------------------------------------------ */
#define ISC_KCDSA				0x40000000   /*!< ISC_KCDSA �˰��� ID */

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* ISC_KCDSA �˰����� ���� ����ü
*/
struct isc_kcdsa_st	{
	ISC_DIGEST_UNIT *d_unit;			/*!< ISC_DIGEST_UNIT*/
	ISC_PRNG_UNIT *prng;				/*!< ISC_PRNG_UNIT*/
	ISC_BIGINT *p;						/*!< �Ҽ� p*/
	ISC_BIGINT *q;						/*!< �Ҽ� q*/
	ISC_BIGINT *g;						/*!< Generator g*/
	ISC_BIGINT* x;						/*!< ���Ű x */
	ISC_BIGINT* y;						/*!< ���� �Ķ���� y = g^x*/
	ISC_BIGINT* z;						/*!< ISC_KCDSA z �� */
	ISC_BIGINT* j;						/*!< ISC_KCDSA j �� */
	int count;						/*!< Ű ���� �������� count���� */				
	uint8* seed;					/*!< ���� seed ����*/
	int seedLen;					/*!< ���� seed ����*/
	int is_private;					/*!< Public : 0 , Private : 1*/
	ISC_BIGINT_POOL *pool;				/*!< ���� ȿ���� ���� Ǯ */
	ISC_BIGINT *XKEY;					/*!< ISC_BIGINT XKEY�� ������*/
	ISC_BIGINT *XSEED;					/*!< ISC_BIGINT XSEED�� ������*/
	uint8 *oupri;					/*!< XSEED�� ����� ���� �Է°� (OUPRI) */
	int oupri_len;					/*!< oupri�� ���� */
	ISC_BIGINT *small_g;				/* G���� ����� ���� ���� g�� */	
};

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* KCDSA_UNIT ����ü�� �޸� �Ҵ�
* \returns
* ISC_KCDSA_UNIT ����ü
*/
ISC_API ISC_KCDSA_UNIT* ISC_New_KCDSA(void);
/*!
* \brief
* KCDSA_UNIT �޸� ���� �Լ�
* \param unit
* �޸� ������ ISC_KCDSA_UNIT
*/
ISC_API void ISC_Free_KCDSA(ISC_KCDSA_UNIT* unit);
/*!
* \brief
* ISC_KCDSA_UNIT �޸� �ʱ�ȭ �Լ�
* \param unit
* �ʱ�ȭ �� ISC_KCDSA_UNIT
*/
ISC_API void ISC_Clean_KCDSA(ISC_KCDSA_UNIT *unit);

/*!
* \brief
* KCDSA Parameter �Է�
* \param kcdsa
* Parameter�� �Էµ� ISC_KCDSA_UNIT
* \param p
* �Ҽ� p
* \param q
* �Ҽ� q
* \param g
* Generator g
* \param x
* ��а� x
* \param y
* ������ y=g^x
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_KCDSA^ISC_F_SET_KCDSA_PARAMS^ISC_ERR_INVALID_INPUT : �߸��� �Է°� �Է�
* -# ISC_L_KCDSA^ISC_F_SET_KCDSA_PARAMS^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ����(BIGINT) ����
* -# ISC_Mod_Exp_Mont_BIGINT() �ַ��ڵ�
*/
ISC_API ISC_STATUS ISC_Set_KCDSA_Params(ISC_KCDSA_UNIT *kcdsa,
					 const ISC_BIGINT* p,
					 const ISC_BIGINT* q,
					 const ISC_BIGINT* g,
					 const ISC_BIGINT* x,
					 const ISC_BIGINT* y);

/*!
* \brief
* KCDSA ���ڼ��� �˰��� �ʱ�ȭ (�ؽ� �˰��� �Է�)
* \param kcdsa
* �ʱ�ȭ �� ISC_KCDSA_UNIT
* \param sign
* (ISC_KCDSA_SIGN)1 : ����, (ISC_KCDSA_VERIFY)0 : ����
* \param digest_alg
* HASH �˰���
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_KCDSA^ISC_F_INIT_KCDSA_EX^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_KCDSA^ISC_F_INIT_KCDSA_EX^ISC_ERR_NOT_SUPPORTED : �������� �ʴ� Ű ���� �Է�
* -# ISC_L_KCDSA^ISC_F_INIT_KCDSA_EX^ISC_ERR_NOT_PROVEN_ALGORITHM : ��������϶� ����� �˰��� ���
* -# ISC_L_KCDSA^ISC_F_INIT_KCDSA_EX^ISC_ERR_MEM_ALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_KCDSA^ISC_F_INIT_KCDSA_EX^ISC_ERR_INIT_DIGEST_FAIL : ISC_Init_DIGEST() ���� ����
*/
ISC_API ISC_STATUS ISC_Init_KCDSA_Ex(ISC_KCDSA_UNIT *kcdsa, int sign, int digest_alg);

/*!
* \brief
* KCDSA ���ڼ��� �˰��� �ʱ�ȭ
* \param kcdsa
* �ʱ�ȭ �� ISC_KCDSA_UNIT
* \param sign
* (ISC_KCDSA_SIGN)1 : ����, (ISC_KCDSA_VERIFY)0 : ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_KCDSA^ISC_F_INIT_KCDSA^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_KCDSA^ISC_F_INIT_KCDSA^ISC_ERR_MEM_ALLOC : ���� �޸� �״� ���� 
* -# ISC_L_KCDSA^ISC_F_INIT_KCDSA^ISC_ERR_INIT_DIGEST_FAIL : ISC_Init_DIGEST() ���� ����
*/
ISC_API ISC_STATUS ISC_Init_KCDSA(ISC_KCDSA_UNIT *kcdsa, int sign);

/*!
* \brief
* ISC_KCDSA ���ڼ��� �޽��� �Է�(Update) �Լ�
* \param kcdsa
* ISC_KCDSA_UNIT ����ü ������
* \param data
* �Էµ� ������(������ �Է� ����)
* \param dataLen
* �������� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_KCDSA^ISC_F_UPDATE_KCDSA^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_KCDSA^ISC_F_UPDATE_KCDSA^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ����(z_KCDSA) ����
* -# ISC_L_KCDSA^ISC_F_UPDATE_KCDSA^ISC_ERR_MALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_KCDSA^ISC_F_UPDATE_KCDSA^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� BIGINT ���� ����
* -# ISC_L_KCDSA^ISC_F_UPDATE_KCDSA^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST ���� ����
*/
ISC_API ISC_STATUS ISC_Update_KCDSA(ISC_KCDSA_UNIT *kcdsa, const uint8 *data, uint32 dataLen);

/*!
* \brief
* KCDSA ���ڼ����� ���� ���� / ���� �Լ�
* \param kcdsa
* ISC_KCDSA_UNIT ����ü ������
* \param r
* ���� r
* \param rLen
* ���� r�� ����
* \param s
* ���� s
* \param sLen
* ���� s�� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_KCDSA^ISC_F_FINAL_KCDSA^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_KCDSA^ISC_F_FINAL_KCDSA^ISC_ERR_NOT_SUPPORTED : �������� �ʴ� Ű ���� �Է�
* -# ISC_Sign_KCDSA()�� �����ڵ�
* -# ISC_Verify_KCDSA()�� �����ڵ�
*/
ISC_API ISC_STATUS ISC_Final_KCDSA(ISC_KCDSA_UNIT *kcdsa, uint8 *r, int *rLen,  uint8 *s, int *sLen);

/*!
* \brief
* ISC_KCDSA ���ڼ����� ���� ����
* \param kcdsa
* ISC_KCDSA_UNIT ����ü ������
* \param r
* ���� r
* \param rLen
* ���� r�� ����
* \param s
* ���� s
* \param sLen
* ���� s�� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_FINAL_DIGEST_FAIL : FINAL DIGEST ���� ����
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_GET_BIGINT_POOL_FAIL : BIGINT POOL ���� ����
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_GET_RAND_FAIL : ���� ���� ����
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : MOD EXP MONT BIGINT ���� ����
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_INIT_DIGEST_FAIL : INIT DIGEST ���� ����
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST ���� ����
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY TO BIGINT ���� ����
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� BIGINT ���� ����
* -# ISC_L_KCDSA^ISC_F_SIGN_KCDSA^ISC_ERR_SUB_BIGINT_FAIL : SUB BIGINT ���� ����
*/
ISC_API ISC_STATUS ISC_Sign_KCDSA(ISC_KCDSA_UNIT *kcdsa, uint8 *r, int *rLen, uint8 *s, int *sLen);

/*!
* \brief
* KCDSA ���ڼ����� ���� ����
* \param kcdsa
* ISC_KCDSA_UNIT ����ü ������
* \param r
* ���� r
* \param rLen
* ���� r�� ����
* \param s
* ���� s
* \param sLen
* ���� s�� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_NULL_INPUT: NULL �Է°� �Է�
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_FINAL_DIGEST_FAIL : FINAL DIGEST ����
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ����(BIGINT) ����
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL ���� ����
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY TO BIGINT ���� ����
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_IS_BIGINT_ZERO_FAIL : BIGINT�� ����� ZERO
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_CMP_BIGINT_FAIL : Cmp BIGINT ����  ����
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : Mod Exp MONT BIGINT ���� ����
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_INIT_DIGEST_FAIL : INIT DIGEST ���� ����
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST ���� ����
* -# ISC_L_KCDSA^ISC_F_VERIFY_KCDSA^ISC_ERR_VERIFY_FAILURE : ������� ����
*/
ISC_API ISC_STATUS ISC_Verify_KCDSA(ISC_KCDSA_UNIT *kcdsa, uint8 *r, int *rLen, uint8 *s, int *sLen);

/*!
* \brief
* ������ �Ҽ� p, q�� ���̿� ����� KCDSA Parameters p, q, g ���� �Լ� (�ؽþ˰��� �Է�)
* \param kcdsa
* ISC_KCDSA_UNIT ����ü ������
* \param digest_alg
* HASH �˰���
* \param p_bits
* ISC_KCDSA �Ҽ� p�� ����
* \param q_bits
* ISC_KCDSA �Ҽ� q�� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_NULL_INPUT: NULL �Է°� �Է�
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_NOT_SUPPORTED: �������� �ʴ� Ű����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_NOT_PROVEN_ALGORITHM: ����� �˰���
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_MEMORY_ALLOC: ���� �޸� �Ҵ� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_RANDOM_GEN_FAILURE: �������� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_BINARY_TO_BIGINT_FAIL: Binary -> Bigint ��ȯ ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_IS_BIGINT_PRIME: ���ѼҼ����� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : MOD EXP MONT BIGINT ���� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ����(BIGINT/PRNG_KCDSA) ���� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_MTP_BIGINT_FAIL : MTP BIGINT ���� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_LEFT_SHIFT_BIGINT_FAIL : LEFT SHIFT BIGINT ���� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS_EX^ISC_ERR_GET_RAND_FAIL : �������� ����
*/
ISC_API ISC_STATUS ISC_Generate_KCDSA_Params_Ex(ISC_KCDSA_UNIT *kcdsa, int digest_alg, int p_bits, int q_bits);

/*!
* \brief
* ������ �Ҽ� p, q�� ���̿� ����� IKCDSA Parameters p, q, g ���� �Լ�
* \param kcdsa
* ISC_KCDSA_UNIT ����ü ������
* \param p_bits
* ISC_KCDSA �Ҽ� p�� ����
* \param q_bits
* ISC_KCDSA �Ҽ� q�� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_NOT_SUPPORTED : �������� �ʴ� Ű����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_MEMORY_ALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_INIT_PRNG_FAIL : INIT PRNG ���� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_GET_RAND_FAIL : �������� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_BINARY_TO_BIGINT_FAIL : Binary -> Bigint ��ȯ ���� 
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_IS_BIGINT_PRIME : ���ѼҼ����� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ����(BIGINT/PRNG_KCDSA) ���� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_MTP_BIGINT_FAIL : MTP BIGINT ���� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_LEFT_SHIFT_BIGINT_FAIL : LEFT SHIFT BIGINT ���� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_PARAMS^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : MOD EXP MONT BIGINT ���� ����
*/
ISC_API ISC_STATUS ISC_Generate_KCDSA_Params(ISC_KCDSA_UNIT *kcdsa, int p_bits, int q_bits);

/*!
* \brief
* �Է¹��� ISC_KCDSA_UNIT�� P, Q, G ���� �̿��� ���Ű X, ����Ű Y ���� (�ؽ� �˰��� �Է� ����)
* \param unit
* ISC_KCDSA_UNIT ����ü ������
* \param digest_alg
* HASH �˰���
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR_EX^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR_EX^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL ���� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR_EX^ISC_ERR_MEM_ALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR_EX^ISC_ERR_GET_RAND_FAIL : �������� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR_EX^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL ���� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR_EX^ISC_ERR_MOD_INVERSE_BIGINT_FAIL : MOD INVERSE BIGINT ���� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR_EX^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ����(BIGINT) ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR_EX^ISC_ERR_KEY_GEN_FAIL : Ű ��ȿ�� �˻� ����
*/
ISC_API ISC_STATUS ISC_Generate_KCDSA_Key_Pair_Ex(ISC_KCDSA_UNIT* unit, int digest_alg);

/*!
* \brief
* �Է¹��� ISC_KCDSA_UNIT�� ����� p, q, g ���� ���� ��а� x�� ������ y ����
* \param unit
* ISC_KCDSA_UNIT ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR^ISC_ERR_MEM_ALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR^ISC_ERR_INIT_PRNG_FAIL : INIT PRNG ���� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR^ISC_ERR_GET_RAND_FAIL : �������� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BITINT POOL ���� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR^ISC_ERR_MOD_INVERSE_BIGINT_FAIL : MOD INVERSE BIGINT ���� ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ����(BIGINT) ����
* -# ISC_L_KCDSA^ISC_F_GENERATE_KCDSA_KEY_PAIR^ISC_ERR_KEY_GEN_FAIL : Ű ��ȿ�� �˻� ����
*/
ISC_API ISC_STATUS ISC_Generate_KCDSA_Key_Pair(ISC_KCDSA_UNIT* unit);

/*!
* \brief
* ISC_KCDSA�� q ���̸� ��ȯ
* \param kcdsa
* ISC_KCDSA_UNIT ����ü ������
* \returns
* -# Modulas ����
* -# ISC_INVALID_SIZE : KCDSA q ���� �������� ����
*/
ISC_API int ISC_Get_KCDSA_Length(ISC_KCDSA_UNIT* kcdsa);


/*!
* \brief
* TIAS.KO-12.001/R1�� ������ PRNG�� ���ϴ� �Լ�. x(0<x<q)�� ISC_BIGINT �������� ����Ѵ�.
* \param unit
* ISC_KCDSA_UNIT ����ü�� ������
* \param hash_id
* TIAS.KO-12.001/R1�� ������ PRNG�� ���ϱ� ���� �ؽ� �˰���
* \param output
* ���� ���� �����ϱ� ���� ISC_BIGINT�� ������
* \param q
* ���� ���� ������ �����ϴ� prime(mod q ������ ���� ���� ���� ���� ����) q�� ������
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_PRNG^ISC_F_GET_RAND^ISC_ERR_RANDOM_GEN_FAILURE : Fail
* -# ISC_L_PRNG^ISC_F_GET_RAND^ISC_ERR_NULL_XKEY_VALUE : XKEY�� NULL�� ���
*/
ISC_INTERNAL ISC_STATUS isc_Get_Rand_KCDSA_BIGINT(ISC_KCDSA_UNIT *unit, int hash_id, ISC_BIGINT *output, ISC_BIGINT *q);

ISC_INTERNAL ISC_STATUS isc_KCDSA_Mod_Hash(uint8 *ret, int *ret_len, ISC_KCDSA_UNIT *kcdsa, uint8 *hashed_value, int hashed_value_len);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_KCDSA_UNIT*, ISC_New_KCDSA, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_KCDSA, (ISC_KCDSA_UNIT* unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_KCDSA, (ISC_KCDSA_UNIT* unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_KCDSA_Params, (ISC_KCDSA_UNIT *kcdsa, const ISC_BIGINT* p, const ISC_BIGINT* q, const ISC_BIGINT* g, const ISC_BIGINT* x, const ISC_BIGINT* y), (kcdsa, p, q, g, x, y), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_KCDSA, (ISC_KCDSA_UNIT *kcdsa, int sign), (kcdsa, sign), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Update_KCDSA, (ISC_KCDSA_UNIT *kcdsa, const uint8 *data, uint32 dataLen), (kcdsa, data, dataLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Final_KCDSA, (ISC_KCDSA_UNIT *kcdsa, uint8 *r, int *rLen,  uint8 *s, int *sLen), (kcdsa, r, rLen, s, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Sign_KCDSA, (ISC_KCDSA_UNIT *kcdsa, uint8 *r, int *rLen, uint8 *s, int *sLen), (kcdsa, r, rLen, s, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Verify_KCDSA, (ISC_KCDSA_UNIT *kcdsa, uint8 *r, int *rLen, uint8 *s, int *sLen), (kcdsa, r, rLen, s, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_KCDSA_Params, (ISC_KCDSA_UNIT *kcdsa, int p_bits, int q_bits), (kcdsa, p_bits, q_bits), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_KCDSA_Key_Pair, (ISC_KCDSA_UNIT* unit), (unit), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(int, ISC_Get_KCDSA_Length, (ISC_KCDSA_UNIT* kcdsa), (kcdsa), 0 );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_KCDSA_Ex, (ISC_KCDSA_UNIT *kcdsa, int sign, int digest_alg), (kcdsa, sign, digest_alg), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_KCDSA_Params_Ex, (ISC_KCDSA_UNIT *kcdsa, int digest_alg, int p_bits, int q_bits), (kcdsa, digest_alg, p_bits, q_bits), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_KCDSA_Key_Pair_Ex, (ISC_KCDSA_UNIT* unit, int digest_alg), (unit,digest_alg), ISC_ERR_GET_ADRESS_LOADLIBRARY );
#endif

#ifdef  __cplusplus
}
#endif

#endif


