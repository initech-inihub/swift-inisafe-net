/*!
* \file dsa.h
* \brief dsa �������
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_DSA_H
#define HEADER_DSA_H


#if defined(ISC_NO_SHA) || defined (ISC_NO_SHA1)
#define ISC_NO_DSA
#error ISC_DSA is disabled.
#endif

#ifdef ISC_NO_DSA
#error ISC_DSA is disabled.
#endif

#include "biginteger.h"
#include "digest.h"
#include "foundation.h"

#define ISC_DSA_PROVEN_MODE  1    /*!<  0: ����� ���, 1: ������� */

#define ISC_DSA_SIGN			1		/*!< ISC_DSA_SIGN*/
#define ISC_DSA_VERIFY			0		/*!< ISC_DSA_VERIFY*/

/*ISC_DSA Alias				0x30000000 ------------------------------------------------ */
#define ISC_DSA				0x30000000   /*!< ISC_DSA �˰��� ID */

/*!
* \brief
* ISC_DSA �˰����� ���� ����ü
*/
struct isc_dsa_st
{
	ISC_DIGEST_UNIT *d_unit;		/*!< ISC_DIGEST_UNIT*/
	ISC_PRNG_UNIT *prng;			/*!< ISC_PRNG_UNIT*/
	uint8* seed;				/*!< ���� seed ����*/
	int seedLen;				/*!< ���� seed ����*/
	ISC_BIGINT *p;					/*!< �Ҽ� p*/
	ISC_BIGINT *q;					/*!< �Ҽ� q*/
	ISC_BIGINT *g;					/*!< Generator g*/
	ISC_BIGINT *y;					/*!< ���� �Ķ���� y = g^x*/
	ISC_BIGINT *x; /* private */	/*!< ���Ű x */
	ISC_BIGINT_POOL *pool;			/*!< ���� ȿ���� ���� Ǯ */
	int is_private;				/*!<Public : 0 , Private : 1*/
};	

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* DSA Parameter �Է�
* \param dsa
* Parameter�� �Էµ� ISC_DSA_UNIT
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
* -# ISC_L_DSA^ISC_F_SET_DSA_PARAMS^ISC_ERR_INVALID_INPUT : �߸��� �Է°� �Է�
*/
ISC_API ISC_STATUS ISC_Set_DSA_Params(ISC_DSA_UNIT *dsa,
				   const ISC_BIGINT* p,
				   const ISC_BIGINT* q,
				   const ISC_BIGINT* g,
				   const ISC_BIGINT* x,
				   const ISC_BIGINT* y);

/*!
* \brief
* ISC_DSA_UNIT ����ü�� �޸� �Ҵ�
* \returns
* ISC_DSA_UNIT ����ü
*/
ISC_API ISC_DSA_UNIT *ISC_New_DSA(void);

/*!
* \brief
* ISC_DSA_UNIT �޸� ���� �Լ�
* \param unit
* �޸� ������ ISC_DSA_UNIT
*/
ISC_API void ISC_Free_DSA(ISC_DSA_UNIT *unit);

/*!
* \brief
* ISC_DSA_UNIT �޸� �ʱ�ȭ �Լ�
* \param unit
* �ʱ�ȭ �� ISC_DSA_UNIT
*/
ISC_API void ISC_Clean_DSA (ISC_DSA_UNIT *unit);

/*!
* \brief
* DSA ���ڼ��� �˰��� �ʱ�ȭ
* \param dsa
* �ʱ�ȭ �� ISC_DSA_UNIT
* \param sign
* (ISC_DSA_SIGN)1 : ����, (ISC_DSA_VERIFY)0 : ����
* \param user_seed
* ������ �����ϴ� ���� seed��
* \param user_seedLen
* ������ �����ϴ� ���� seed���� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_DSA^ISC_F_INIT_DSA^ISC_ERR_NOT_PROVEN_ALGORITHM : ������忡 ����� �˰��� ���
* -# ISC_L_DSA^ISC_F_INIT_DSA^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_DSA^ISC_F_INIT_DSA^ISC_ERR_MEM_ALLOC : ���� �޸� �Ҵ�
* -# ISC_L_DSA^ISC_F_INIT_DSA^ISC_ERR_INIT_DIGEST_FAIL : INIT DIGEST ���� ����
*/
ISC_API ISC_STATUS ISC_Init_DSA(ISC_DSA_UNIT *dsa, int digest_alg, int sign, uint8* user_seed, int user_seedLen);

/*!
* \brief
* ISC_DSA ���ڼ��� �޽��� �Է�(Update) �Լ�
* \param dsa
* ISC_DSA_UNIT ����ü ������
* \param data
* �Էµ� ������(������ �Է� ����)
* \param dataLen
* �������� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_DSA^ISC_F_UPDATE_DSA^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_DSA^ISC_F_UPDATE_DSA^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST ���� ����
*/
ISC_API ISC_STATUS ISC_Update_DSA(ISC_DSA_UNIT *dsa, const uint8 *data, int dataLen);

/*!
* \brief
* DSA ���ڼ����� ���� ���� / ���� �Լ�
* \param dsa
* ISC_DSA_UNIT ����ü ������
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
* -# ISC_L_DSA^ISC_F_FINAL_DSA^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_DSA^ISC_F_FINAL_DSA^ISC_ERR_NO_PRIVATE_VALUE : ����� ����Ű �������� ����
* -# ISC_L_DSA^ISC_F_FINAL_DSA^ISC_ERR_SIGN_DSA_FAIL : ���� ����
* -# ISC_L_DSA^ISC_F_FINAL_DSA^ISC_ERR_VERIFY_DSA_FAIL : ���� ����
*/
ISC_API ISC_STATUS ISC_Final_DSA(ISC_DSA_UNIT *dsa, uint8 *r, int *rLen,  uint8 *s, int *sLen);

/*!
* \brief
* ISC_DSA ���ڼ����� ���� ����
* \param dsa
* ISC_DSA_UNIT ����ü ������
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
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_INIT_PRNG_FAIL : INIT PRNG ���� ����
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL ���� ����
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_NULL_INPUT : : NULL �Է°� �Է�
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_FINAL_DIGEST_FAIL : FINAL DIGEST ���� ����
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL ���� ����
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL ���� ����
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_GET_RAND_DSA_BIGINT_FAIL : �������� ����
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : MOD EXP MONT BIGINT ���� ����
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_MOD_BIGINT_FAIL : MOD BIGINT ���� ����
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_MOD_INVERSE_BIGINT_FAIL : MOD INVERSE BIGINT ���� ����
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY -> BIGINT ��ȯ ����
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_MOD_MTP_BIGINT_FAIL : MOD MTP BIGINT ���� ����
* -# ISC_L_DSA^ISC_F_SIGN_DSA^ISC_ERR_ADD_BIGINT_FAIL : ADD BIGINT ���� ����
*/
ISC_API ISC_STATUS ISC_Sign_DSA(ISC_DSA_UNIT *dsa, uint8 *r, int *rLen, uint8 *s, int *sLen);

/*!
* \brief
* ISC_DSA ���ڼ����� ���� ����
* \param dsa
* ISC_DSA_UNIT ����ü ������
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
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL ���� ����
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_FINAL_DIGEST_FAIL : FINAL DIGEST ���� ����
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY -> BIGINT ��ȯ ����
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_MOD_INVERSE_BIGINT_FAIL : MOD INVERSE BIGINT ���� ����
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_MALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_MOD_MTP_BIGINT_FAIL : MOD MTP BIGINT ���� ����
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL ���� ����
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : MOD EXP MONT BIGINT ���� ����
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_MOD_BIGINT_FAIL : MOD BIGINT ���� ����
* -# ISC_L_DSA^ISC_F_VERIFY_DSA^ISC_ERR_VERIFY_DSA_FAIL : ���� ����
*/
ISC_API ISC_STATUS ISC_Verify_DSA(ISC_DSA_UNIT *dsa, uint8 *r,  int rLen, uint8 *s, int sLen);

/*!
* \brief
* ������ �Ҽ� p�� ���̿� ����� ISC_DSA Parameters p, q, g ���� �Լ�
* \param dsa
* ISC_DSA_UNIT ����ü ������
* \param p_bits
* ISC_DSA �Ҽ� p�� ����
* \param user_seed
* ����� ���� ���� seed��(20 bytes), NULL�� �˰��� ������ seed�� ���Ƿ� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ���� ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL ���� ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL ���� ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_MALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_LEFT_SHIFT_BIGINT_FAIL : LEFT SHIFT BIGINT ���� ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_INIT_PRNG_FAIL : INIT PRNG ���� ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_INIT_DIGEST_FAIL : INIT DIGEST ���� ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_GET_RAND_FAIL : �������� ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST ���� ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_FINAL_DIGEST_FAIL : FINAL DIGEST ���� ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY -> BIGINT ��ȯ ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_ADD_BIGINT_FAIL : ADD BIGINT ���� ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_COPY_BIGINT_FAIL : COPY BIGINT ���� ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_MOD_BIGINT_FAIL : MOD BIGINT ���� ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_SUB_BIGINT_FAIL : SUB BIGINT ���� ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_DIV_BIGINT_FAIL : DIV BIGINT ���� ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_SET_BIGINT_FAIL : SET BIGINT ���� ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_PARAMS^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : MOD EXP MONT BIGINT ���� ����
*/
ISC_API ISC_STATUS ISC_Generate_DSA_Params(ISC_DSA_UNIT *dsa, int digest_alg, int p_bits, uint8* user_seed);

/*!
* \brief
* �Է¹��� ISC_DSA_UNIT�� ����� p, q, g ���� ���� ��а� x�� ������ y ����
* \param dsa
* ISC_DSA_UNIT ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_KEY_PAIR^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_KEY_PAIR^ISC_ERR_MEMORY_ALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_KEY_PAIR^ISC_ERR_INIT_PRNG_FAIL : INIT PRNG ���� ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_KEY_PAIR^ISC_ERR_GET_RAND_DSA_BIGINT_FAIL : �������� ����
* -# ISC_L_DSA^ISC_F_GENERATE_DSA_KEY^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : MOD EXP MONT BIGINT ���� ����
*/
ISC_API ISC_STATUS ISC_Generate_DSA_Key_Pair(ISC_DSA_UNIT *dsa);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_DSA_Params, (ISC_DSA_UNIT *dsa, const ISC_BIGINT* p, const ISC_BIGINT* q, const ISC_BIGINT* g, const ISC_BIGINT* x, const ISC_BIGINT* y), (dsa, p, q, g, x, y), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_DSA_UNIT*, ISC_New_DSA, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_DSA, (ISC_DSA_UNIT *unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_DSA, (ISC_DSA_UNIT *unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_DSA, (ISC_DSA_UNIT *dsa, int digest_alg, int sign, uint8* user_seed, int user_seedLen), (dsa, digest_alg, sign, user_seed, user_seedLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Update_DSA, (ISC_DSA_UNIT *dsa, const uint8 *data, int dataLen), (dsa, data, dataLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Final_DSA, (ISC_DSA_UNIT *dsa, uint8 *r, int *rLen,  uint8 *s, int *sLen), (dsa, r, rLen,  s, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Sign_DSA, (ISC_DSA_UNIT *dsa, uint8 *r, int *rLen, uint8 *s, int *sLen), (dsa, r, rLen, s, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Verify_DSA, (ISC_DSA_UNIT *dsa, uint8 *r,  int rLen, uint8 *s, int sLen), (dsa, r, rLen, s, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_DSA_Params, (ISC_DSA_UNIT *dsa, int digest_alg, int p_bits, uint8* user_seed), (dsa, digest_alg, p_bits, user_seed), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_DSA_Key_Pair, (ISC_DSA_UNIT *dsa), (dsa), ISC_ERR_GET_ADRESS_LOADLIBRARY );

#endif

#ifdef  __cplusplus
}
#endif
#endif



