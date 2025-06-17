/*!
* \file ecdsa.h
* \brief ecdsa �������
* \author
* Copyright (c) 2013 by \<INITech\>
*/

#ifndef HEADER_ECDSA_H
#define HEADER_ECDSA_H


#if defined(ISC_NO_ECC)
#define ISC_NO_ECDSA
#error ISC_ECDSA is disabled.
#endif

#ifdef ISC_NO_ECDSA
#error ISC_ECDSA is disabled.
#endif

#include "biginteger.h"
#include "digest.h"
#include "foundation.h"
#include "ecc.h"

#define ISC_ECDSA_PROVEN_MODE	1		/*!<  0: ����� ���, 1: ������� */

#define ISC_ECDSA_SIGN			1		/*!< ISC_ECDSA_SIGN*/
#define ISC_ECDSA_VERIFY		0		/*!< ISC_ECDSA_VERIFY*/

/* ISC_ECDSA Alias				0x50000000 ------------------------------------------------ */
#define ISC_ECDSA				0x50000000   /*!< ISC_ECDSA �˰��� ID */

/*!
* \brief
* ISC_ECDSA �˰����� ���� ����ü
*/
struct isc_ecdsa_st
{
	ISC_ECC_KEY_UNIT *key;			/*!< ISC_ECC_KEY_UNIT*/
	ISC_DIGEST_UNIT *d_unit;		/*!< ISC_DIGEST_UNIT*/
	ISC_BIGINT *k;					/*!< �������� ����� ���� k�� */
	ISC_ECPOINT *kG;				/*!< �������� ����� ���� kG�� */
	ISC_BIGINT_POOL *pool;			/*!< ���� ȿ���� ���� Ǯ */
	int is_private;					/*!< Public : 0 , Private : 1 */
	ISC_BIGINT *kkey;				/*!< ���Ͱ�. ������� �ʴ´�. */
};	

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_ECDSA_UNIT ����ü�� �޸� �Ҵ�
* \returns
* ISC_ECDSA_UNIT ����ü
*/
ISC_API ISC_ECDSA_UNIT *ISC_New_ECDSA(void);

/*!
* \brief
* ISC_ECDSA_UNIT �޸� ���� �Լ�
* \param unit
* �޸� ������ ISC_ECDSA_UNIT
*/
ISC_API void ISC_Free_ECDSA(ISC_ECDSA_UNIT *unit);

/*!
* \brief
* ISC_ECDSA_UNIT �޸� �ʱ�ȭ �Լ�
* \param unit
* �ʱ�ȭ �� ISC_ECDSA_UNIT
*/
ISC_API void ISC_Clean_ECDSA(ISC_ECDSA_UNIT *unit);

/*!
* \brief
* ECDSA ���ڼ��� �˰��� �ʱ�ȭ
* \param ecdsa
* �ʱ�ȭ �� ISC_ECDSA_UNIT
* \param digest_alg
* �ؽ� �˰��� ID
* \param sign
* (ISC_ECDSA_SIGN)1 : ����, (ISC_ECDSA_VERIFY)0 : ����
* \param user_seed
* ������ �����ϴ� ���� seed��
* \param user_seedLen
* ������ �����ϴ� ���� seed���� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# LOCATION^ISC_F_INIT_ECDSA^ISC_ERR_NOT_PROVEN_ALGORITHM : ��������˰��� ����
* -# LOCATION^ISC_F_INIT_ECDSA^ISC_ERR_NULL_INPUT : NULL ������ �Է�
* -# LOCATION^ISC_F_INIT_ECDSA^ISC_ERR_MEM_ALLOC : �޸� �Ҵ� ����
* -# LOCATION^ISC_F_INIT_ECDSA^ISC_ERR_INIT_DIGEST_FAIL : �ؽ� �ʱ�ȭ ����
*/
ISC_API ISC_STATUS ISC_Init_ECDSA(ISC_ECDSA_UNIT *unit, int digest_alg, int sign, uint8* user_seed, int user_seedLen);

/*!
* \brief
* ISC_ECDSA ���ڼ��� �޽��� �Է�(Update) �Լ�
* \param ecdsa
* ISC_ECDSA_UNIT ����ü ������
* \param data
* �Էµ� ������(������ �Է� ����)
* \param dataLen
* �������� ����
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_UPDATE_ECDSA^ISC_ERR_NULL_INPUT : �Էµ� RSA_UNIT�� NULL�� ���
* -# LOCATION^ISC_F_UPDATE_ECDSA^ISC_ERR_UPDATE_DIGEST_FAIL : ���� Digest �Լ� ���� 
*/
ISC_API ISC_STATUS ISC_Update_ECDSA(ISC_ECDSA_UNIT *unit, const uint8 *data, int dataLen);

/*!
* \brief
* ISC_ECDSA ���ڼ����� ���� ���� / ���� �Լ�
* \param ecdsa
* ISC_ECDSA_UNIT ����ü ������
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
* -# LOCATION^ISC_F_FINAL_ECDSA^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# LOCATION^ISC_F_FINAL_ECDSA^ISC_ERR_NO_PRIVATE_VALUE : ����Ű�� ���� ���� �õ�
* -# LOCATION^ISC_F_FINAL_ECDSA^ISC_ERR_SIGN_DSA_FAIL : ���� ����
* -# LOCATION^ISC_F_FINAL_ECDSA^ISC_ERR_VERIFY_ECDSA_FAIL : ���� ����
*/
ISC_API ISC_STATUS ISC_Final_ECDSA(ISC_ECDSA_UNIT *unit, uint8 *r, int *rLen,  uint8 *s, int *sLen);

/*!
* \brief
* ISC_ECDSA_UNIT�� �Էµ� �Ķ���� ����
* \param ecdsa
* target ISC_ECDSA_UNIT ����ü
* \param field_id
* curve id��
* \param x
* ����Ű ��
* \param y
* ����Ű ��
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_ECDSA^ISC_F_SET_ECDSA_PARAMS_EX^ISC_ERR_NULL_INPUT : NULL�� �Է�
* -# ISC_L_ECDSA^ISC_F_SET_ECDSA_PARAMS_EX^ISC_ERR_MEM_ALLOC : �޸� ���� ����
* -# ISC_L_ECDSA^ISC_F_SET_ECDSA_PARAMS_EX^ISC_ERR_SET_ECC_KEY_PARAMS_EX : Ŀ�� ���� ����
*/
ISC_API ISC_STATUS ISC_Set_ECDSA_Params(ISC_ECDSA_UNIT *unit, const int field_id, const ISC_BIGINT* x, const ISC_ECPOINT* y);

/*!
* \brief
* ISC_ECDSA_UNIT�� �Էµ� �Ķ���� ����
* \param ecdsa
* target ISC_ECDSA_UNIT ����ü
* \param curve
* curve ��
* \param x
* ����Ű ��
* \param y
* ����Ű ��
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_ECDSA^ISC_F_SET_ECDSA_PARAMS^ISC_ERR_NULL_INPUT : NULL�� �Է�
* -# ISC_L_ECDSA^ISC_F_SET_ECDSA_PARAMS^ISC_ERR_MEM_ALLOC : �޸� ���� ����
* -# ISC_L_ECDSA^ISC_F_SET_ECDSA_PARAMS^ISC_ERR_OPERATE_FUNCTION : Ŀ�� ���� ����
* -# ISC_L_ECDSA^ISC_F_SET_ECDSA_PARAMS^ISC_F_SET_ECDSA_PARAMS^ISC_ERR_COPY_BIGINT_FAIL : BIGINT_COPY ����
*/
ISC_API ISC_STATUS ISC_Set_ECDSA_Params_Ex(ISC_ECDSA_UNIT *unit, const ISC_ECURVE* curve, const ISC_BIGINT* x, const ISC_ECPOINT* y);

/*!
* \brief
* ����Ű, ����Ű Ű���� ����
* \param key
* ISC_ECC_KEY_UNIT ����ü �����ͷ� curve�� ������ �Ǿ���� �Ѵ�. ���� �� Ű���� �����Ѵ�.
* -# ISC_SUCCESS : Success
* -# ISC_L_ECDSA^ISC_F_GENERATE_ECDSA_KEY_PAIR^ISC_ERR_NULL_INPUT : NULL�� �Է�
* -# ISC_L_ECDSA^ISC_F_GENERATE_ECDSA_KEY_PAIR^ISC_ERR_GENERATE_KEY_PAIR : Ű�� ���� ����
*/
ISC_API ISC_STATUS ISC_Generate_ECDSA_Key_Pair(ISC_ECDSA_UNIT *unit);

/*!
* \brief
* ISC_ECDSA ���ڼ����� ���� ����
* \param ecdsa
* ISC_ECDSA_UNIT ����ü ������
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
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_INIT_PRNG_FAIL : ISC_Init_PRNG ����
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_START_BIGINT_POOL_FAIL : START_BIGINT_POOL ����
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_FINAL_DIGEST_FAIL : FINAL_DIGEST ����
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_GET_BIGINT_POOL_FAIL : GET_BIGINT_POOL ����
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_GET_RAND_DSA_BIGINT_FAIL : ���� K ���� ����
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_MTP_FP_ECC : ECC ���� ���� ����
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_ADD_BIGINT_FAIL : ADD_BIGINT ����
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_ADD_FP_ECC : ECC ���� ���� ����
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_MOD_INVERSE_BIGINT_FAIL : MOD_INVERSE_BIGINT ����
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY_TO_BIGINT ����
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_MOD_BIGINT_FAIL : MOD_BIGINT ����
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_MOD_MTP_BIGINT_FAIL : MOD_MTP_BIGINT ����
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_ADD_BIGINT_FAIL : ADD_BIGINT ����
*/
ISC_INTERNAL ISC_STATUS isc_Sign_ECDSA(ISC_ECDSA_UNIT *unit, uint8 *r, int *rLen, uint8 *s, int *sLen);

/*!
* \brief
* ISC_ECDSA ���ڼ����� ���� ����
* \param ecdsa
* ISC_ECDSA_UNIT ����ü ������
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
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_START_BIGINT_POOL_FAIL : START_BIGINT_POOL ����
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_FINAL_DIGEST_FAIL : FINAL_DIGEST ����
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY_TO_BIGINT ����
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_MOD_INVERSE_BIGINT_FAIL : MOD_INVERSE_BIGINT ����
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_MEMORY_ALLOC : MEMORY_ALLOC ����
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_MOD_MTP_BIGINT_FAIL : MOD_MTP_BIGINT ����
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_GET_BIGINT_POOL_FAIL : GET_BIGINT_POOL ����
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_MTP_FP_ECC : ECC ���� ����
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_ADD_FP_ECC : ECC ���� ����
* -# LOCATION^ISC_F_VERIFY_ECDSA^ISC_ERR_VERIFY_FAILURE : ���� ����
*/
ISC_INTERNAL ISC_STATUS isc_Verify_ECDSA(ISC_ECDSA_UNIT *unit, uint8 *r, int rLen, uint8 *s, int sLen);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_ECDSA_UNIT*, ISC_New_ECDSA, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_ECDSA, (ISC_ECDSA_UNIT *unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_ECDSA, (ISC_ECDSA_UNIT *unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_ECDSA, (ISC_ECDSA_UNIT *unit, int digest_alg, int sign, uint8* user_seed, int user_seedLen), (unit, digest_alg, sign, user_seed, user_seedLen), ISC_ERR_GET_ADRESS_LOADLIBRARY);
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Update_ECDSA, (ISC_ECDSA_UNIT *unit, const uint8 *data, int dataLen), (unit, data, dataLen), ISC_ERR_GET_ADRESS_LOADLIBRARY);
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Final_ECDSA, (ISC_ECDSA_UNIT *unit, uint8 *r, int *rLen,  uint8 *s, int *sLen), (unit, r, rLen, s, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY);
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_ECDSA_Params, (ISC_ECDSA_UNIT *unit, const int field_id, const ISC_BIGINT* x, const ISC_ECPOINT* y), (unit, field_id, x, y), ISC_ERR_GET_ADRESS_LOADLIBRARY);
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_ECDSA_Params_Ex, (ISC_ECDSA_UNIT *unit, const ISC_ECURVE* curve, const ISC_BIGINT* x, unit ISC_ECPOINT* y), (unit, curve, x, y), ISC_ERR_GET_ADRESS_LOADLIBRARY);
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_ECDSA_Key_Pair, (ISC_ECDSA_UNIT *unit), (unit), ISC_ERR_GET_ADRESS_LOADLIBRARY);

#endif /* #ifndef ISC_WIN_LOADLIBRARY_CRYPTO */

#ifdef  __cplusplus
}
#endif

#endif /* #ifndef HEADER_ECDSA_H */
