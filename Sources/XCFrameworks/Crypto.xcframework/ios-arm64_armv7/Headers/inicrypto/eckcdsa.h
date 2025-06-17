/*!
* \file eckcdsa.h
* \brief eckcdsa �������
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_ECKCDSA_H
#define HEADER_ECKCDSA_H


#include "biginteger.h"
#include "foundation.h"
#include "ecc.h"

#ifdef ISC_NO_ECKCDSA
#error ISC_ECKCDSA is disabled.
#endif

#define ISC_ECKCDSA_SIGN		1			/*!< ISC_ECKCDSA_SIGN*/
#define ISC_ECKCDSA_VERIFY		0			/*!< ISC_ECKCDSA_VERIFY*/

#define ISC_ECKCDSA_PROVEN_MODE	0    /*!<  0: ����� ���, 1: ������� */

/*ISC_ECKCDSA Alias				0x60000000 ------------------------------------------------ */
#define ISC_ECKCDSA				0x60000000   /*!< ISC_ECKCDSA �˰��� ID */

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* ISC_ECKCDSA �˰����� ���� ����ü
*/
struct isc_eckcdsa_st	{
	ISC_DIGEST_UNIT *d_unit;		/*!< ISC_DIGEST_UNIT*/
	ISC_ECC_KEY_UNIT *key;			/*!< ISC_ECC_KEY_UNIT*/
	ISC_BIGINT *k;					/*!< �������� ����� ���� k�� */
	ISC_ECPOINT *kG;				/*!< �������� ����� ���� kG�� */
	ISC_BIGINT *kkey;				/*!< ���Ͱ�. ������� �ʴ´�. */
	int is_private;					/*!< Public : 0 , Private : 1*/
	ISC_BIGINT_POOL *pool;			/*!< ���� ȿ���� ���� Ǯ */
};

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ECKCDSA_UNIT ����ü�� �޸� �Ҵ�
* \returns
* ISC_ECKCDSA_UNIT ����ü
*/
ISC_API ISC_ECKCDSA_UNIT* ISC_New_ECKCDSA(void);
/*!
* \brief
* ECKCDSA_UNIT �޸� ���� �Լ�
* \param unit
* �޸� ������ ISC_ECKCDSA_UNIT
*/
ISC_API void ISC_Free_ECKCDSA(ISC_ECKCDSA_UNIT* unit);
/*!
* \brief
* ISC_ECKCDSA_UNIT �޸� �ʱ�ȭ �Լ�
* \param unit
* �ʱ�ȭ �� ISC_ECKCDSA_UNIT
*/
ISC_API void ISC_Clean_ECKCDSA(ISC_ECKCDSA_UNIT *unit);

/*!
* \brief
* ECKCDSA Parameter ����
* \param eckcdsa
* Parameter�� �Էµ� ISC_ECKCDSA_UNIT
* \param field_id
* Ŀ�� id��
* \param x
* ����Ű x
* \param y
* ����Ű y
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_ECKCDSA^ISC_F_SET_ECKCDSA_PARAMS_EX^ISC_ERR_NULL_INPUT : NULL�� �Է�
* -# ISC_L_ECKCDSA^ISC_F_SET_ECKCDSA_PARAMS_EX^ISC_ERR_MEM_ALLOC : �޸� �Ҵ� ����
* -# LOCATION^ISC_F_SET_ECKCDSA_PARAMS_EX^ISC_ERR_SET_ECC_KEY_PARAMS_EX : Ŀ�갪 ���� ����
*/
ISC_API ISC_STATUS ISC_Set_ECKCDSA_Params(ISC_ECKCDSA_UNIT *unit, const int field_id, const ISC_BIGINT* x, const ISC_ECPOINT* y);

/*!
* \brief
* ECKCDSA Parameter ����
* \param eckcdsa
* Parameter�� �Էµ� ISC_ECKCDSA_UNIT
* \param curve
* Ŀ�갪
* \param x
* ����Ű x
* \param y
* ����Ű y
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_L_ECKCDSA^ISC_F_SET_ECKCDSA_PARAMS^ISC_ERR_NULL_INPUT : NULL�� �Է�
* -# ISC_L_ECKCDSA^ISC_F_SET_ECKCDSA_PARAMS^ISC_ERR_MEM_ALLOC : �޸� �Ҵ� ����
* -# LOCATION^ISC_F_SET_ECKCDSA_PARAMS^ISC_ERR_SUB_OPERATION_FAILURE : Ŀ�갪 ���� ����
* -# LOCATION^ISC_F_SET_ECKCDSA_PARAMS^ISC_ERR_COPY_BIGINT_FAIL : COPY BIGINT ����
*/
ISC_API ISC_STATUS ISC_Set_ECKCDSA_Params_Ex(ISC_ECKCDSA_UNIT *unit, 
										  const ISC_ECURVE* curve, 
										  const ISC_BIGINT* x, 
										  const ISC_ECPOINT* y);



/*!
* \brief
* ECKCDSA ���ڼ��� �˰��� �ʱ�ȭ
* \param unit
* �ʱ�ȭ �� ISC_ECKCDSA_UNIT
* \param digest_id
* �ؽ� ���̵�
* \param sign
* (ISC_ECKCDSA_SIGN)1 : ����, (ISC_ECKCDSA_VERIFY)0 : ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_ECKCDSA^ISC_F_INIT_ECKCDSA^ISC_ERR_NULL_INPUT : NULL�� �Է�
* -# ISC_L_ECKCDSA^ISC_F_INIT_ECKCDSA^ISC_ERR_MEM_ALLOC : �޸� �Ҵ� ����
* -# ISC_L_ECKCDSA^ISC_F_INIT_ECKCDSA^ISC_ERR_NOT_SUPPORTED_CURVE_TYPE : �������� �ʴ� Ŀ�갪 �Է�
* -# ISC_L_ECKCDSA^ISC_F_INIT_ECKCDSA^ISC_ERR_INIT_DIGEST_FAIL : INIT DIGEST ����
* -# ISC_L_ECKCDSA^ISC_F_INIT_ECKCDSA^ISC_ERR_NEW_BIGINT_POOL_FAIL : NEW BIGINT POOL ����
*/
ISC_API ISC_STATUS ISC_Init_ECKCDSA(ISC_ECKCDSA_UNIT *unit, int digest_id, int sign);

/*!
* \brief
* ISC_ECKCDSA ���ڼ��� �޽��� �Է�(Update) �Լ�
* \param eckcdsa
* ISC_ECKCDSA_UNIT ����ü ������
* \param data
* �Էµ� ������(������ �Է� ����)
* \param dataLen
* �������� ����
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_ECKCDSA^ISC_F_UPDATE_ECKCDSA^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_ECKCDSA^ISC_F_UPDATE_ECKCDSA^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ����(lmb_ECKCDSA) ����
* -# ISC_L_ECKCDSA^ISC_F_UPDATE_ECKCDSA^ISC_ERR_MEM_ALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_ECKCDSA^ISC_F_UPDATE_ECKCDSA^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� BIGINT ���� ����
* -# ISC_L_ECKCDSA^ISC_F_UPDATE_ECKCDSA^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST ���� ����
*/
ISC_API ISC_STATUS ISC_Update_ECKCDSA(ISC_ECKCDSA_UNIT *unit, const uint8 *data, uint32 dataLen);

/*!
* \brief
* ECKCDSA ���ڼ����� ���� ���� / ���� �Լ�
* \param eckcdsa
* ISC_ECKCDSA_UNIT ����ü ������
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
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# LOCATION^ISC_F_SIGN_ECKCDSA^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# LOCATION^ISC_F_SIGN_ECKCDSA^ISC_ERR_FINAL_DIGEST_FAIL : FINAL DIGEST ����
* -# LOCATION^ISC_F_SIGN_ECKCDSA^ISC_ERR_GET_BIGINT_POOL_FAIL : BIGINT POOL ����
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_MEM_ALLOC : ���� �޸� �Ҵ� ����
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_RAND_BIGINT_FAIL : RAND_BIGINT ����
* -# LOCATION^ISC_F_SIGN_ECKCDSA^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ����
* -# LOCATION^ISC_F_SIGN_ECKCDSA^ISC_ERR_MOD_BIGINT_FAIL : MOD BIGINT ����
* -# LOCATION^ISC_F_SIGN_ECKCDSA^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : MOD EXP MONT BIGINT ����
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_ADD_BIGINT_FAIL : ADD BIGINT ����
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_ADD_FP_ECC : ADD FP ECC ����
* -# LOCATION^ISC_F_SIGN_ECDSA^ISC_ERR_COPY_BIGINT_FAIL : COPY BIGINT ����
* -# LOCATION^ISC_F_SIGN_ECKCDSA^ISC_ERR_INIT_DIGEST_FAIL : INIT DIGEST ����
* -# LOCATION^ISC_F_SIGN_ECKCDSA^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST ����
* -# LOCATION^ISC_F_SIGN_ECKCDSA^ISC_ERR_FINAL_DIGEST_FAIL : FINAL DIGEST ����
* -# LOCATION^ISC_F_SIGN_ECKCDSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY TO BIGINT ����
* -# LOCATION^ISC_F_SIGN_ECKCDSA^ISC_ERR_SUB_BIGINT_FAIL : SUB BIGINT ����
* -# LOCATION^ISC_F_SIGN_ECKCDSA^ISC_ERR_MOD_MTP_BIGINT_FAIL : MOD MTP BIGINT ����
* -# LOCATION^ISC_F_VERIFY_ECKCDSA^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# LOCATION^ISC_F_VERIFY_ECKCDSA^ISC_ERR_FINAL_DIGEST_FAIL : FINAL DIGEST ����
* -# LOCATION^ISC_F_VERIFY_ECKCDSA^ISC_ERR_COMPARE_FAIL : Compare ����
* -# LOCATION^ISC_F_VERIFY_ECKCDSA^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL ����
* -# LOCATION^ISC_F_VERIFY_ECKCDSA^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL ����
* -# LOCATION^ISC_F_VERIFY_ECKCDSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY TO BIGINT ����
* -# LOCATION^ISC_F_VERIFY_ECKCDSA^ISC_ERR_IS_BIGINT_ZERO_FAIL : IS BIGINT ZERO ����
* -# LOCATION^ISC_F_VERIFY_ECKCDSA^ISC_ERR_CMP_BIGINT_FAIL : CMP BIGINT ����
* -# LOCATION^ISC_F_VERIFY_ECKCDSA^ISC_ERR_MTP_ECC_MONT_FAIL : MTP ECC MONT ����
* -# LOCATION^ISC_F_VERIFY_ECKCDSA^ISC_ERR_MTP_ECC_FBC_FAIL : MTP ECC FBC ����
* -# LOCATION^ISC_F_VERIFY_ECKCDSA^ISC_ERR_ADD_ECC_FAIL : ADD ECC ����
* -# LOCATION^ISC_F_VERIFY_ECKCDSA^ISC_ERR_INIT_DIGEST_FAIL : INIT DIGEST ����
* -# LOCATION^ISC_F_VERIFY_ECKCDSA^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST ����
* -# LOCATION^ISC_F_VERIFY_ECKCDSA^ISC_ERR_VERIFY_FAILURE : VERIFY ����
*/
ISC_API ISC_STATUS ISC_Final_ECKCDSA(ISC_ECKCDSA_UNIT *unit, uint8 *r, int *rLen,  uint8 *s, int *sLen);

/*!
* \brief
* ����Ű, ����Ű Ű���� ����
* \param key
* ISC_ECC_KEY_UNIT ����ü �����ͷ� curve�� ������ �Ǿ���� �Ѵ�. ���� �� Ű���� �����Ѵ�.
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_ECDH^ISC_F_GENERATE_ECKCDSA_KEY_PAIR^ISC_ERR_NULL_INPUT : NULL�� �Է�          
* -# ISC_L_ECDH^ISC_F_GENERATE_ECKCDSA_KEY_PAIR^ISC_ERR_GENERATE_KEY_PAIR : Ű�� ���� ����
*/
ISC_API ISC_STATUS ISC_Generate_ECKCDSA_Key_Pair(ISC_ECKCDSA_UNIT *unit);

/*!
* \brief
* ISC_ECKCDSA ���ڼ����� ���� ����
* \param eckcdsa
* ISC_ECKCDSA_UNIT ����ü ������
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
* -# ISC_L_ECKCDSA^ISC_F_SIGN_ECKCDSA^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
* -# ISC_L_ECKCDSA^ISC_F_SIGN_ECKCDSA^ISC_ERR_FINAL_DIGEST_FAIL : FINAL DIGEST ���� ����
* -# ISC_L_ECKCDSA^ISC_F_SIGN_ECKCDSA^ISC_ERR_GET_BIGINT_POOL_FAIL : BIGINT POOL ���� ����
* -# ISC_L_ECKCDSA^ISC_F_SIGN_ECKCDSA^ISC_ERR_GET_RAND_FAIL : ���� ���� ����
* -# ISC_L_ECKCDSA^ISC_F_SIGN_ECKCDSA^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : MOD EXP MONT BIGINT ���� ����
* -# ISC_L_ECKCDSA^ISC_F_SIGN_ECKCDSA^ISC_ERR_INIT_DIGEST_FAIL : INIT DIGEST ���� ����
* -# ISC_L_ECKCDSA^ISC_F_SIGN_ECKCDSA^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST ���� ����
* -# ISC_L_ECKCDSA^ISC_F_SIGN_ECKCDSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY TO BIGINT ���� ����
* -# ISC_L_ECKCDSA^ISC_F_SIGN_ECKCDSA^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� BIGINT ���� ����
* -# ISC_L_ECKCDSA^ISC_F_SIGN_ECKCDSA^ISC_ERR_SUB_BIGINT_FAIL : SUB BIGINT ���� ����
*/
ISC_INTERNAL ISC_STATUS ISC_Sign_ECKCDSA(ISC_ECKCDSA_UNIT *unit, uint8 *r, int *rLen, uint8 *s, int *sLen);

/*!
* \brief
* ECKCDSA ���ڼ����� ���� ����
* \param eckcdsa
* ISC_ECKCDSA_UNIT ����ü ������
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
* -# ISC_L_ECKCDSA^ISC_F_VERIFY_ECKCDSA^ISC_ERR_NULL_INPUT: NULL �Է°� �Է�
* -# ISC_L_ECKCDSA^ISC_F_VERIFY_ECKCDSA^ISC_ERR_FINAL_DIGEST_FAIL : FINAL DIGEST ����
* -# ISC_L_ECKCDSA^ISC_F_VERIFY_ECKCDSA^ISC_ERR_SUB_OPERATION_FAILURE : �����Լ� ����(BIGINT) ����
* -# ISC_L_ECKCDSA^ISC_F_VERIFY_ECKCDSA^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL ���� ����
* -# ISC_L_ECKCDSA^ISC_F_VERIFY_ECKCDSA^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY TO BIGINT ���� ����
* -# ISC_L_ECKCDSA^ISC_F_VERIFY_ECKCDSA^ISC_ERR_IS_BIGINT_ZERO_FAIL : BIGINT�� ����� ZERO
* -# ISC_L_ECKCDSA^ISC_F_VERIFY_ECKCDSA^ISC_ERR_CMP_BIGINT_FAIL : Cmp BIGINT ����  ����
* -# ISC_L_ECKCDSA^ISC_F_VERIFY_ECKCDSA^ISC_ERR_MOD_EXP_MONT_BIGINT_FAIL : Mod Exp MONT BIGINT ���� ����
* -# ISC_L_ECKCDSA^ISC_F_VERIFY_ECKCDSA^ISC_ERR_INIT_DIGEST_FAIL : INIT DIGEST ���� ����
* -# ISC_L_ECKCDSA^ISC_F_VERIFY_ECKCDSA^ISC_ERR_UPDATE_DIGEST_FAIL : UPDATE DIGEST ���� ����
* -# ISC_L_ECKCDSA^ISC_F_VERIFY_ECKCDSA^ISC_ERR_VERIFY_FAILURE : ������� ����
*/
ISC_INTERNAL ISC_STATUS ISC_Verify_ECKCDSA(ISC_ECKCDSA_UNIT *unit, uint8 *r, int *rLen, uint8 *s, int *sLen);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_ECKCDSA_UNIT*, ISC_New_ECKCDSA, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_ECKCDSA, (ISC_ECKCDSA_UNIT* unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_ECKCDSA, (ISC_ECKCDSA_UNIT* unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_ECKCDSA_Params, (ISC_ECKCDSA_UNIT *unit, const int field_id, const ISC_BIGINT* x, const ISC_ECPOINT* y), (unit,field_id,x,y), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_ECKCDSA_Params_Ex, (ISC_ECKCDSA_UNIT *unit,const ISC_ECURVE* curve,const ISC_BIGINT* x,const ISC_ECPOINT* y), (unit,curve,x,y), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Init_ECKCDSA, (ISC_ECKCDSA_UNIT *unit,int digest_id,int sign), (unit,digest_id,sign), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Update_ECKCDSA, (ISC_ECKCDSA_UNIT *unit, const uint8 *data, uint32 dataLen), (unit, data, dataLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Final_ECKCDSA, (ISC_ECKCDSA_UNIT *unit, uint8 *r, int *rLen,  uint8 *s, int *sLen), (unit, r, rLen, s, sLen), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_ECKCDSA_Key_Pair, (ISC_ECKCDSA_UNIT *unit), (unit), ISC_ERR_GET_ADRESS_LOADLIBRARY);

#endif

#ifdef  __cplusplus
}
#endif

#endif


