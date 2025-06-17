/*!
* \file ecdh.h
* \brief ecdh �������
* \author
* Copyright (c) 2013 by \<INITech\>
*/

#ifndef HEADER_ECDH_H
#define HEADER_ECDH_H

#include "biginteger.h"
#include "foundation.h"
#include "ecc.h"

#ifdef ISC_NO_HAS160
#define ISC_NO_ECDH
#endif

#ifdef ISC_NO_ECDH
#error ISC_ECDH is disabled.
#endif

#define ISC_ECDH_PROVEN_MODE  0    /*!<  0: ����� ���, 1: ������� */

/*ISC_ECDH Alias				0x80000000 ------------------------------------------------ */
#define ISC_ECDH				0x80000000   /*!< ISC_ECDH �˰��� ID */

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* ISC_ECDH �˰����� ���� ����ü
*/
struct isc_ecdh_st {
	ISC_ECC_KEY_UNIT *key;			/*!< ECC Ű�� �� Ŀ�� */
	ISC_BIGINT_POOL *pool;			/*!< ���� ȿ���� ���� Ǯ */
	
	/* KCMVP TEST �뵵 ���� ��������� ������ ����*/
	ISC_ECPOINT *kab;				/*!< ����Ű */
};

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_ECDH_UNIT ����ü�� �޸� �Ҵ�
* \returns
* ISC_ECDH_UNIT ����ü
*/
ISC_API ISC_ECDH_UNIT* ISC_New_ECDH(void);

/*!
* \brief
* ISC_ECDH_UNIT �޸� ���� �Լ�
* \param ecdh
* �޸� ������ ISC_ECDH_UNIT
*/
ISC_API void ISC_Free_ECDH(ISC_ECDH_UNIT* unit);

/*!
* \brief
* ISC_ECDH_UNIT �޸� �ʱ�ȭ �Լ�
* \param ecdh
* �ʱ�ȭ �� ISC_ECDH_UNIT
*/
ISC_API void ISC_Clean_ECDH(ISC_ECDH_UNIT *unit);

/*!
* \brief
* ECDH Parameter�� �Էµ� �Ķ���ͷ� �ʱ�ȭ �Ѵ�.
* \param ecdh
* Parameter�� ����� ISC_ECDH_UNIT
* \param field_id
* �Է°� curve id
* \param ra
* �ڽ��� ����Ű
* \param kta
* �ڽ��� ����Ű
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_SET_ECDH_PARAMS_Ex^ISC_ERR_NULL_INPUT : NULL�� �Է�
* -# LOCATION^ISC_F_SET_ECDH_PARAMS_Ex^ISC_ERR_MEM_ALLOC : �޸� �Ҵ� ����
* -# LOCATION^ISC_F_SET_ECDH_PARAMS_Ex^ISC_ERR_SET_ECC_KEY_PARAMS_EX : Ŀ�갪 ���� ����
* -# LOCATION^ISC_F_SET_ECDH_PARAMS_Ex^ISC_ERR_COPY_BIGINT_FAIL : COPY_BIGINT ����
*/
ISC_API ISC_STATUS ISC_Set_ECDH_Params(ISC_ECDH_UNIT *unit, int field_id, ISC_BIGINT *ra, ISC_ECPOINT *kta);

/*!
* \brief
* ECDH Parameter�� �Էµ� �Ķ���ͷ� �ʱ�ȭ �Ѵ�.
* \param ecdh
* Parameter�� ����� ISC_ECDH__UNIT
* \param curve
* �Է°� curve
* \param ra
* �ڽ��� ����Ű
* \param kta
* �ڽ��� ����Ű
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_SET_ECDH_PARAMS^ISC_ERR_NULL_INPUT : NULL�� �Է�
* -# LOCATION^ISC_F_SET_ECDH_PARAMS^ISC_ERR_MEM_ALLOC : �޸� �Ҵ� ����
* -# LOCATION^ISC_F_SET_ECDH_PARAMS^ISC_ERR_SUB_OPERATION_FAILURE : Ŀ�갪 ���� ����
* -# LOCATION^ISC_F_SET_ECDH_PARAMS^ISC_ERR_COPY_BIGINT_FAIL : COPY_BIGINT ����
*/
ISC_API ISC_STATUS ISC_Set_ECDH_Params_Ex(ISC_ECDH_UNIT *unit, ISC_ECURVE *curve, ISC_BIGINT *ra, ISC_ECPOINT *kta);							

/*!
* \brief
* ����Ű, ����Ű Ű���� ����
* \param key
* ISC_ECC_KEY_UNIT ����ü �����ͷ� curve�� ������ �Ǿ���� �Ѵ�. ���� �� Ű���� �����Ѵ�.
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_ECDH^ISC_F_GENERATE_ECDH_KEY_PAIR^ISC_ERR_NULL_INPUT : NULL�� �Է�          
* -# ISC_L_ECDH^ ISC_F_GENERATE_ECDH_KEY_PAIR^ISC_ERR_NOT_SUPPORTED_CURVE_TYPE : ������
* -# ISC_L_ECDH^ISC_F_GENERATE_ECDH_KEY_PAIR^ISC_ERR_GENERATE_KEY_PAIR : Ű�� ���� ����
*/
ISC_API ISC_STATUS ISC_Generate_ECDH_Key_Pair(ISC_ECDH_UNIT *unit);

/*!
* \brief
* �Է¹��� ISC_ECDH_UNIT�� �ڽ��� ���Ű ra, ������ ����Ű ktb�� �̿��� ����Ű kab�� �����Ѵ�. kab = ktb^ra mod p
* \param key
* ������ uint8���� ����Ű��
* \param key_len
* ������ uint8���� ����Ű�� ����
* \param ecdh
* ����Ű�� ����� ���� �Ķ���� ��
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_ECDH^ISC_F_COMPUTE_ECDH_KEY^ISC_ERR_NULL_INPUT : NULL�� �Է�
* -# ISC_L_ECDH^ISC_F_COMPUTE_ECDH_KEY^ISC_ERR_MEM_ALLOC : �޸� �Ҵ� ����
* -# ISC_L_ECDH^ISC_F_COMPUTE_ECDH_KEY^ISC_ERR_NOT_SUPPORTED_CURVE_TYPE : �������� �ʴ� Ŀ�갪 �Է�
* -# ISC_L_ECDH^ISC_F_COMPUTE_ECDH_KEY^ISC_ERR_MTP_BIGINT_FAIL : MTP_BIGINT ����
* -# ISC_L_ECDH^ISC_F_COMPUTE_ECDH_KEY^ISC_ERR_MTP_ECC_MONT_FAIL : _MTP_ECC_MONT ����
*/
ISC_API ISC_STATUS ISC_Compute_ECDH_Key(ISC_ECDH_UNIT *unit, ISC_ECPOINT *pub_key, uint8 *out, int *out_len);


#else

ISC_RET_LOADLIB_CRYPTO(ISC_ECDH_UNIT*, ISC_New_ECDH, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_ECDH, (ISC_ECDH_UNIT* unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_ECDH, (ISC_ECDH_UNIT* unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_ECDH_Params, (ISC_ECDH_UNIT *unit, int field_id, ISC_BIGINT *ra, ISC_ECPOINT *kta), (unit,field_id,ra,kta), ISC_ERR_GET_ADRESS_LOADLIBRARY);
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_ECDH_Params_Ex, (ISC_ECDH_UNIT *unit,ISC_ECURVE *curve,ISC_BIGINT *ra,ISC_ECPOINT *kta,ISC_ECPOINT *ktb,ISC_ECPOINT *kab), (unit,curve,ra,kta,ktb,kab), ISC_ERR_GET_ADRESS_LOADLIBRARY);
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_ECDH_Key_Pair, (ISC_ECDH_UNIT *unit), (unit), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Compute_Key, (ISC_ECDH_UNIT *unit, ISC_ECPOINT *pub_key, uint8 *out, int *out_len), (unit, pub_key, out, out_len), ISC_ERR_GET_ADRESS_LOADLIBRARY );

#endif

#ifdef  __cplusplus
}
#endif

#endif


