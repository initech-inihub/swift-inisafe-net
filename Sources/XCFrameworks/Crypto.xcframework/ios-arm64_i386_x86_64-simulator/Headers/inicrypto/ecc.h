/*!
* \file ecc.h
* \brief ecc �������(ecc �˰���)
* \author
* Copyright (c) 2013 by \<INITech\>
*/

#ifndef HEADER_ECC_H
#define HEADER_ECC_H

#ifdef ISC_NO_ECC
#error ECC is disabled.
#endif /* ISC_NO_ECC */

#include "biginteger.h"
#include "digest.h"
#include "foundation.h"
#include "ecpoint.h"
#include "ecurve.h"

struct isc_ecc_key_st
{
	ISC_ECURVE *curve;				/*!< curve �� */
	ISC_ECPOINT *y;					/*!< ���� �Ķ���� y = g^x*/
	ISC_BIGINT *x;					/*!< ����Ű x */
	int is_private;					/*!< �����. ������ */
};	

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_ECC_KEY_UNIT ����ü�� �޸� �Ҵ�
* \returns
* ISC_ECC_KEY_UNIT ����ü
*/
ISC_API ISC_ECC_KEY_UNIT *ISC_New_ECC_Key(void);

/*!
* \brief
* ISC_ECC_KEY_UNIT �޸� ���� �Լ�
* \param unit
* �޸� ������ ISC_ECC_KEY_UNIT
*/
ISC_API void ISC_Free_ECC_Key(ISC_ECC_KEY_UNIT *unit);

/*!
* \brief
* ISC_ECC_KEY_UNIT �޸� �ʱ�ȭ �Լ�
* \param unit
* �ʱ�ȭ �� ISC_ECC_KEY_UNIT
*/
ISC_API void ISC_Clean_ECC_Key(ISC_ECC_KEY_UNIT *unit);

/*!
* \brief
* ISC_ECC_KEY_UNIT �Ķ���� ���� �Լ�
* \param unit
* �������� ������ ISC_ECC_KEY_UNIT ����ü ������
* \param field_id
* �Է°� curve id (ISC_ECC_P_224, ISC_ECC_P_256, ISC_ECC_K_233, ISC_ECC_K_283)
* \param x
* �Է°� ����Ű
* \param y
* �Է°� ����Ű
* \returns
* -# INI_SUCCES : ����
* -# ISC_L_ECC^ISC_F_SET_ECC_KEY_PRAMS_EX^ISC_ERR_NULL_INPUT : NULL�� �Է�
* -# ISC_L_ECC^ISC_F_SET_ECC_KEY_PRAMS_EX^ISC_ERR_SET_ECC_KEY_PARAMS_EX : Ŀ�� �Ķ���� ���� ����
* -# ISC_L_ECC^ISC_F_SET_ECC_KEY_PRAMS_EX^ISC_ERR_MEM_ALLOC : �޸� ���� �Ҵ� ����
* -# ISC_L_ECC^ISC_F_SET_ECC_KEY_PRAMS_EX^ISC_ERR_COPY_BIGINT_FAIL : COPY BIGINT ����
*/
ISC_API ISC_STATUS ISC_Set_ECC_Key_Params(ISC_ECC_KEY_UNIT *unit, const int field_id, const ISC_BIGINT* x, const ISC_ECPOINT* y);

/*!
* \brief
* ISC_ECC_KEY_UNIT �Ķ���� ���� �Լ�
* \param unit
* �������� ������ ISC_ECC_KEY_UNIT ����ü ������
* \param curve
* �Է°� curve
* \param x
* �Է°� ����Ű
* \param y
* �Է°� ����Ű
* \returns
* INI_SUCCES : ����
* ISC_F_SET_ECC_KEY_PRAMS^ISC_ERR_NULL_INPUT
*/
ISC_API ISC_STATUS ISC_Set_ECC_Key_Params_Ex(ISC_ECC_KEY_UNIT *unit, const ISC_ECURVE* curve, const ISC_BIGINT* x, const ISC_ECPOINT* y);

/*!
* \brief
* Ÿ����� �������� �̿��� ����Ű ���� (TTA ǥ�� �ؼ�)
* \param key
* �ԷµǴ� ������ ����(Ŀ��)�� �����Ǿ� �־����. ����Ű�� ��ȿ���� ������.
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_API ISC_STATUS ISC_Validate_ECC_Pub_Key(ISC_ECURVE *curve, ISC_ECPOINT *Q);

/*
* \brief
* ISC_ECC_KEY_UNIT b�� a�� ����
* \param a
* target ISC_ECC_KEY_UNIT
* \param b
* source ISC_ECC_KEY_UNIT
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_INTERNAL ISC_STATUS isc_Copy_ECC_Key(ISC_ECC_KEY_UNIT *a, const ISC_ECC_KEY_UNIT *b);

/*!
* \brief
* Ÿ��� ������ �̿��� Fixed-base comb ECSM ���� �Լ�
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param x
* Ÿ����󿡼� ���� ������ biginteger
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Mtp_ECC_Fbc(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_BIGINT *x);

/*!
* \brief
* Ÿ��� ������ �̿��� Double-and-Add ECSM ���� �Լ�
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param a
* Ÿ����󿡼� ���� ������ ��ǥ
* \param x
* Ÿ����󿡼� ���� ������ biginteger
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Mtp_ECC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* Ÿ��� ������ �̿��� Montgomery ladder ECSM ���� �Լ�
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param a
* Ÿ����󿡼� ���� ������ ��ǥ
* \param x
* Ÿ����󿡼� ���� ������ biginteger
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Mtp_ECC_Mont(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* Ÿ��� ������ �̿��� General ECADD ���� �Լ�
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param a
* Ÿ����󿡼� ���� ������ ��ǥ
* \param x
* Ÿ����󿡼� ���� ������ ��ǥ
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Add_ECC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_ECPOINT *b);

/*!
* \brief
* Ÿ��� ������ �̿��� ����ü ���� ���� �Լ�
* \param out
* ���ϵ� biginteger
* \param curve
* Ÿ���
* \param a
* ���� ������ biginteger
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Inverse_ECC(ISC_BIGINT *out, ISC_ECURVE *curve, ISC_BIGINT *a, ISC_BIGINT_POOL *pool);

/*!
* \brief
* Ÿ��� ������ �̿��� ����ü ���� ���� �Լ�
* \param out
* ���ϵ� biginteger
* \param curve
* Ÿ���
* \param a
* ���� ������ biginteger
* \param b
* ���� ������ biginteger
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Mtp_ECC(ISC_BIGINT *out, ISC_ECURVE *curve, ISC_BIGINT *a, ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* Ÿ��� ������ �̿��� ����ü ���� ���� �Լ�
* \param out
* ���ϵ� biginteger
* \param curve
* Ÿ���
* \param a
* ���� ������ biginteger
* \param b
* ���� ������ biginteger
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Add_ECC(ISC_BIGINT *out, ISC_ECURVE *curve, ISC_BIGINT *a, ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* Ÿ��� ������ �̿��� ����ü ���� ���� �Լ�
* \param out
* ���ϵ� biginteger
* \param curve
* Ÿ���
* \param a
* ���� ������ biginteger
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_ECC(ISC_BIGINT *out, ISC_ECURVE *curve, ISC_BIGINT *a, ISC_BIGINT_POOL *pool);

/*!
* \brief
* Ÿ����� �������� �̿��� Ű�� ���� (TTA ǥ�� �ؼ�)
* \param key
* �ԷµǴ� ������ ����(Ŀ��)�� �����Ǿ� �־����. ����Ű, ����Ű�� �����ؼ� �����
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Generate_ECC_Key_Pair(ISC_ECC_KEY_UNIT *key);

#ifndef ISC_CRYPTO_VS_TEST /* IUT �׽�Ʈ �Ҷ��� �ܺ��Լ��� ����. */

/*!
* \brief
* Ÿ����� �������� �̿��� ����Ű ���� (TTA ǥ�� �ؼ�)
* \param curve
* �Է°� curve
* \param d
* �Է°� ����Ű
* \param in_pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \param out
* �Էµ� ����Ű�� Ŀ�긦 �̿��Ͽ� ����Ű�� �����ؼ� ����
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Generate_ECC_Pub_Key(ISC_ECURVE *curve, ISC_BIGINT *d, ISC_BIGINT_POOL *in_pool, ISC_ECPOINT *out);
#else

ISC_API ISC_STATUS ISC_Generate_ECC_Pub_Key(ISC_ECURVE *curve, ISC_BIGINT *d, ISC_BIGINT_POOL *in_pool, ISC_ECPOINT *out);

#endif

/*!
* \brief
* Ÿ����� �������� �̿��� ����Ű ���� (TTA ǥ�� �ؼ�)
* \param curve
* �Է°� curve
* \param hash_id
* ����Ű ������ ���Ǵ� �ؽþ˰���
* \param in_oui
* �Է°� optional user input��
* \param in_oui_len 
* �Է°� in_oui�� ����
* \param in_xkey
* �Է°� xkey��
* \param in_xkey_len 
* in_xkey�� ����
* \param in_pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \param out
* ��°� �Էµ� Ŀ�긦 �̿��Ͽ� ����Ű�� ����
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS isc_Generate_ECC_Priv_Key(ISC_ECURVE *curve, int hash_id, uint8 *in_oui, int in_oui_len, uint8 *in_xkey, int in_xkey_len, ISC_BIGINT_POOL *in_pool, ISC_BIGINT *out);

/*!
* \brief
* Ÿ����� �������� �̿��� Ű�� ���� (NIST ǥ�� �ؼ�)
* \param key
* �ԷµǴ� ������ ����(Ŀ��)�� �����Ǿ� �־����. ����Ű, ����Ű�� �����ؼ� �����
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Generate_ECC_Key_Pair_NIST(ISC_ECC_KEY_UNIT *key);

/*!
* \brief
* Ÿ����� �������� �̿��� ����Ű ���� (NIST ǥ�� �ؼ�)
* \param curve
* �Է°� curve
* \param in_pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \param out
* ��°� �Էµ� Ŀ�긦 �̿��Ͽ� ����Ű�� ����
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS isc_Generate_ECC_Priv_Key_NIST(ISC_ECURVE *curve, ISC_BIGINT_POOL *in_pool, ISC_BIGINT *out);

/*!
* \brief
* Ÿ����� �������� �̿��� ����Ű ���� (TTA ǥ�� �ؼ�)
* \param curve
* �Է°� curve
* \param d
* �Է°� ����Ű
* \param out
* �Էµ� ����Ű�� Ŀ�긦 �̿��Ͽ� ����Ű�� �����ؼ� ����
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Generate_ECC_Pub_Key_NIST(ISC_ECURVE *curve, ISC_BIGINT *d, ISC_ECPOINT *out);

/*!
* \brief
* ����Ű ���� �� ���� ���Ǵ� G-Function (TTA ǥ�� �ؼ�)
* \param alg_id
* �Է°� �ؽþ˰���
* \param seed
* �Է°� seed
* \param seedLen
* �Է°� seed�� ����(byte)
* \param size
* �Է°� ��µǾ�� �� ���� ���� (bit)
* \param out
* ����� �����
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS isc_ECC_G_Function(int alg_id, uint8* seed, int seedLen, int size, ISC_BIGINT* out);


#else

ISC_RET_LOADLIB_CRYPTO(ISC_ECC_KEY_UNIT*, ISC_New_ECC_Key, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_ECC_Key, (ISC_ECC_KEY_UNIT *unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_ECC_Key, (ISC_ECC_KEY_UNIT *unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_ECC_Key_Params, (ISC_ECC_KEY_UNIT *unit, const int field_id, const ISC_BIGINT* x, const ISC_ECPOINT* y), (unit,field_id,x,y), ISC_ERR_GET_ADRESS_LOADLIBRARY);
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_ECC_Key_Params_Ex, (ISC_ECC_KEY_UNIT *unit, const ISC_ECURVE* curve, const ISC_BIGINT* x, const ISC_ECPOINT* y), (unit,curve,x,y), ISC_ERR_GET_ADRESS_LOADLIBRARY);

#endif /* ISC_WIN_LOADLIBRARY_CRYPTO */

#ifdef __cplusplus
}
#endif

#endif /* HEADER_ECC_H */
