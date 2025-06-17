/*!
* \file ecc.h
* \brief ecc �������(�Ĺ����� ecc �˰���)
* \author
* Copyright (c) 2013 by \<INITech\>
*/

#ifndef HEADER_ECURVE_H
#define HEADER_ECURVE_H

#if defined(ISC_NO_ECC) || defined(ISC_NO_SHA)
#define NO_ECURVE
#error ISC_ECURVE is disabled.
#endif

#ifdef NO_ECURVE
#error ISC_ECURVE is disabled.
#endif /* NO_ECURVE */

#include "biginteger.h"
#include "digest.h"
#include "foundation.h"
#include "ecpoint.h"

#define ISC_ECC_NO_FINITE_FIELD		0x00000000
#define ISC_ECC_FINITE_FIELD_FP		0x000000FF
#define ISC_ECC_P_224				0x00000001
#define ISC_ECC_P_256				0x00000002
#define ISC_ECC_FINITE_FIELD_F2M	0x0000FF00
#define ISC_ECC_K_233				0x00000100
#define ISC_ECC_K_283				0x00000200
#define ISC_ECC_FINITE_FIELD_FPM	0x00FF0000

#define ISC_ECC_CURVE_NAME_LEN		32
#define ISC_ECC_MAX_SIZE			72

typedef struct isc_ecurve_st
{
	int field_id;		/* Ŀ�� ID */
	ISC_BIGINT *a;
	ISC_BIGINT *b;
	ISC_BIGINT *prime;	/* ��ü */
	ISC_ECPOINT *g;		/* �⺻��(Base point), G */
	ISC_BIGINT *order;	/* �⺻�� G�� ����. n. ��ȿ�� */
	char name[ISC_ECC_CURVE_NAME_LEN];	/* Ŀ�� �̸� */
} ISC_ECURVE;

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

	/*!
	* \brief
	* ISC_ECURVE ����ü�� �޸� �Ҵ�
	* \returns
	* ISC_ECURVE ����ü
	*/
	ISC_API ISC_ECURVE *ISC_New_ECURVE(void);

	/*!
	* \brief
	* ECPOINT_UNIT �޸� ���� �Լ�
	* \param unit
	* �޸� ������ ISC_ECURVE
	*/
	ISC_API void ISC_Free_ECURVE(ISC_ECURVE *unit);

	/*!
	* \brief
	* ECPOINT_UNIT �޸� �ʱ�ȭ �Լ�
	* \param unit
	* �ʱ�ȭ �� ISC_ECURVE
	*/
	ISC_API void ISC_Clean_ECURVE(ISC_ECURVE *unit);

	/*!
	* \brief
	* ISC_ECURVE �� �Ķ���� ����
	* \param out
	* ������ ��� ISC_ECURVE ��
	* \param field_id
	* ����ü�� type (�� : ISC_ECC_P_224, ISC_ECC_P_256, ISC_ECC_K_233, ISC_ECC_K_283)
	* \param name 
	* Ŀ���� �̸� (�� : secp256r1)
	* \returns
	* INI_SUCCES : ����
	* ISC_FAIL : ����
	*/
	ISC_API ISC_STATUS ISC_Set_ECURVE_Params(ISC_ECURVE *out, const int field_id);

	/*!
	* \brief
	* ISC_ECURVE �� �Ķ���� ����
	* \param out
	* ������ ��� ISC_ECURVE ��
	* \param field_id
	* ����ü�� type (�� : ISC_ECC_P_224, ISC_ECC_P_256, ISC_ECC_K_233, ISC_ECC_K_283)
	* \param name 
	* Ŀ���� �̸� (�� : secp256r1)
	* \param a
	* ISC_BIGINT a
	* \param b
	* ISC_BIGINT b
	* \param prime
	* ISC_BIGINT prime
	* \param g
	* ISC_ECPOINT g
	* \param order
	* ISC_ECPOINT order
	* \returns
	* INI_SUCCES : ����
	* ISC_FAIL : ����
	*/
	ISC_API ISC_STATUS ISC_Set_ECURVE_Params_Ex(ISC_ECURVE *out, const int field_id, const char *name, const ISC_BIGINT  *a, const ISC_BIGINT *b, const ISC_BIGINT *prime, const ISC_ECPOINT *g, const ISC_BIGINT *order);

	/*!
	* \brief
	* Ŀ���� ���̸� ������ (byte)
	* \param curve
	* �Է°� curve
	* \returns
	* 0�� �ƴ� ���� : ����
	* ISC_INVALID_SIZE : ����
	*/
	ISC_API int ISC_Get_ECC_Byte_Length(ISC_ECURVE* curve);

	/*!
	* \param a
	* target curve
	* \param b
	* source curve
	* \returns
	* INI_SUCCES : ����
	* ISC_FAIL : ����
	*/
    ISC_INTERNAL ISC_STATUS isc_Copy_ECURVE(ISC_ECURVE *a, ISC_ECURVE *b);

	/*!
	* \brief
	* �����ϴ� Ŀ������ Ȯ���ϴ� �Լ�
	* \param curve_id
	* \returns
	* INI_SUCCES : ����
	* ISC_FAIL : ����
	*/
    ISC_INTERNAL int isc_Is_Supported_ECC_CURVE(int curve_id);

	/*!
	* \brief
	* Ŀ�꺰 Tbit�� ���� (TTA ǥ���ؼ�)
	* \param curve
	* �Է°� curve
	* \returns
	* 0�� �ƴ� ���� : ����
	* ISC_INVALID_SIZE : ����
	*/
    ISC_INTERNAL int isc_Get_ECC_Tbit_Length(ISC_ECURVE *curve);

#else

	ISC_RET_LOADLIB_CRYPTO(ISC_ECURVE*, ISC_New_ECURVE, (void), (), NULL );
	ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_ECURVE, (ISC_ECURVE *unit), (unit) );
	ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_ECURVE, (ISC_ECURVE *unit), (unit) );
	ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, isc_Copy_ECURVE, (ISC_ECURVE *a, const ISC_ECURVE *b), (a, b), ISC_ERR_GET_ADRESS_LOADLIBRARY);
	ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_ECURVE_Params, (ISC_ECURVE *out, const int field_id), (out, field_id), ISC_ERR_GET_ADRESS_LOADLIBRARY);
	ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_ECURVE_Params_Ex, (ISC_ECURVE *out, int field_id, char *name, ISC_BIGINT  *a, ISC_BIGINT *b, ISC_BIGINT *prime, ISC_ECPOINT *g, ISC_BIGINT *order), (out, field_id, name, a, b, prime, g, order), ISC_ERR_GET_ADRESS_LOADLIBRARY);
	ISC_RET_LOADLIB_CRYPTO(int, ISC_Get_ECC_Byte_Length, (ISC_ECURVE* curve), (curve), 0 );

#endif /* ISC_WIN_LOADLIBRARY_CRYPTO */

#ifdef __cplusplus
}
#endif

#endif /* HEADER_ECURVE_H */
