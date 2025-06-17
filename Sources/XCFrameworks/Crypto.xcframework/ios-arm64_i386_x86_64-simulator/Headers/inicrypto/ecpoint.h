/*!
* \file ecc.h
* \brief ecc �������(�Ĺ����� ecc �˰���)
* \author
* Copyright (c) 2013 by \<INITech\>
*/

#ifndef HEADER_ECPOINT_H
#define HEADER_ECPOINT_H

#if defined(ISC_NO_ECC)
#define ISC_NO_ECPOINT
#error ECC is disabled.
#endif

#ifdef ISC_NO_ECPOINT
#error ISC_ECPOINT is disabled.
#endif /* #ifdef ISC_NO_ECPOINT */

#include "biginteger.h"
#include "digest.h"
#include "foundation.h"

typedef struct isc_ecpoint_st
{
	ISC_BIGINT *x;
	ISC_BIGINT *y;
	int inf;		/* ���ѿ��� ���� (���ѿ��� : ISC_EC_INF_TRUE, �ƴҶ� : ISC_EC_INF_FALSE) */
} ISC_ECPOINT;

typedef struct isc_ecpoint_pc_st
{
	ISC_BIGINT *X;
	ISC_BIGINT *Y;
	ISC_BIGINT *Z;
	int inf;
} ISC_ECPOINT_PC;

#define ISC_EC_INF_FALSE	0
#define ISC_EC_INF_TRUE		1

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_ECPOINT ����ü�� �޸� �Ҵ�
* \returns
* ISC_ECPOINT ����ü
*/
ISC_API ISC_ECPOINT *ISC_New_ECPOINT(void);

/*!
* \brief
* ISC_ECPOINT �޸� ���� �Լ�
* \param unit
* �޸� ������ ISC_ECPOINT
*/
ISC_API void ISC_Free_ECPOINT(ISC_ECPOINT *unit);

/*!
* \brief
* ISC_ECPOINT �޸� �ʱ�ȭ �Լ�
* \param unit
* �ʱ�ȭ �� ISC_ECPOINT
*/
ISC_API void ISC_Clean_ECPOINT(ISC_ECPOINT *unit);

/*
* \brief
* �Էµ� b��ǥ�� a�� ����
* \param a
* target ��ǥ
* \param b
* source ��ǥ
* \returns
* INI_SUCCES : ����
* ISC_FAIL : ����
*/
ISC_INTERNAL ISC_STATUS isc_Copy_ECPOINT(ISC_ECPOINT *a, const ISC_ECPOINT *b);

/*!
* \brief
* ISC_ECPOINT_PC ����ü�� �޸� �Ҵ�
* \returns
* ISC_ECPOINT_PC ����ü
*/
ISC_INTERNAL ISC_ECPOINT_PC *ISC_New_ECPOINT_PC(void);

/*!
* \brief
* ISC_ECPOINT_PC �޸� ���� �Լ�
* \param unit
* �޸� ������ ISC_ECPOINT_PC
*/
ISC_INTERNAL void ISC_Free_ECPOINT_PC(ISC_ECPOINT_PC *unit);

/*!
* \brief
* ISC_ECPOINT_PC �޸� �ʱ�ȭ �Լ�
* \param unit
* �ʱ�ȭ �� ISC_ECPOINT_PC
*/
ISC_INTERNAL void ISC_Clean_ECPOINT_PC(ISC_ECPOINT_PC *unit);

#else

ISC_RET_LOADLIB_CRYPTO(ISC_ECPOINT*, ISC_New_ECPOINT, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_ECPOINT, (ISC_ECPOINT *unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_ECPOINT, (ISC_ECPOINT *unit), (unit) );

#endif /* ISC_WIN_LOADLIBRARY_CRYPTO */

#ifdef __cplusplus
}
#endif

#endif /* HEADER_ECC_H */
