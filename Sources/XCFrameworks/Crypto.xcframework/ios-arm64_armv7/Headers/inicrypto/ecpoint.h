/*!
* \file ecc.h
* \brief ecc 헤더파일(파밍전용 ecc 알고리즘)
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
	int inf;		/* 무한원점 상태 (무한원점 : ISC_EC_INF_TRUE, 아닐때 : ISC_EC_INF_FALSE) */
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
* ISC_ECPOINT 구조체의 메모리 할당
* \returns
* ISC_ECPOINT 구조체
*/
ISC_API ISC_ECPOINT *ISC_New_ECPOINT(void);

/*!
* \brief
* ISC_ECPOINT 메모리 해제 함수
* \param unit
* 메모리 해제할 ISC_ECPOINT
*/
ISC_API void ISC_Free_ECPOINT(ISC_ECPOINT *unit);

/*!
* \brief
* ISC_ECPOINT 메모리 초기화 함수
* \param unit
* 초기화 할 ISC_ECPOINT
*/
ISC_API void ISC_Clean_ECPOINT(ISC_ECPOINT *unit);

/*
* \brief
* 입력된 b좌표를 a에 복사
* \param a
* target 좌표
* \param b
* source 좌표
* \returns
* INI_SUCCES : 성공
* ISC_FAIL : 실패
*/
ISC_INTERNAL ISC_STATUS isc_Copy_ECPOINT(ISC_ECPOINT *a, const ISC_ECPOINT *b);

/*!
* \brief
* ISC_ECPOINT_PC 구조체의 메모리 할당
* \returns
* ISC_ECPOINT_PC 구조체
*/
ISC_INTERNAL ISC_ECPOINT_PC *ISC_New_ECPOINT_PC(void);

/*!
* \brief
* ISC_ECPOINT_PC 메모리 해제 함수
* \param unit
* 메모리 해제할 ISC_ECPOINT_PC
*/
ISC_INTERNAL void ISC_Free_ECPOINT_PC(ISC_ECPOINT_PC *unit);

/*!
* \brief
* ISC_ECPOINT_PC 메모리 초기화 함수
* \param unit
* 초기화 할 ISC_ECPOINT_PC
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
