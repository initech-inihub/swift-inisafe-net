/*!
* \file ecc.h
* \brief ecc 헤더파일(파밍전용 ecc 알고리즘)
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
	int field_id;		/* 커브 ID */
	ISC_BIGINT *a;
	ISC_BIGINT *b;
	ISC_BIGINT *prime;	/* 전체 */
	ISC_ECPOINT *g;		/* 기본점(Base point), G */
	ISC_BIGINT *order;	/* 기본점 G의 위수. n. 유효한 */
	char name[ISC_ECC_CURVE_NAME_LEN];	/* 커브 이름 */
} ISC_ECURVE;

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

	/*!
	* \brief
	* ISC_ECURVE 구조체의 메모리 할당
	* \returns
	* ISC_ECURVE 구조체
	*/
	ISC_API ISC_ECURVE *ISC_New_ECURVE(void);

	/*!
	* \brief
	* ECPOINT_UNIT 메모리 해제 함수
	* \param unit
	* 메모리 해제할 ISC_ECURVE
	*/
	ISC_API void ISC_Free_ECURVE(ISC_ECURVE *unit);

	/*!
	* \brief
	* ECPOINT_UNIT 메모리 초기화 함수
	* \param unit
	* 초기화 할 ISC_ECURVE
	*/
	ISC_API void ISC_Clean_ECURVE(ISC_ECURVE *unit);

	/*!
	* \brief
	* ISC_ECURVE 에 파라메터 설정
	* \param out
	* 설정된 결과 ISC_ECURVE 값
	* \param field_id
	* 유한체의 type (예 : ISC_ECC_P_224, ISC_ECC_P_256, ISC_ECC_K_233, ISC_ECC_K_283)
	* \param name 
	* 커브의 이름 (예 : secp256r1)
	* \returns
	* INI_SUCCES : 성공
	* ISC_FAIL : 실패
	*/
	ISC_API ISC_STATUS ISC_Set_ECURVE_Params(ISC_ECURVE *out, const int field_id);

	/*!
	* \brief
	* ISC_ECURVE 에 파라메터 설정
	* \param out
	* 설정된 결과 ISC_ECURVE 값
	* \param field_id
	* 유한체의 type (예 : ISC_ECC_P_224, ISC_ECC_P_256, ISC_ECC_K_233, ISC_ECC_K_283)
	* \param name 
	* 커브의 이름 (예 : secp256r1)
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
	* INI_SUCCES : 성공
	* ISC_FAIL : 실패
	*/
	ISC_API ISC_STATUS ISC_Set_ECURVE_Params_Ex(ISC_ECURVE *out, const int field_id, const char *name, const ISC_BIGINT  *a, const ISC_BIGINT *b, const ISC_BIGINT *prime, const ISC_ECPOINT *g, const ISC_BIGINT *order);

	/*!
	* \brief
	* 커브의 길이를 리턴함 (byte)
	* \param curve
	* 입력값 curve
	* \returns
	* 0이 아닌 정수 : 성공
	* ISC_INVALID_SIZE : 실패
	*/
	ISC_API int ISC_Get_ECC_Byte_Length(ISC_ECURVE* curve);

	/*!
	* \param a
	* target curve
	* \param b
	* source curve
	* \returns
	* INI_SUCCES : 성공
	* ISC_FAIL : 실패
	*/
    ISC_INTERNAL ISC_STATUS isc_Copy_ECURVE(ISC_ECURVE *a, ISC_ECURVE *b);

	/*!
	* \brief
	* 지원하는 커브인지 확인하는 함수
	* \param curve_id
	* \returns
	* INI_SUCCES : 성공
	* ISC_FAIL : 실패
	*/
    ISC_INTERNAL int isc_Is_Supported_ECC_CURVE(int curve_id);

	/*!
	* \brief
	* 커브별 Tbit를 구함 (TTA 표준준수)
	* \param curve
	* 입력값 curve
	* \returns
	* 0이 아닌 정수 : 성공
	* ISC_INVALID_SIZE : 실패
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
