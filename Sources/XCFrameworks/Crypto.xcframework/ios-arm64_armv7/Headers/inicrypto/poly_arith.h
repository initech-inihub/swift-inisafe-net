#ifndef HEADER_POLY_ARITH_H
#define HEADER_POLY_ARITH_H

#include "biginteger.h"

/*!
* \brief
* 타원곡선 별 워드 사이즈 설정
*/
#define ISC_K233_WORD_SIZE			8
#define ISC_K283_WORD_SIZE			9
#define ISC_K233_WORD_DBL_SIZE		16
#define ISC_K283_WORD_DBL_SIZE		18

/*!
* \brief
* 타원곡선 별 타입 설정
*/
#define ISC_CURVE_TYPE_K233			1
#define ISC_CURVE_TYPE_K283			2

/*!
* \brief
* K-233 타원곡선 하위 유한체 연산
*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* K233 곡선에 사용하는 유한체 덧셈 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 덧셈 연산할 ISC_BIGINT 구조체 포인터
* \param b
* 덧셈 연산할 ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Add_POLY_K233(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* K233 곡선에 사용하는 곱셈 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 곱셈 연산할 ISC_BIGINT 구조체 포인터
* \param b
* 곱셈 연산할 ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Mtp_POLY_K233(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* K233 곡선에 사용하는 제곱 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 제곱 연산할 ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Sqr_POLY_K233(ISC_BIGINT *ret, const ISC_BIGINT *a, ISC_BIGINT_POOL *pool);

/*!
* \brief
* K233 곡선에 사용하는 유한체 감산 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 감산 연산할 ISC_BIGINT 구조체 포인터
* \param m
* 기약다항식 ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS isc_Mod_POLY_K233(ISC_BIGINT *ret, ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

/*!
* \brief
* K233 곡선에 사용하는 유한체 곱셈 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 곱셈 연산할 ISC_BIGINT 구조체 포인터
* \param b
* 곱셈 연산할 ISC_BIGINT 구조체 포인터
* \param m
* 기약다항식 ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Mtp_POLY_K233(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, const ISC_BIGINT *m, ISC_BIGINT_POOL* pool);

/*!
* \brief
* K233 곡선에 사용하는 유한체 제곱 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 제곱 연산할 ISC_BIGINT 구조체 포인터
* \param m
* 기약다항식 ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Sqr_POLY_K233(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL* pool);

/*!
* \brief
* K233 곡선에 사용하는 유한체 역원 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 역원 연산할 ISC_BIGINT 구조체 포인터
* \param m
* 기약다항식 ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS isc_Mod_Inverse_POLY_K233(ISC_BIGINT *ret, ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

/*!
* \brief
* K-283 타원곡선 하위 유한체 연산
*/

/*!
* \brief
* K283 곡선에 사용하는 유한체 덧셈 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 덧셈 연산할 ISC_BIGINT 구조체 포인터
* \param b
* 덧셈 연산할 ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Add_POLY_K283(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* K283 곡선에 사용하는 곱셈 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 곱셈 연산할 ISC_BIGINT 구조체 포인터
* \param b
* 곱셈 연산할 ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Mtp_POLY_K283(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* K283 곡선에 사용하는 제곱 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 제곱 연산할 ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Sqr_POLY_K283(ISC_BIGINT *ret, const ISC_BIGINT *a, ISC_BIGINT_POOL *pool);

/*!
* \brief
* K283 곡선에 사용하는 유한체 감산 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 감산 연산할 ISC_BIGINT 구조체 포인터
* \param m
* 기약다항식 ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS isc_Mod_POLY_K283(ISC_BIGINT *ret, ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

/*!
* \brief
* K283 곡선에 사용하는 유한체 곱셈 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 곱셈 연산할 ISC_BIGINT 구조체 포인터
* \param b
* 곱셈 연산할 ISC_BIGINT 구조체 포인터
* \param m
* 기약다항식 ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Mtp_POLY_K283(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, const ISC_BIGINT *m, ISC_BIGINT_POOL* pool);

/*!
* \brief
* K283 곡선에 사용하는 유한체 제곱 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 제곱 연산할 ISC_BIGINT 구조체 포인터
* \param m
* 기약다항식 ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Sqr_POLY_K283(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL* pool);

/*!
* \brief
* K283 곡선에 사용하는 유한체 역원 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 역원 연산할 ISC_BIGINT 구조체 포인터
* \param m
* 기약다항식 ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS isc_Mod_Inverse_POLY_K283(ISC_BIGINT *ret, ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

#ifdef  __cplusplus
}
#endif

#endif /* #ifndef HEADER_POLY_ARITH_H */
