#ifndef HEADER_PRIME_ARITH_H
#define HEADER_PRIME_ARITH_H

#include "biginteger.h"

/*!
* \brief
* 타원곡선 별 워드 사이즈 설정
*/

#define ISC_P224_WORD_SIZE			7
#define ISC_P256_WORD_SIZE			8
#define ISC_P224_WORD_DBL_SIZE		14
#define ISC_P256_WORD_DBL_SIZE		16

/*!
* \brief
* 타원곡선 별 타입 설정
*/
#define ISC_CURVE_TYPE_P224			3
#define ISC_CURVE_TYPE_P256			4

/*!
* \brief
* P-224 타원곡선 하위 유한체 연산
*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* P224 곡선에 사용하는 우측 1비트 시프트 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 시프트 연산할 ISC_BIGINT 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS isc_Right_Shift1_BIGINT_P224(ISC_BIGINT *ret, const ISC_BIGINT *a);

/*!
* \brief
* P224 곡선에 사용하는 곱셈 연산 함수
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
ISC_INTERNAL ISC_STATUS ISC_Mtp_BIGINT_P224(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P224 곡선에 사용하는 제곱 연산 함수
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
ISC_INTERNAL ISC_STATUS ISC_Sqr_BIGINT_P224(ISC_BIGINT *ret, const ISC_BIGINT *a, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P224 곡선에 사용하는 유한체 감산 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 감산 연산할 ISC_BIGINT 구조체 포인터
* \param m
* Modulus ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS isc_Mod_BIGINT_P224(ISC_BIGINT *r, ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P224 곡선에 사용하는 유한체 덧셈 연산 함수
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
ISC_INTERNAL ISC_STATUS ISC_Mod_Add_BIGINT_P224(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P224 곡선에 사용하는 유한체 뺄셈 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 뺄셈 연산할 ISC_BIGINT 구조체 포인터
* \param b
* 뺄셈 연산할 ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Sub_BIGINT_P224(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P224 곡선에 사용하는 유한체 제곱 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 제곱 연산할 ISC_BIGINT 구조체 포인터
* \param m
* Modulus ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Sqr_BIGINT_P224(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL* pool);

/*!
* \brief
* P224 곡선에 사용하는 유한체 곱셈 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 곱셈 연산할 ISC_BIGINT 구조체 포인터
* \param b
* 곱셈 연산할 ISC_BIGINT 구조체 포인터
* \param m
* Modulus ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Mtp_BIGINT_P224(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, const ISC_BIGINT *m, ISC_BIGINT_POOL* pool);

/*!
* \brief
* P224 곡선에 사용하는 유한체 역원 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 곱셈 연산할 ISC_BIGINT 구조체 포인터
* \param m
* Modulus ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS isc_Mod_Inverse_BIGINT_P224(ISC_BIGINT *ret, ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P-256 타원곡선 하위 유한체 연산
*/

/*!
* \brief
* P256 곡선에 사용하는 우측 1비트 시프트 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 시프트 연산할 ISC_BIGINT 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS isc_Right_Shift1_BIGINT_P256(ISC_BIGINT *ret, const ISC_BIGINT *a);

/*!
* \brief
* P256 곡선에 사용하는 곱셈 연산 함수
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
ISC_INTERNAL ISC_STATUS ISC_Mtp_BIGINT_P256(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P256 곡선에 사용하는 제곱 연산 함수
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
ISC_INTERNAL ISC_STATUS ISC_Sqr_BIGINT_P256(ISC_BIGINT *ret, const ISC_BIGINT *a, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P256 곡선에 사용하는 유한체 감산 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 감산 연산할 ISC_BIGINT 구조체 포인터
* \param m
* Modulus ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS isc_Mod_BIGINT_P256(ISC_BIGINT *r, ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P256 곡선에 사용하는 유한체 덧셈 연산 함수
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
ISC_INTERNAL ISC_STATUS ISC_Mod_Add_BIGINT_P256(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P256 곡선에 사용하는 유한체 뺄셈 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 뺄셈 연산할 ISC_BIGINT 구조체 포인터
* \param b
* 뺄셈 연산할 ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Sub_BIGINT_P256(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P256 곡선에 사용하는 유한체 제곱 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 제곱 연산할 ISC_BIGINT 구조체 포인터
* \param m
* Modulus ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Sqr_BIGINT_P256(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL* pool);

/*!
* \brief
* P256 곡선에 사용하는 유한체 곱셈 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 곱셈 연산할 ISC_BIGINT 구조체 포인터
* \param b
* 곱셈 연산할 ISC_BIGINT 구조체 포인터
* \param m
* Modulus ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Mtp_BIGINT_P256(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, const ISC_BIGINT *m, ISC_BIGINT_POOL* pool);

/*!
* \brief
* P256 곡선에 사용하는 유한체 역원 연산 함수
* \param ret
* 결과값 ISC_BIGINT 구조체 포인터
* \param a
* 곱셈 연산할 ISC_BIGINT 구조체 포인터
* \param m
* Modulus ISC_BIGINT 구조체 포인터
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS isc_Mod_Inverse_BIGINT_P256(ISC_BIGINT *ret, ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

#ifdef  __cplusplus
}
#endif

#endif /* #ifndef HEADER_PRIME_ARITH_H */

