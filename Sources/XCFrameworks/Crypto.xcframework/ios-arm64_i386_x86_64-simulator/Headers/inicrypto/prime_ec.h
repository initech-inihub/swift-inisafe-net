#ifndef HEADER_PRIME_EC_H
#define HEADER_PRIME_EC_H

#include "prime_arith.h"
#include "ecurve.h"


/*!
* \brief
* P-224 곡선에 대한 타원곡선 연산 (Affine coordinates)
*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* P224 곡선 Affine 좌표계 ECADD
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param a
* 타원곡선상에서 덧셈 연산할 좌표
* \param b
* 타원곡선상에서 덧셈 연산할 좌표
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Add_Fp_ECC_P224AC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_ECPOINT *b);

/*!
* \brief
* P224 곡선 Affine 좌표계 ECDBL
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param a
* 타원곡선상에서 두배 연산할 좌표
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Dbl_Fp_ECC_P224AC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a);

/*!
* \brief
* P-224 곡선에 대한 타원곡선 연산 (Jacobian coordinates)
*/

/*!
* \brief
* P224 곡선 Jacobian 좌표계 mixed ECADD
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param a
* 타원곡선상에서 덧셈 연산할 좌표
* \param b
* 타원곡선상에서 덧셈 연산할 좌표
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Add_Fp_ECC_P224PC(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a, ISC_ECPOINT *b);

/*!
* \brief
* P224 곡선 Jacobian 좌표계 general ECADD
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param a
* 타원곡선상에서 덧셈 연산할 좌표
* \param b
* 타원곡선상에서 덧셈 연산할 좌표
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Add_Fp_ECC_P224PC2(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a, ISC_ECPOINT_PC *b);

/*!
* \brief
* P224 곡선 Jacobian 좌표계 ECDBL
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param a
* 타원곡선상에서 두배 연산할 좌표
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Dbl_Fp_ECC_P224PC(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a);

/*!
* \brief
* P224 곡선 Jacobian 좌표계 Double-and-Add ECSM
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param a
* 타원곡선상에서 곱셈 연산할 좌표
* \param x
* 타원곡선상에서 곱셈 연산할 biginteger
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Mtp_Fp_ECC_P224PC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* P224 곡선 Jacobian 좌표계 Montgomery ladder ECSM
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param a
* 타원곡선상에서 곱셈 연산할 좌표
* \param x
* 타원곡선상에서 곱셈 연산할 biginteger
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Mtp_Fp_ECC_P224PC_Mont(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* P224 곡선 Jacobian 좌표계 Fixed-base comb ECSM
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param x
* 타원곡선상에서 곱셈 연산할 biginteger
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Mtp_Fp_ECC_P224PC_Fbc(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_BIGINT *x);

/*!
* \brief
* P-256 곡선에 대한 타원곡선 연산 (Affine coordinates)
*/

/*!
* \brief
* P256 곡선 Affine 좌표계 ECADD
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param a
* 타원곡선상에서 덧셈 연산할 좌표
* \param b
* 타원곡선상에서 덧셈 연산할 좌표
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Add_Fp_ECC_P256AC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_ECPOINT *b);

/*!
* \brief
* P256 곡선 Affine 좌표계 ECDBL
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param a
* 타원곡선상에서 두배 연산할 좌표
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Dbl_Fp_ECC_P256AC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a);

/*!
* \brief
* P-256 곡선에 대한 타원곡선 연산 (Jacobian coordinates)
*/

/*!
* \brief
* P256 곡선 Jacobian 좌표계 mixed ECADD
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param a
* 타원곡선상에서 덧셈 연산할 좌표
* \param b
* 타원곡선상에서 덧셈 연산할 좌표
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Add_Fp_ECC_P256PC(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a, ISC_ECPOINT *b);

/*!
* \brief
* P256 곡선 Jacobian 좌표계 general ECADD
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param a
* 타원곡선상에서 덧셈 연산할 좌표
* \param b
* 타원곡선상에서 덧셈 연산할 좌표
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Add_Fp_ECC_P256PC2(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a, ISC_ECPOINT_PC *b);

/*!
* \brief
* P256 곡선 Jacobian 좌표계 ECDBL
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param a
* 타원곡선상에서 두배 연산할 좌표
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Dbl_Fp_ECC_P256PC(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a);

/*!
* \brief
* P256 곡선 Jacobian 좌표계 Double-and-Add ECSM
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param a
* 타원곡선상에서 곱셈 연산할 좌표
* \param x
* 타원곡선상에서 곱셈 연산할 biginteger
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Mtp_Fp_ECC_P256PC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* P256 곡선 Jacobian 좌표계 Montgomery ladder ECSM
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param a
* 타원곡선상에서 곱셈 연산할 좌표
* \param x
* 타원곡선상에서 곱셈 연산할 biginteger
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Mtp_Fp_ECC_P256PC_Mont(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* P256 곡선 Jacobian 좌표계 Fixed-base comb ECSM
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param x
* 타원곡선상에서 곱셈 연산할 biginteger
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Mtp_Fp_ECC_P256PC_Fbc(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_BIGINT *x);


#ifdef  __cplusplus
}
#endif

#endif /* #ifndef HEADER_PRIME_EC_H */

