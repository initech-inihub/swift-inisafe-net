#ifndef HEADER_POLY_EC_H
#define HEADER_POLY_EC_H

#include "poly_arith.h"
#include "ecpoint.h"
#include "ecurve.h"

/*!
* \brief
* K-233 곡선에 대한 타원곡선 연산 (Affine coordinates)
*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* K233 곡선 Affine 좌표계 ECADD
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
ISC_INTERNAL ISC_STATUS isc_Add_F2m_ECC_K233AC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_ECPOINT *b);

/*!
* \brief
* K233 곡선 Affine 좌표계 ECADD
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param a
* 타원곡선상에서 두배 연산할 좌표
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Dbl_F2m_ECC_K233AC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a);

/*!
* \brief
* K-233 곡선에 대한 타원곡선 연산 (Lopez-Dahab coordinates)
*/

/*!
* \brief
* K233 곡선 LD 좌표계 mixed ECADD
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
ISC_INTERNAL ISC_STATUS isc_Add_F2m_ECC_K233PC(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a, ISC_ECPOINT *b);

/*!
* \brief
* K233 곡선 LD 좌표계 general ECADD
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
ISC_INTERNAL ISC_STATUS isc_Add_F2m_ECC_K233PC2(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a, ISC_ECPOINT_PC *b); /* 13M + 4S */

/*!
* \brief
* K233 곡선 LD 좌표계 ECDBL
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param a
* 타원곡선상에서 두배 연산할 좌표
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Dbl_F2m_ECC_K233PC(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a);

/*!
* \brief
* K233 곡선 LD 좌표계 Double-and-Add ECSM
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
ISC_INTERNAL ISC_STATUS isc_Mtp_F2m_ECC_K233PC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* K233 곡선 LD 좌표계 Montgomery ladder ECSM
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
ISC_INTERNAL ISC_STATUS isc_Mtp_F2m_ECC_K233PC_Mont(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* K233 곡선 LD 좌표계 Fixed-base comb ECSM
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param x
* 타원곡선상에서 곱셈 연산할 biginteger
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Mtp_F2m_ECC_K233PC_Fbc(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_BIGINT *x);

/*!
* \brief
* K-283 곡선에 대한 타원곡선 연산 (Affine coordinates)
*/

/*!
* \brief
* K283 곡선 Affine 좌표계 ECADD
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
ISC_INTERNAL ISC_STATUS isc_Add_F2m_ECC_K283AC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_ECPOINT *b);

/*!
* \brief
* K283 곡선 Affine 좌표계 ECADD
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param a
* 타원곡선상에서 두배 연산할 좌표
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Dbl_F2m_ECC_K283AC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a);

/*!
* \brief
* K-283 곡선에 대한 타원곡선 연산 (Lopez-Dahab coordinates)
*/

/*!
* \brief
* K283 곡선 LD 좌표계 mixed ECADD
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
ISC_INTERNAL ISC_STATUS isc_Add_F2m_ECC_K283PC(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a, ISC_ECPOINT *b);

/*!
* \brief
* K283 곡선 LD 좌표계 general ECADD
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
ISC_INTERNAL ISC_STATUS isc_Add_F2m_ECC_K283PC2(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a, ISC_ECPOINT_PC *b); /* 13M + 4S */

/*!
* \brief
* K283 곡선 LD 좌표계 ECDBL
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param a
* 타원곡선상에서 두배 연산할 좌표
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Dbl_F2m_ECC_K283PC(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a);

/*!
* \brief
* K283 곡선 LD 좌표계 Double-and-Add ECSM
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
ISC_INTERNAL ISC_STATUS isc_Mtp_F2m_ECC_K283PC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* K283 곡선 LD 좌표계 Montgomery ladder ECSM
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
ISC_INTERNAL ISC_STATUS isc_Mtp_F2m_ECC_K283PC_Mont(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* K283 곡선 LD 좌표계 Fixed-base comb ECSM
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param x
* 타원곡선상에서 곱셈 연산할 biginteger
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Mtp_F2m_ECC_K283PC_Fbc(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_BIGINT *x);


#ifdef  __cplusplus
}
#endif

#endif /* #ifndef HEADER_POLY_EC_H */
