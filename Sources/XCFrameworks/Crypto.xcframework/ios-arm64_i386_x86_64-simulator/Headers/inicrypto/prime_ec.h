#ifndef HEADER_PRIME_EC_H
#define HEADER_PRIME_EC_H

#include "prime_arith.h"
#include "ecurve.h"


/*!
* \brief
* P-224 ��� ���� Ÿ��� ���� (Affine coordinates)
*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* P224 � Affine ��ǥ�� ECADD
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param a
* Ÿ����󿡼� ���� ������ ��ǥ
* \param b
* Ÿ����󿡼� ���� ������ ��ǥ
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Add_Fp_ECC_P224AC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_ECPOINT *b);

/*!
* \brief
* P224 � Affine ��ǥ�� ECDBL
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param a
* Ÿ����󿡼� �ι� ������ ��ǥ
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Dbl_Fp_ECC_P224AC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a);

/*!
* \brief
* P-224 ��� ���� Ÿ��� ���� (Jacobian coordinates)
*/

/*!
* \brief
* P224 � Jacobian ��ǥ�� mixed ECADD
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param a
* Ÿ����󿡼� ���� ������ ��ǥ
* \param b
* Ÿ����󿡼� ���� ������ ��ǥ
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Add_Fp_ECC_P224PC(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a, ISC_ECPOINT *b);

/*!
* \brief
* P224 � Jacobian ��ǥ�� general ECADD
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param a
* Ÿ����󿡼� ���� ������ ��ǥ
* \param b
* Ÿ����󿡼� ���� ������ ��ǥ
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Add_Fp_ECC_P224PC2(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a, ISC_ECPOINT_PC *b);

/*!
* \brief
* P224 � Jacobian ��ǥ�� ECDBL
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param a
* Ÿ����󿡼� �ι� ������ ��ǥ
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Dbl_Fp_ECC_P224PC(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a);

/*!
* \brief
* P224 � Jacobian ��ǥ�� Double-and-Add ECSM
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
*/
ISC_INTERNAL ISC_STATUS isc_Mtp_Fp_ECC_P224PC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* P224 � Jacobian ��ǥ�� Montgomery ladder ECSM
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
*/
ISC_INTERNAL ISC_STATUS isc_Mtp_Fp_ECC_P224PC_Mont(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* P224 � Jacobian ��ǥ�� Fixed-base comb ECSM
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param x
* Ÿ����󿡼� ���� ������ biginteger
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Mtp_Fp_ECC_P224PC_Fbc(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_BIGINT *x);

/*!
* \brief
* P-256 ��� ���� Ÿ��� ���� (Affine coordinates)
*/

/*!
* \brief
* P256 � Affine ��ǥ�� ECADD
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param a
* Ÿ����󿡼� ���� ������ ��ǥ
* \param b
* Ÿ����󿡼� ���� ������ ��ǥ
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Add_Fp_ECC_P256AC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_ECPOINT *b);

/*!
* \brief
* P256 � Affine ��ǥ�� ECDBL
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param a
* Ÿ����󿡼� �ι� ������ ��ǥ
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Dbl_Fp_ECC_P256AC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a);

/*!
* \brief
* P-256 ��� ���� Ÿ��� ���� (Jacobian coordinates)
*/

/*!
* \brief
* P256 � Jacobian ��ǥ�� mixed ECADD
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param a
* Ÿ����󿡼� ���� ������ ��ǥ
* \param b
* Ÿ����󿡼� ���� ������ ��ǥ
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Add_Fp_ECC_P256PC(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a, ISC_ECPOINT *b);

/*!
* \brief
* P256 � Jacobian ��ǥ�� general ECADD
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param a
* Ÿ����󿡼� ���� ������ ��ǥ
* \param b
* Ÿ����󿡼� ���� ������ ��ǥ
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Add_Fp_ECC_P256PC2(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a, ISC_ECPOINT_PC *b);

/*!
* \brief
* P256 � Jacobian ��ǥ�� ECDBL
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param a
* Ÿ����󿡼� �ι� ������ ��ǥ
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Dbl_Fp_ECC_P256PC(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a);

/*!
* \brief
* P256 � Jacobian ��ǥ�� Double-and-Add ECSM
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
*/
ISC_INTERNAL ISC_STATUS isc_Mtp_Fp_ECC_P256PC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* P256 � Jacobian ��ǥ�� Montgomery ladder ECSM
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
*/
ISC_INTERNAL ISC_STATUS isc_Mtp_Fp_ECC_P256PC_Mont(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* P256 � Jacobian ��ǥ�� Fixed-base comb ECSM
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param x
* Ÿ����󿡼� ���� ������ biginteger
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Mtp_Fp_ECC_P256PC_Fbc(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_BIGINT *x);


#ifdef  __cplusplus
}
#endif

#endif /* #ifndef HEADER_PRIME_EC_H */

