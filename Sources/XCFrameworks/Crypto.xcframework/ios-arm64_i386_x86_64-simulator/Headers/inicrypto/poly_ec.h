#ifndef HEADER_POLY_EC_H
#define HEADER_POLY_EC_H

#include "poly_arith.h"
#include "ecpoint.h"
#include "ecurve.h"

/*!
* \brief
* K-233 ��� ���� Ÿ��� ���� (Affine coordinates)
*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* K233 � Affine ��ǥ�� ECADD
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
ISC_INTERNAL ISC_STATUS isc_Add_F2m_ECC_K233AC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_ECPOINT *b);

/*!
* \brief
* K233 � Affine ��ǥ�� ECADD
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param a
* Ÿ����󿡼� �ι� ������ ��ǥ
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Dbl_F2m_ECC_K233AC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a);

/*!
* \brief
* K-233 ��� ���� Ÿ��� ���� (Lopez-Dahab coordinates)
*/

/*!
* \brief
* K233 � LD ��ǥ�� mixed ECADD
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
ISC_INTERNAL ISC_STATUS isc_Add_F2m_ECC_K233PC(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a, ISC_ECPOINT *b);

/*!
* \brief
* K233 � LD ��ǥ�� general ECADD
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
ISC_INTERNAL ISC_STATUS isc_Add_F2m_ECC_K233PC2(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a, ISC_ECPOINT_PC *b); /* 13M + 4S */

/*!
* \brief
* K233 � LD ��ǥ�� ECDBL
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param a
* Ÿ����󿡼� �ι� ������ ��ǥ
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Dbl_F2m_ECC_K233PC(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a);

/*!
* \brief
* K233 � LD ��ǥ�� Double-and-Add ECSM
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
ISC_INTERNAL ISC_STATUS isc_Mtp_F2m_ECC_K233PC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* K233 � LD ��ǥ�� Montgomery ladder ECSM
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
ISC_INTERNAL ISC_STATUS isc_Mtp_F2m_ECC_K233PC_Mont(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* K233 � LD ��ǥ�� Fixed-base comb ECSM
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param x
* Ÿ����󿡼� ���� ������ biginteger
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Mtp_F2m_ECC_K233PC_Fbc(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_BIGINT *x);

/*!
* \brief
* K-283 ��� ���� Ÿ��� ���� (Affine coordinates)
*/

/*!
* \brief
* K283 � Affine ��ǥ�� ECADD
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
ISC_INTERNAL ISC_STATUS isc_Add_F2m_ECC_K283AC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_ECPOINT *b);

/*!
* \brief
* K283 � Affine ��ǥ�� ECADD
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param a
* Ÿ����󿡼� �ι� ������ ��ǥ
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Dbl_F2m_ECC_K283AC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a);

/*!
* \brief
* K-283 ��� ���� Ÿ��� ���� (Lopez-Dahab coordinates)
*/

/*!
* \brief
* K283 � LD ��ǥ�� mixed ECADD
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
ISC_INTERNAL ISC_STATUS isc_Add_F2m_ECC_K283PC(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a, ISC_ECPOINT *b);

/*!
* \brief
* K283 � LD ��ǥ�� general ECADD
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
ISC_INTERNAL ISC_STATUS isc_Add_F2m_ECC_K283PC2(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a, ISC_ECPOINT_PC *b); /* 13M + 4S */

/*!
* \brief
* K283 � LD ��ǥ�� ECDBL
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param a
* Ÿ����󿡼� �ι� ������ ��ǥ
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Dbl_F2m_ECC_K283PC(ISC_ECPOINT_PC *out, ISC_ECURVE *curve, ISC_ECPOINT_PC *a);

/*!
* \brief
* K283 � LD ��ǥ�� Double-and-Add ECSM
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
ISC_INTERNAL ISC_STATUS isc_Mtp_F2m_ECC_K283PC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* K283 � LD ��ǥ�� Montgomery ladder ECSM
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
ISC_INTERNAL ISC_STATUS isc_Mtp_F2m_ECC_K283PC_Mont(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* K283 � LD ��ǥ�� Fixed-base comb ECSM
* \param out
* ���ϵ� ��ǥ
* \param curve
* Ÿ���
* \param x
* Ÿ����󿡼� ���� ������ biginteger
* \returns
* -# ISC_SUCCESS : Success
*/
ISC_INTERNAL ISC_STATUS isc_Mtp_F2m_ECC_K283PC_Fbc(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_BIGINT *x);


#ifdef  __cplusplus
}
#endif

#endif /* #ifndef HEADER_POLY_EC_H */
