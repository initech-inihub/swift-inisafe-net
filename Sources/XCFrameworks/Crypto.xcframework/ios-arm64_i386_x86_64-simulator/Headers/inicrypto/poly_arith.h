#ifndef HEADER_POLY_ARITH_H
#define HEADER_POLY_ARITH_H

#include "biginteger.h"

/*!
* \brief
* Ÿ��� �� ���� ������ ����
*/
#define ISC_K233_WORD_SIZE			8
#define ISC_K283_WORD_SIZE			9
#define ISC_K233_WORD_DBL_SIZE		16
#define ISC_K283_WORD_DBL_SIZE		18

/*!
* \brief
* Ÿ��� �� Ÿ�� ����
*/
#define ISC_CURVE_TYPE_K233			1
#define ISC_CURVE_TYPE_K283			2

/*!
* \brief
* K-233 Ÿ��� ���� ����ü ����
*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* K233 ��� ����ϴ� ����ü ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param b
* ���� ������ ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Add_POLY_K233(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* K233 ��� ����ϴ� ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param b
* ���� ������ ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Mtp_POLY_K233(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* K233 ��� ����ϴ� ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Sqr_POLY_K233(ISC_BIGINT *ret, const ISC_BIGINT *a, ISC_BIGINT_POOL *pool);

/*!
* \brief
* K233 ��� ����ϴ� ����ü ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param m
* �����׽� ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS isc_Mod_POLY_K233(ISC_BIGINT *ret, ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

/*!
* \brief
* K233 ��� ����ϴ� ����ü ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param b
* ���� ������ ISC_BIGINT ����ü ������
* \param m
* �����׽� ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Mtp_POLY_K233(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, const ISC_BIGINT *m, ISC_BIGINT_POOL* pool);

/*!
* \brief
* K233 ��� ����ϴ� ����ü ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param m
* �����׽� ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Sqr_POLY_K233(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL* pool);

/*!
* \brief
* K233 ��� ����ϴ� ����ü ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param m
* �����׽� ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS isc_Mod_Inverse_POLY_K233(ISC_BIGINT *ret, ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

/*!
* \brief
* K-283 Ÿ��� ���� ����ü ����
*/

/*!
* \brief
* K283 ��� ����ϴ� ����ü ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param b
* ���� ������ ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Add_POLY_K283(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* K283 ��� ����ϴ� ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param b
* ���� ������ ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Mtp_POLY_K283(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* K283 ��� ����ϴ� ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Sqr_POLY_K283(ISC_BIGINT *ret, const ISC_BIGINT *a, ISC_BIGINT_POOL *pool);

/*!
* \brief
* K283 ��� ����ϴ� ����ü ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param m
* �����׽� ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS isc_Mod_POLY_K283(ISC_BIGINT *ret, ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

/*!
* \brief
* K283 ��� ����ϴ� ����ü ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param b
* ���� ������ ISC_BIGINT ����ü ������
* \param m
* �����׽� ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Mtp_POLY_K283(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, const ISC_BIGINT *m, ISC_BIGINT_POOL* pool);

/*!
* \brief
* K283 ��� ����ϴ� ����ü ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param m
* �����׽� ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Sqr_POLY_K283(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL* pool);

/*!
* \brief
* K283 ��� ����ϴ� ����ü ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param m
* �����׽� ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS isc_Mod_Inverse_POLY_K283(ISC_BIGINT *ret, ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

#ifdef  __cplusplus
}
#endif

#endif /* #ifndef HEADER_POLY_ARITH_H */
