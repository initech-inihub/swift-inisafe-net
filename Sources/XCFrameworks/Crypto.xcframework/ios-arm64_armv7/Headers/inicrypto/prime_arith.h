#ifndef HEADER_PRIME_ARITH_H
#define HEADER_PRIME_ARITH_H

#include "biginteger.h"

/*!
* \brief
* Ÿ��� �� ���� ������ ����
*/

#define ISC_P224_WORD_SIZE			7
#define ISC_P256_WORD_SIZE			8
#define ISC_P224_WORD_DBL_SIZE		14
#define ISC_P256_WORD_DBL_SIZE		16

/*!
* \brief
* Ÿ��� �� Ÿ�� ����
*/
#define ISC_CURVE_TYPE_P224			3
#define ISC_CURVE_TYPE_P256			4

/*!
* \brief
* P-224 Ÿ��� ���� ����ü ����
*/

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* P224 ��� ����ϴ� ���� 1��Ʈ ����Ʈ ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ����Ʈ ������ ISC_BIGINT ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS isc_Right_Shift1_BIGINT_P224(ISC_BIGINT *ret, const ISC_BIGINT *a);

/*!
* \brief
* P224 ��� ����ϴ� ���� ���� �Լ�
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
ISC_INTERNAL ISC_STATUS ISC_Mtp_BIGINT_P224(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P224 ��� ����ϴ� ���� ���� �Լ�
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
ISC_INTERNAL ISC_STATUS ISC_Sqr_BIGINT_P224(ISC_BIGINT *ret, const ISC_BIGINT *a, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P224 ��� ����ϴ� ����ü ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param m
* Modulus ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS isc_Mod_BIGINT_P224(ISC_BIGINT *r, ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P224 ��� ����ϴ� ����ü ���� ���� �Լ�
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
ISC_INTERNAL ISC_STATUS ISC_Mod_Add_BIGINT_P224(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P224 ��� ����ϴ� ����ü ���� ���� �Լ�
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
ISC_INTERNAL ISC_STATUS ISC_Mod_Sub_BIGINT_P224(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P224 ��� ����ϴ� ����ü ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param m
* Modulus ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Sqr_BIGINT_P224(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL* pool);

/*!
* \brief
* P224 ��� ����ϴ� ����ü ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param b
* ���� ������ ISC_BIGINT ����ü ������
* \param m
* Modulus ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Mtp_BIGINT_P224(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, const ISC_BIGINT *m, ISC_BIGINT_POOL* pool);

/*!
* \brief
* P224 ��� ����ϴ� ����ü ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param m
* Modulus ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS isc_Mod_Inverse_BIGINT_P224(ISC_BIGINT *ret, ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P-256 Ÿ��� ���� ����ü ����
*/

/*!
* \brief
* P256 ��� ����ϴ� ���� 1��Ʈ ����Ʈ ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ����Ʈ ������ ISC_BIGINT ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS isc_Right_Shift1_BIGINT_P256(ISC_BIGINT *ret, const ISC_BIGINT *a);

/*!
* \brief
* P256 ��� ����ϴ� ���� ���� �Լ�
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
ISC_INTERNAL ISC_STATUS ISC_Mtp_BIGINT_P256(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P256 ��� ����ϴ� ���� ���� �Լ�
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
ISC_INTERNAL ISC_STATUS ISC_Sqr_BIGINT_P256(ISC_BIGINT *ret, const ISC_BIGINT *a, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P256 ��� ����ϴ� ����ü ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param m
* Modulus ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS isc_Mod_BIGINT_P256(ISC_BIGINT *r, ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P256 ��� ����ϴ� ����ü ���� ���� �Լ�
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
ISC_INTERNAL ISC_STATUS ISC_Mod_Add_BIGINT_P256(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P256 ��� ����ϴ� ����ü ���� ���� �Լ�
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
ISC_INTERNAL ISC_STATUS ISC_Mod_Sub_BIGINT_P256(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* P256 ��� ����ϴ� ����ü ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param m
* Modulus ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Sqr_BIGINT_P256(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL* pool);

/*!
* \brief
* P256 ��� ����ϴ� ����ü ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param b
* ���� ������ ISC_BIGINT ����ü ������
* \param m
* Modulus ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Mtp_BIGINT_P256(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, const ISC_BIGINT *m, ISC_BIGINT_POOL* pool);

/*!
* \brief
* P256 ��� ����ϴ� ����ü ���� ���� �Լ�
* \param ret
* ����� ISC_BIGINT ����ü ������
* \param a
* ���� ������ ISC_BIGINT ����ü ������
* \param m
* Modulus ISC_BIGINT ����ü ������
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
* \returns
* -# ISC_SUCCESS : Success
* -# others : ���� (�����ڵ�)
*/
ISC_INTERNAL ISC_STATUS isc_Mod_Inverse_BIGINT_P256(ISC_BIGINT *ret, ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

#ifdef  __cplusplus
}
#endif

#endif /* #ifndef HEADER_PRIME_ARITH_H */

