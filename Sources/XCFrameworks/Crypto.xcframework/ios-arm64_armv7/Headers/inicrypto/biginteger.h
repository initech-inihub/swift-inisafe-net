
/*!
* \file biginteger.h
* \brief
* POSITIVE INTEGER�� �ٷ�� Big Integer Ÿ�԰� ���� ������ ����
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_BIGINT_H
#define HEADER_BIGINT_H

#include "foundation.h"
#include "mem.h"
#include "drbg.h"

#ifndef ISC_NO_PRNG
#include "prng.h"
#endif

#ifdef ISC_NO_BIGINT
#error ISC_BIGINT is disabled.
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#define ISC_BIGINT_POOL_SIZE 8 /*!<  ISC_BIGINT_POOL �ʱ� �Ҵ� ���� */

	/*!
	* \brief
	* BigInteger ����ü
	*/
	struct isc_big_integer_st
	{
		uintptr *data; /*!< Big Integer ������*/
		int index;   /*!< Big Integer Array�� Index*/
		int length;  /*!< Big Integer Array�� ����*/
		int status;  /*!< Big Integer ����ü�� ���� ����*/
	};

	/*!
	* \brief
	* BigInteger Montgomery multiplication algorithms ����ü
	*/
	struct isc_big_integer_mont_st
	{
		int ri;
		ISC_BIGINT rr;
		ISC_BIGINT n;
		ISC_BIGINT ni;
		uintptr n0;
	};

	/*!
	* \brief
	* BigInteger Pool Item ����ü
	*/
	struct isc_big_integer_pool_item_st
	{
		ISC_BIGINT vals[ISC_BIGINT_POOL_SIZE + 1];
		struct isc_big_integer_pool_item_st *prev, *next;
	};

	/*!
	* \brief
	* BigInteger Pool ����ü
	*/
	struct isc_big_integer_pool_st
	{
		ISC_BIGINT_POOL_ITEM *head, *current, *tail;
		uint32 used, size;
		uint32 st[80];
		int32 st_index;
	};

	/*!
	* \brief
	* ISC_BIGINT_POOL ���� ���� ISC_BIGINT ��ȯ
	* \param pool
	* ����� ISC_BIGINT_POOL
	* \param num
	* ��ȯ�� ISC_BIGINT ����
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
ISC_INTERNAL ISC_STATUS isc_Release_BIGINT_POOL(ISC_BIGINT_POOL *pool, unsigned int num);


#define ISC_BIGINT_NEW			0x01  /*!<  ISC_BIGINT�� �޸� �Ҵ� ��*/
#define ISC_BIGINT_HAS_DATA		0x02  /*!<  ISC_BIGINT�� ���� �����͸� �����ϰ� ����*/
#define ISC_BIGINT_INIT			0x04  /*!<  ISC_BIGINT�� �ʱ�ȭ ��*/

#define ISC_PRIME 1			/*!<  ISC_PRIME*/
#define ISC_COMPOSITE -1	/*!<  ISC_COMPOSITE*/

#define ISC_CORRECT_TOP(bInt) \
	{ \
	uintptr *len; \
	if (bInt && (bInt)->index > 0) \
	{ \
	for (len= &((bInt)->data[(bInt)->index-1]); (bInt)->index > 0; (bInt)->index--) \
	if (*(len--)) break; \
	}\
	}

	/*!
	* \brief
	* ISC_BIGINT�� ����Ʈ �迭 ���̸� ����
	* \param bInt
	* ����Ʈ �迭�� ���̸� ���� ISC_BIGINT
	* \returns
	* ����Ʈ �迭�� ����
	*/
#define ISC_GET_BIGINT_BYTES_UNSIGNED_LENGTH(bInt)		((ISC_Get_BIGINT_Bits_Length(bInt)+7)/8)	
#define ISC_GET_BIGINT_BYTES_LENGTH(bInt)				((ISC_Get_BIGINT_Bits_Length(bInt)+8)/8)
#define ISC_IS_BIGINT_ABS_WORD(bInt,w)			((((bInt)->index == 1) && ((bInt)->data[0] == (uintptr)(w))) \
	|| (((w) == 0) && ((bInt)->index == 0)))
#define ISC_IS_BIGINT_ZERO(bInt)					((bInt)->index == 0)
#define ISC_IS_BIGINT_ONE(bInt)					ISC_IS_BIGINT_ABS_WORD((bInt),1)
#define ISC_IS_BIGINT_WORD(bInt,w)				ISC_IS_BIGINT_ABS_WORD((bInt),(w))
#define ISC_IS_BIGINT_ODD(bInt)					((bInt)->index > 0) && ((bInt)->data[0] & 1)
#define ISC_SET_BIGINT_ONE(w)					ISC_Set_BIGINT_Word((w),1)
#define ISC_SET_BIGINT_ZERO(w)					ISC_Set_BIGINT_Word((w),0)
#define ISC_SET_BIGINT_ONE_EX(w,l)				isc_Set_BIGINT_One_Ex((w),(l))
#define ISC_SET_BIGINT_ZERO_EX(w,l)				isc_Set_BIGINT_Zero_Ex((w),(l))

#define ISC_EXPAND_BIGINT_WORD(bInt,words)		(((words) <= (bInt)->length)?(bInt):isc_Expand_BIGINT((bInt),(words)))
#define ISC_EXPAND_BIGINT_WORD_EX(bInt,words)		(((words) <= (bInt)->length)?(bInt):isc_Expand_BIGINT_Ex((bInt),(words)))
#define ISC_EXPAND_BIGINT_BITS(bInt,bits)		((((((bits+ISC_BITS_IN_32L-1))/ISC_BITS_IN_32L)) <= (bInt)->length) ? \
	(bInt):isc_Expand_BIGINT((bInt),(bits+ISC_BITS_IN_32L-1)/ISC_BITS_IN_32L))

#define ISC_GET_BIGINT_WINDOW_BITS_FOR_EXPONENT_SIZE(b) \
	((b) > 671 ? 6 : \
	(b) > 239 ? 5 : \
	(b) >  79 ? 4 : \
	(b) >  23 ? 3 : 1)

#define ISC_GET_BIGINT_WINDOW_BITS_FOR_CTIME_EXPONENT_SIZE(b) \
    ((b) > 937 ? 6 : \
    (b) > 306 ? 5 : \
    (b) >  89 ? 4 : \
    (b) >  22 ? 3 : 1)

ISC_INTERNAL ISC_BIGINT *isc_Expand_BIGINT(ISC_BIGINT *ret, int words);
ISC_INTERNAL ISC_BIGINT *isc_Expand_BIGINT_Ex(ISC_BIGINT *ret, int words);

	/*!
	* \brief
	* �Է� ����ü�� �Է¹��� ������� Ȯ�� �� 1�� ����� �Լ�
	* ISC_BIGINT ����ü
	* \param words
	* Ȯ���� ���� ����
	* \returns
	* -# ISC_BIGINT ����ü : ����
	* -# NULL : ����
	*/
ISC_INTERNAL ISC_BIGINT *isc_Set_BIGINT_One_Ex(ISC_BIGINT *ret, int words);

	/*!
	* \brief
	* �Է� ����ü�� �Է¹��� ������� Ȯ�� �� 0���� ����� �Լ�
	* \param ret
	* ISC_BIGINT ����ü
	* \param words
	* Ȯ���� ���� ����
	* \returns
	* -# ISC_BIGINT ����ü : ����
	* -# NULL : ����
	*/
ISC_INTERNAL ISC_BIGINT *isc_Set_BIGINT_Zero_Ex(ISC_BIGINT *ret, int words);

	/*!
	* \brief
	* ISC_BIGINT_MONT ����ü�� �޸� �Ҵ�
	* \returns
	* ISC_BIGINT_MONT ����ü
	*/
ISC_INTERNAL ISC_BIGINT_MONT *isc_New_BIGINT_MONT();

	/*!
	* \brief
	* ISC_BIGINT_MONT ����ü�� Reset
	* \param mont
	* Reset�� ISC_BIGINT_MONT
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
ISC_INTERNAL ISC_STATUS isc_Init_BIGINT_MONT(ISC_BIGINT_MONT *mont);

	/*!
	* \brief
	* ISC_BIGINT_MONT �޸� ���� �Լ�
	* \param mont
	* �޸� ������ ISC_BIGINT_MONT
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/

ISC_INTERNAL ISC_STATUS isc_Free_BIGINT_MONT(ISC_BIGINT_MONT *mont);
ISC_INTERNAL int isc_Get_BIGINT_Bits_Word(uintptr l);

ISC_INTERNAL int isc_Cmp_BIGINT_Words(const uintptr *a, const uintptr *b, int n);
	/*!
	* \brief
	* ISC_BIGINT a�� b�� �ִ�����(GCD)�� ����
	* \param ret
	* �����(�ִ�����) ISC_BIGINT ����ü ������
	* \param a
	* ISC_BIGINT ����ü ������ a
	* \param b
	* ISC_BIGINT ����ü ������ b
	* \param pool
	* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
ISC_INTERNAL ISC_STATUS isc_Gcd_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT n �󿡼��� ISC_BIGINT a�� ����(inverse)�� ����, ret�� NULL��� ���������� �޸� �Ҵ�
	* \param ret
	* �����(����) ISC_BIGINT ����ü ������
	* \param a
	* ������ ���ϰ��� �ϴ� ISC_BIGINT ����ü ������
	* \param n
	* Modulas ISC_BIGINT ����ü ������
	* \param pool
	* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
ISC_API ISC_STATUS ISC_Mod_Inverse_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *n, ISC_BIGINT_POOL *pool);
	/*!
	* \brief
	* ISC_BIGINT a�� ISC_BIGINT b�� Divide ���� (rem = m % d)
	* \param ret
	* ����� ����� ISC_BIGINT ����ü ������, �޸� �Ҵ��� �Ǿ� �־�� ��
	* \param m
	* ������ �� ��
	* \param d
	* ���� ��* \param pool
	* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
#define mod_BIGINT(ret,m,d,pool) ISC_Div_BIGINT(NULL,ret,m,d,pool)
ISC_INTERNAL ISC_STATUS isc_Mod_Mul_BIGINT_Montgomery(ISC_BIGINT *r, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_MONT *mont, ISC_BIGINT_POOL *pool);
ISC_INTERNAL ISC_STATUS isc_BIGINT_from_Montgomery(ISC_BIGINT *r, ISC_BIGINT *a, ISC_BIGINT_MONT *mont, ISC_BIGINT_POOL *pool);
ISC_INTERNAL ISC_STATUS isc_Set_BIGINT_MONT(ISC_BIGINT_MONT *mont, const ISC_BIGINT *mod, ISC_BIGINT_POOL *pool);
#define BIGINT_to_montgomery(r, a, mont, pool) isc_Mod_Mul_BIGINT_Montgomery((r), (a), &(mont->rr), (mont), (pool))

ISC_INTERNAL ISC_BIGINT *isc_Euclid(ISC_BIGINT *a, ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

ISC_INTERNAL void isc_Sqr_Word_Base(uintptr *ret, const uintptr *a, int n, uintptr *temp);
ISC_INTERNAL void isc_Sqr_Recursive(uintptr *ret, const uintptr *a, int n, uintptr *t);
ISC_INTERNAL void isc_Mtp_Word_Base(uintptr *ret, uintptr *a, int na, uintptr *b, int nb);
ISC_INTERNAL void isc_Mtp_Recursive(uintptr *ret, uintptr *a, uintptr *b, int n, int dna, int dnb, uintptr *t);
ISC_INTERNAL void isc_Mtp_Recursive_P(uintptr *ret, uintptr *a, uintptr *b, int n, int tna, int tnb, uintptr *t);

ISC_INTERNAL uintptr isc_Add_Words(uintptr *ret, const uintptr *a, const uintptr *b, int n);
ISC_INTERNAL uintptr isc_Sub_Words(uintptr *r, const uintptr *a, const uintptr *b, int n);
ISC_INTERNAL uintptr isc_Mtp_Words(uintptr *rp, const uintptr *ap, int num, uintptr w);
ISC_INTERNAL uintptr isc_Div_Words(uintptr h, uintptr l, uintptr d);
ISC_INTERNAL uintptr isc_Mtp_Add_Words(uintptr *rp, const uintptr *ap, int num, uintptr w);
ISC_INTERNAL void isc_Sqr_Words(uintptr *ret, const uintptr *a, int n);

ISC_INTERNAL uintptr isc_Sub_Part_Words(uintptr *r, const uintptr *a, const uintptr *b, int cl, int dl);
ISC_INTERNAL void isc_Sqr_Base(uintptr *r, const uintptr *a);
ISC_INTERNAL void isc_Sqr_Base_Ex(uintptr *r, const uintptr *a);
ISC_INTERNAL void isc_Mtp_Base(uintptr *r, uintptr *a, uintptr *b);
ISC_INTERNAL void isc_Mtp_Base_Ex(uintptr *r, uintptr *a, uintptr *b);
ISC_INTERNAL int isc_Cmp_Parts(const uintptr *a, const uintptr *b, int cl, int dl);
ISC_INTERNAL ISC_STATUS isc_Left_Shift_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, int n);
ISC_INTERNAL ISC_STATUS isc_Right_Shift_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, int n);

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO


	/*!
	* \brief
	* ISC_BIGINT_POOL �ʱ�ȭ �Լ�
	* \param pool
	* �ʱ�ȭ�� ISC_BIGINT_POOL
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
ISC_INTERNAL ISC_STATUS isc_Init_BIGINT_Pool(ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT_POOL ����ü�� �޸� �Ҵ�
	* \returns
	* ISC_BIGINT_POOL ����ü
	*/
	ISC_API ISC_BIGINT_POOL* ISC_New_BIGINT_Pool();

	/*!
	* \brief
	* ISC_BIGINT_POOL �޸� ���� �Լ�
	* \param pool
	* �޸� ������ ISC_BIGINT_POOL
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
	ISC_API ISC_STATUS ISC_Free_BIGINT_Pool(ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT_POOL�� �����͸� 0���� �ʱ�ȭ
	* \param pool
	* �ʱ�ȭ�� ISC_BIGINT_POOL
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
	ISC_API ISC_STATUS ISC_Clear_BIGINT_Pool(ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT_POOL ��� ���� ��� �Լ�
	* �Լ��� ȣ��� ���Ŀ� ISC_Get_BIGINT_Pool() �Լ��� ����ϰ� ISC_Finish_BIGINT_Pool(pool) �Լ��� ���� ��ȯ�Ѵ�
	* \param pool
	* ����� ISC_BIGINT_POOL
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_START_BIGINT_POOL^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
	*/
	ISC_API ISC_STATUS ISC_Start_BIGINT_Pool(ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT_POOL ��� ���� ��� �Լ�
	* ISC_Start_BIGINT_Pool(pool) ȣ�� ���ķ� ISC_Get_BIGINT_Pool()�� ���� ���� ��ü�� Pool�� ��ȯ�Ѵ�.
	* \param pool
	* ����� ISC_BIGINT_POOL
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_FINISH_BIGINT_POOL^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
	*/
	ISC_API ISC_STATUS ISC_Finish_BIGINT_Pool(ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT_POOL ���� ISC_BIGINT�� ��´�
	* \param pool
	* ����� ISC_BIGINT_POOL
	* \returns
	* ISC_BIGINT ����ü
	*/
	ISC_API ISC_BIGINT* ISC_Get_BIGINT_Pool(ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT_POOL ���� ���� ISC_BIGINT ��ȯ
	* \param pool
	* ����� ISC_BIGINT_POOL
	* \param num
	* ��ȯ�� ISC_BIGINT ����
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/

	/*!
	* \brief
	* ISC_BIGINT ����ü�� �޸� �Ҵ�
	* \returns
	* ISC_BIGINT ����ü
	*/
	ISC_API ISC_BIGINT *ISC_New_BIGINT(void);

	/*!
	* \brief
	* ISC_BIGINT �޸� ���� �Լ�
	* \param bInt
	* �޸� ������ ISC_BIGINT
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
	ISC_API ISC_STATUS ISC_Free_BIGINT(ISC_BIGINT *bInt);


	/*!
	* \brief
	* ISC_BIGINT ����ü�� Reset
	* \param bInt
	* Reset�� ISC_BIGINT
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
	ISC_API ISC_STATUS ISC_Init_BIGINT(ISC_BIGINT *bInt);

	/*!
	* \brief
	* ISC_BIGINT�� �����͸� 0���� �ʱ�ȭ
	* \param bInt
	* �ʱ�ȭ �� ISC_BIGINT
	*/
	ISC_API void ISC_Clear_BIGINT(ISC_BIGINT *bInt);

	/*!
	* \brief
	* ��� ��Ʈ���� char �迭�� �Է��Ͽ�, ISC_BIGINT ����ü�� ����
	* \param hex_arr
	* ��ȯ�� ��� ��Ʈ���� char �迭
	* \returns
	* -# ������ ISC_BIGINT ����ü ������ : Success
	* -# NULL : ����
	*/
	ISC_API ISC_BIGINT* ISC_HEX_To_BIGINT(const char *hex_arr);

	/*!
	* \brief
	* ISC_BIGINT�� ������ ��� ��Ʈ���� char �迭�� ��ȯ
	* \param bInt
	* ��ȯ�� ISC_BIGINT ����ü ������
	* \returns
	* -# �����Ͱ� ����� ��� ��Ʈ���� char �迭 ������ : Success
	* -# NULL : ����
	*/
	ISC_API char* ISC_BIGINT_To_HEX(const ISC_BIGINT *bInt);

	/*!
	* \brief
	* ISC_BIGINT�� ������ 10������ char �迭�� ��ȯ
	* \param bInt
	* ��ȯ�� ISC_BIGINT ����ü ������
	* \returns
	* -# �����Ͱ� ����� 10���� ��Ʈ���� char �迭 ������ : Success
	* -# NULL : ����
	*/
	ISC_API char* ISC_BIGINT_To_DEC(const ISC_BIGINT *bInt);

	/*!
	* \brief
	* ISC_BIGINT �������� bits ���� ���̸� ����
	* \param bInt
	* ISC_BIGINT ����ü ������
	* \returns
	* -# bits ���� ����
	*/
	ISC_API int ISC_Get_BIGINT_Bits_Length(const ISC_BIGINT *bInt);
	
	/*!
	* \brief
	* ISC_BIGINT �������� n��° ��Ʈ�� 1���� �Ǵ�
	* \param bInt
	* ISC_BIGINT ����ü ������
	* \param n
	* Bits Index
	* \returns
	* -# 1 : n��° ��Ʈ�� 1
	* -# 0 : n��° ��Ʈ�� 0
	*/
	ISC_API int ISC_Is_BIGINT_Bit_Set(const ISC_BIGINT *bInt, int n);

	/*!
	* \brief
	* ISC_BIGINT �������� n ��° ��Ʈ�� 1�� ����
	* \param bInt
	* ISC_BIGINT ����ü ������
	* \param n
	* ��Ʈ�� ������ �ε���
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_SET_BIGINT_BIT^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
	* -# LOCATION^ISC_F_SET_BIGINT_BIT^ISC_ERR_EXPAND_BIGINT_WORD : EXPAND BIGINT WORD ���� ����
	*/
	ISC_API ISC_STATUS ISC_Set_BIGINT_Bit(ISC_BIGINT *bInt, int n);

	/*!
	* \brief
	* ISC_BIGINT �����Ϳ� unsigned long Ÿ�� �ڷḦ �Է�
	* \param bInt
	* ISC_BIGINT ����ü ������
	* \param w
	* �Է��� ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
	ISC_API ISC_STATUS	ISC_Set_BIGINT_Word(ISC_BIGINT *bInt, uintptr w);

	/*!
	* \brief
	* ISC_BIGINT �������� ���� ������ ��ȯ
	* \param bInt
	* ISC_BIGINT ����ü ������
	* \returns
	* -# 4 bytes : ������ ������
	* -# 0xFFFFFFFF : ISC_BIGINT�� 4 ����Ʈ �̻��� �����͸� ��� ���� ���
	* -# 0 : Fail
	*/
	ISC_API uintptr ISC_Get_BIGINT_Word(const ISC_BIGINT *bInt);

ISC_INTERNAL ISC_STATUS isc_Left_Shift_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, int n);
ISC_INTERNAL ISC_STATUS isc_Right_Shift_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, int n);

	/*!
	* \brief
	* ISC_BIGINT from �� ������ �����͸� ISC_BIGINT to�� ����
	* \param to
	* ISC_BIGINT ����ü ������ Destination
	* \param from
	* ISC_BIGINT ����ü ������ Source
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
	ISC_API ISC_STATUS ISC_Copy_BIGINT(ISC_BIGINT *to, const ISC_BIGINT *from);

	/*!
	* \brief
	* ISC_BIGINT a�� b�� ������ Swap
	* \param a
	* ISC_BIGINT ����ü ������
	* \param b
	* ISC_BIGINT ����ü ������
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	ISC_API void ISC_Swap_BIGINT(ISC_BIGINT *a, ISC_BIGINT *b);

	/*!
	* \brief
	* ISC_BIGINT bInt�� ������ �����Ͱ� ����� ���ο� ISC_BIGINT ������ ��ȯ
	* \param bInt
	* ISC_BIGINT ����ü ������
	* \returns
	* -# �޸� �Ҵ�� ISC_BIGINT ����ü ������
	* -# NULL(0) : Fail
	*/
	ISC_API ISC_BIGINT *ISC_Dup_BIGINT(const ISC_BIGINT *bInt);

	/*!
	* \brief
	* �ΰ��� ISC_BIGINT �� ũ�⸦ ��
	* \param a
	* ISC_BIGINT ����ü ������
	* \param b
	* ISC_BIGINT ����ü ������
	* \returns
	* -# 1 : a > b
	* -# 0 : a = b
	* -# -1 : a < b
	*/
	ISC_API int ISC_Cmp_BIGINT(const ISC_BIGINT *a, const ISC_BIGINT *b);

	/*!
	* \brief
	* ���̳ʸ� �����͸� ISC_BIGINT�� ��ȯ. �Էµ� bInt�� NULL�� ��� ���Ӱ� �����͸� �޸� �Ҵ� �� ��ȯ
	* \param bin
	* Bianry ������
	* \param len
	* Binary �������� ����
	* \param bInt
	* ISC_BIGINT ����ü ������
	* Binary
	* �����Ͱ� ����� ISC_BIGINT, NULL�� ��� ���������� �޸� �Ҵ�
	* \returns
	* -# ����� ����� ISC_BIGINT ����ü ������
	* -# NULL(0) : Fail
	*/
	ISC_API ISC_BIGINT *ISC_Binary_To_BIGINT(const uint8 *bin, int len, ISC_BIGINT *bInt);

	/*!
	* \brief
	* ISC_BIGINT ����ü�� uint8�� binary�� ��ȯ, uint8�� binary�� �޸𸮰� �Ҵ� �Ǿ� �־�� ��. 2�� ���� ó�� ��. binary�� ���̴� ISC_GET_BIGINT_BYTES_UNSIGNED_LENGTH(ISC_BIGINT*) �� ���� �� ����
	* \param bInt
	* ISC_BIGINT ����ü ������
	* \param bin
	* Binary ������ ����
	* \returns
	* -# ����� ����� Binary�� ����
	*/
	ISC_API int ISC_BIGINT_To_Binary_Unsigned(const ISC_BIGINT *bInt, uint8 *bin);

	/*!
	* \brief
	* ISC_BIGINT ����ü�� uint8�� binary�� ��ȯ, uint8�� binary�� �޸𸮰� �Ҵ� �Ǿ� �־�� ��. binary�� ���̴� ISC_GET_BIGINT_BYTES_LENGTH(ISC_BIGINT*) �� ���� �� ����
	* \param bInt
	* ISC_BIGINT ����ü ������
	* \param bin
	* Binary ������ ����
	* \returns
	* -# ����� ����� Binary�� ����
	*/
	ISC_API int ISC_BIGINT_To_Binary(const ISC_BIGINT *bInt, uint8 *bin);

	/*!
	* \brief
	* ���� 1�� �ʱ�ȭ�� ISC_BIGINT�� ����
	* \returns
	* -# ���� 1�� �ʱ�ȭ�� ISC_BIGINT ������
	* -# NULL : Fail
	*/
	ISC_API const ISC_BIGINT *ISC_Value_One_BIGINT(void);

	/*!
	* \brief
	* ���� 0�� �ʱ�ȭ�� ISC_BIGINT�� ����
	* \returns
	* -# ���� 0�� �ʱ�ȭ�� ISC_BIGINT ������
	* -# NULL : Fail
	*/
	ISC_API const ISC_BIGINT *ISC_Value_Zero_BIGINT(void);

	/*!
	* \brief
	* ISC_BIGINT �� Print
	* \param bInt
	* ISC_BIGINT ����ü ������
	*/
	ISC_API void ISC_Print_BIGINT(const ISC_BIGINT *bInt);

	/*!
	* \brief
	* ISC_BIGINT �� dump
	* \param bInt
	* ISC_BIGINT ����ü ������
	* \returns
	* -# ������� ����� ���ڿ� (�ܺο��� �޸� ���� �ʿ� [ISC_MEM_FREE])
	* -# NULL : Fail
	*/
	ISC_API char* ISC_Dump_BIGINT(const ISC_BIGINT *bInt);

	/*!
	* \brief
	* ISC_BIGINT a�� ISC_BIGINT b�� Addition ���� (ret = a + b)
	* \param ret
	* ����� ����� ISC_BIGINT ����ü ������, �޸� �Ҵ��� �Ǿ� �־�� ��
	* \param a
	* ISC_BIGINT ����ü ������
	* \param b
	* ISC_BIGINT ����ü ������
	* \param pool
	* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
	ISC_API ISC_STATUS ISC_Add_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT a�� ISC_BIGINT b�� Subtraction ����(ret = a - b), �ݵ�� a�� b���� Ŀ�� ��(ũ�� �� ������ ISC_Cmp_BIGINT() ����)
	* \param ret
	* ����� ����� ISC_BIGINT ����ü ������, �޸� �Ҵ��� �Ǿ� �־�� ��
	* \param a
	* ISC_BIGINT ����ü ������
	* \param b
	* ISC_BIGINT ����ü ������
	* \param pool
	* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
	ISC_API ISC_STATUS ISC_Sub_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT �׷� �������� a�� ISC_BIGINT b�� Subtraction ����(ret = (a - b) mod m), �׻� ����� ������ ��) (1 - 2) mod 7 = 6
	* \param ret
	* ����� ����� ISC_BIGINT ����ü ������, �޸� �Ҵ��� �Ǿ� �־�� ��
	* \param a
	* ISC_BIGINT ����ü ������
	* \param b
	* ISC_BIGINT ����ü ������
	* \param m
	* ISC_BIGINT ����ü ������
	* \param pool
	* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_MOD_SUB_BIGINT^ISC_ERR_NULL_INPUT : NULL �Է°� �Է�
	* -# LOCATION^ISC_F_MOD_SUB_BIGINT^ISC_ERR_MALLOC : ���� �޸� �Ҵ� ����
	*/
	ISC_API ISC_STATUS ISC_Mod_Sub_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT a�� ISC_BIGINT b�� Divide ���� (num = divisor x dir_ret + rm)
	* \param div_ret
	* ���� ����� ISC_BIGINT ����ü ������
	* \param rm
	* ������ ���� ����� ISC_BIGINT ����ü ������
	* \param num
	* ������ �� ��
	* \param divisor
	* ���� ��
	* \param pool
	* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_DIV_BIGINT^ISC_ERR_INTERNAL : ���ο��� ����
	* -# LOCATION^ISC_F_DIV_BIGINT^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL ���� ����
	* -# LOCATION^ISC_F_DIV_BIGINT^ISC_ERR_MALLOC : ���� �޸� �Ҵ� ����
	* -# LOCATION^ISC_F_DIV_BIGINT^ISC_ERR_LEFT_SHIFT_BIGINT_FAIL : LEFT SHIFT BIGINT ���� ����
	*/
	ISC_API ISC_STATUS ISC_Div_BIGINT(ISC_BIGINT *div_ret, ISC_BIGINT *rm, const ISC_BIGINT *num, const ISC_BIGINT *divisor, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT a�� ISC_BIGINT b�� Multiplication ���� (ret = a x b)
	* \param ret
	* ����� ����� ISC_BIGINT ����ü ������, �޸� �Ҵ��� �Ǿ� �־�� ��
	* \param a
	* ISC_BIGINT ����ü ������
	* \param b
	* ISC_BIGINT ����ü ������
	* \param pool
	* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
	ISC_API ISC_STATUS ISC_Mtp_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT a�� ISC_BIGINT b�� Sqaure ���� (ret = a^2)
	* \param ret
	* ����� ����� ISC_BIGINT ����ü ������, �޸� �Ҵ��� �Ǿ� �־�� ��
	* \param a
	* ISC_BIGINT ����ü ������
	* \param pool
	* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_SQR_BIGINT^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL ���� ����
	* -# LOCATION^ISC_F_SQR_BIGINT^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL ���� ����
	* -# LOCATION^ISC_F_SQR_BIGINT^ISC_ERR_EXPAND_BIGINT_WORD : EXPAND BIGINT WORD ���� ����
	* -# LOCATION^ISC_F_SQR_BIGINT^ISC_ERR_COPY_BIGINT_FAIL : COPY BIGINT ���� ����
	*/
	ISC_API ISC_STATUS ISC_Sqr_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT a�� ISC_BIGINT b�� m �󿡼��� ������(Exponent) ���� (ret = a^p mod m)
	* \param ret
	* ����� ����� ISC_BIGINT ����ü ������, �޸� �Ҵ��� �Ǿ� �־�� ��
	* \param a
	* Base ISC_BIGINT ����ü ������
	* \param p
	* Exponent ISC_BIGINT ����ü ������
	* \param m
	* m ISC_BIGINT ����ü ������
	* \param pool
	* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_SET_BIGINT_FAIL : SET BIGINT ���� ����
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT ���� ����
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_MOD_BIGINT_FAIL : MOD_BIGINT ���� ����
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_MOD_MTP_BIGINT_FAIL : MOD MTP BIGINT ���� ����
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL ���� ����
	*/
	ISC_API ISC_STATUS ISC_Mod_Exp_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *p, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ����޸� �˰����� �̿��� ISC_BIGINT a�� ISC_BIGINT b�� m �󿡼��� ������(Exponent) ���� (ret = a^p mod m)
	* \param ret
	* ����� ����� ISC_BIGINT ����ü ������, �޸� �Ҵ��� �Ǿ� �־�� ��
	* \param a
	* Base ISC_BIGINT ����ü ������
	* \param p
	* Exponent ISC_BIGINT ����ü ������
	* \param m
	* m ISC_BIGINT ����ü ������
	* \param pool
	* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_MOD_EXP_MONT_BIGINT^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL ���� ����
	* -# LOCATION^ISC_F_MOD_EXP_MONT_BIGINT^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL ���� ����
	* -# LOCATION^ISC_F_MOD_EXP_MONT_BIGINT^ISC_ERR_MALLOC : ���� �޸� �Ҵ� ����
	* -# LOCATION^ISC_F_MOD_EXP_MONT_BIGINT^ISC_ERR_SET_BIGINT_FAIL : SET BIGINT ���� ����
	* -# LOCATION^ISC_F_MOD_EXP_MONT_BIGINT^ISC_ERR_MOD_BIGINT_FAIL : MOD BIGINT ���� ����
	* -# LOCATION^ISC_F_MOD_EXP_MONT_BIGINT^ISC_ERR_BIGINT_TO_MONTGOMERY_FAIL : BIGINT TO MONTGOMERY ���� ����
	* -# LOCATION^ISC_F_MOD_EXP_MONT_BIGINT^ISC_ERR_MOD_MUL_BIGINT_MONTGOMERY_FAIL : MOD MUL BIGINT MONTGOMERY ���� ����
	* -# LOCATION^ISC_F_MOD_EXP_MONT_BIGINT^ISC_ERR_BIGINT_FROM_MONTGOMERY_FAIL : BIGINT FROM MONTGOMERY ���� ����
	*/
	ISC_API ISC_STATUS ISC_Mod_Exp_Mont_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *p, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* Fixed-Windows ��Ŀ������ ����� ISC_BIGINT a�� ISC_BIGINT b�� m �󿡼��� ������(Exponent) ���� (ret = a^p mod m)
	* \param ret
	* ����� ����� ISC_BIGINT ����ü ������, �޸� �Ҵ��� �Ǿ� �־�� ��
	* \param a
	* Base ISC_BIGINT ����ü ������
	* \param p
	* Exponent ISC_BIGINT ����ü ������
	* \param m
	* m ISC_BIGINT ����ü ������
	* \param pool
	* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_SET_BIGINT_FAIL : SET BIGINT ���� ����
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT ���� ����
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_MOD_BIGINT_FAIL : MOD_BIGINT ���� ����
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_MOD_MTP_BIGINT_FAIL : MOD MTP BIGINT ���� ����
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL ���� ����
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_MALLOC : ���� �޸� �Ҵ� ����
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_COPY_BIGINT_FAIL : COPY BIGINT ���� ����
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_MOD_MUL_BIGINT_MONTGOMERY_FAIL : MOD MUL BIGINT MONTGOMERY ���� ����
	*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Exp_Mont_BIGINT_FixedWindow(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *p, const ISC_BIGINT *m, ISC_BIGINT_POOL *in_pool);

	/*!
	* \brief
	* ���� ISC_BIGINT �� ���� (DRBG ���)
	* \param rnd
	* ������ ������ ISC_BIGINT ����ü ������
	* \param bits
	* ������ ISC_BIGINT�� bit size
	* \param top
	* �ֻ��� ��Ʈ�� ���� �����ϴ� ��
	* -# -1 : ���� �״�� �д�. (�ֻ��� ��Ʈ�� 0�� �ɼ��� �ִ�.)
	* -# 0 : �ֻ��� ��Ʈ�� 1�� ����
	* -# 1 : �ֻ��� 2��Ʈ�� 1�� ����
	* \param bottom
	* ������ ���� ISC_BIGINT�� Ȧ�� ����
	* \param pool
	* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_RAND_BIGINT_EX^ISC_ERR_MEM_ALLOC : ���� �޸� �Ҵ� ����
	* -# LOCATION^ISC_F_RAND_BIGINT_EX^ISC_ERR_GET_RAND_FAIL : �������� ����
	* -# LOCATION^ISC_F_RAND_BIGINT_EX^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY -> BIGINT ��ȯ ����
	*/
	ISC_API ISC_STATUS ISC_Rand_BIGINT_Ex(ISC_BIGINT *rnd, int bits, int top, int bottom, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ���� ISC_BIGINT �� ���� (PRNG ���)
	* \param rnd
	* ������ ������ ISC_BIGINT ����ü ������
	* \param bits
	* ������ ISC_BIGINT�� bit size
	* \param top
	* �ֻ��� ��Ʈ�� ���� �����ϴ� ��
	* -# -1 : ���� �״�� �д�. (�ֻ��� ��Ʈ�� 0�� �ɼ��� �ִ�.)
	* -# 0 : �ֻ��� ��Ʈ�� 1�� ����
	* -# 1 : �ֻ��� 2��Ʈ�� 1�� ����
	* \param bottom
	* ������ ���� ISC_BIGINT�� Ȧ�� ����
	* \param pool
	* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
	* \param alg_id
	* random generator(prng)���� ���� �˰���
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
	ISC_API ISC_STATUS ISC_Rand_BIGINT(ISC_BIGINT *rnd, int bits, int top, int bottom, ISC_BIGINT_POOL *pool,int alg_id);

	/*!
	* \brief
	* ISC_BIGINT a�� ISC_BIGINT b�� m �󿡼��� Multiplication ���� (ret = a x b mod m)
	* \param ret
	* ����� ����� ISC_BIGINT ����ü ������, �޸� �Ҵ��� �Ǿ� �־�� ��
	* \param a
	* ISC_BIGINT ����ü ������
	* \param b
	* ISC_BIGINT ����ü ������
	* \param m
	* m ISC_BIGINT ����ü ������
	* \param pool
	* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
	ISC_API ISC_STATUS ISC_Mod_Mtp_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT a�� uintptr w�� Divide ���� (rem = m % d)
	* \param a
	* ������ �� ��
	* \param w
	* ���� ��
	* \returns
	* -# �� �� : Success
	* -# -1 : ����
	*/
	ISC_API uintptr ISC_Mod_BIGINT_Word(ISC_BIGINT *a, uintptr w);

	/*!
	* \brief
	* ISC_BIGINT a�� uintptr w�� Divide ���� (num = divisor x dir_ret + rm)
	* \param a
	* ������ �� ��
	* \param w
	* ���� ��
	* \returns
	* -# ������ �� : Success
	* -# -1 : ����
	*/
	ISC_API uintptr ISC_Div_BIGINT_Word(ISC_BIGINT *a, uintptr w);

	/*!
	* \brief
	* ISC_BIGINT a�� uintptr w�� Addition ���� (ret = a + b)
	* \param a
	* ISC_BIGINT ����ü ������ (�����)
	* \param w
	* ������ ��
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
	ISC_API ISC_STATUS ISC_Add_BIGINT_Word(ISC_BIGINT *a, uintptr w);

	/*!
	* \brief
	* ISC_BIGINT a�� uintptr w�� Subtraction ����(ret = a - b)
	* \param a
	* ISC_BIGINT ����ü ������ (�����)
	* \param w
	* �� ��
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
	ISC_API ISC_STATUS ISC_Sub_BIGINT_Word(ISC_BIGINT *a, uintptr w);

	/*!
	* \brief
	* ISC_BIGINT a�� uintptr w�� Multiplication ���� (ret = a x b)
	* \param a
	* ISC_BIGINT ����ü ������ (�����)
	* \param w
	* ������ ��
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : ���� (�����ڵ�)
	*/
	ISC_API ISC_STATUS ISC_Mtp_BIGINT_Word(ISC_BIGINT *a, uintptr w);

	/*!
	* \brief
	* bits �� ��ŭ�� prime number�� ����
	* \param prime
	* ����� ����� ISC_BIGINT ����ü ������, �޸� �Ҵ��� �Ǿ� �־�� ��
	* \param bits
	* prime�� ��Ʈ ��
	* \param pool
	* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_GENERATE_BIGINT_PRIME^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL ���� ����
	* -# LOCATION^ISC_F_GENERATE_BIGINT_PRIME^ISC_ERR_RAND_BIGINT_FAIL : RAND BIGINT ���� ����
	* -# LOCATION^ISC_F_GENERATE_BIGINT_PRIME^ISC_ERR_ADD_BIGINT_FAIL : ADD BIGINT ���� ����
	* -# LOCATION^ISC_F_GENERATE_BIGINT_PRIME^ISC_ERR_RIGHT_SHIFT_BIGINT_FAIL : RIGHT SHIFT BIGINT ���� ����
	*/
	ISC_API ISC_STATUS ISC_Generate_BIGINT_Prime_Ex(ISC_BIGINT *prime, int bits, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* bits �� ��ŭ�� prime number�� ����
	* \param prime
	* ����� ����� ISC_BIGINT ����ü ������, �޸� �Ҵ��� �Ǿ� �־�� ��
	* \param bits
	* prime�� ��Ʈ ��
	* \param pool
	* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
	* \param alg_id
	* random generator(prng)���� ���� �˰���
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_GENERATE_BIGINT_PRIME^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL ���� ����
	* -# LOCATION^ISC_F_GENERATE_BIGINT_PRIME^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL ���� ����
	* -# LOCATION^ISC_F_GENERATE_BIGINT_PRIME^ISC_ERR_RAND_BIGINT_FAIL : RAND BIGINT ���� ����
	* -# LOCATION^ISC_F_GENERATE_BIGINT_PRIME^ISC_ERR_ADD_BIGINT_FAIL : ADD BIGINT ���� ����
	* -# LOCATION^ISC_F_GENERATE_BIGINT_PRIME^ISC_ERR_RIGHT_SHIFT_BIGINT_FAIL : RIGHT SHIFT BIGINT ���� ����
	*/
	ISC_API ISC_STATUS ISC_Generate_BIGINT_Prime(ISC_BIGINT *prime, int bits, ISC_BIGINT_POOL *pool, int alg_id);

	/*!
	* \brief
	* �Էµ� ISC_BIGINT n�� �Ҽ� ���� �����ϴ� �Լ�(Miller-Rabin Test)
	* \param n
	* �Ҽ��� �� ������ ISC_BIGINT
	* \param iter
	* prime�� ��Ʈ ��,  Miller-Rabin�� Error Ȯ�� ~ 1/(4^iter)
	* \param pool
	* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
	* \returns
	* -# 1 : Prime
	* -# 0 : Fail
	* -# -1 : Composite
	*/
	ISC_API int ISC_Is_BIGINT_Prime_Ex(const ISC_BIGINT *n, int iter, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* �Էµ� ISC_BIGINT n�� �Ҽ� ���� �����ϴ� �Լ�(Miller-Rabin Test)
	* \param n
	* �Ҽ��� �� ������ ISC_BIGINT
	* \param iter
	* prime�� ��Ʈ ��,  Miller-Rabin�� Error Ȯ�� ~ 1/(4^iter)
	* \param pool
	* ���� ȿ���� ���� ISC_BIGINT_POOL ����ü ������
	* \param alg_id
	* random generator(prng)���� ���� �˰���
	* \returns
	* -# 1 : Prime
	* -# 0 : Fail
	* -# -1 : Composite
	*/
	ISC_API int ISC_Is_BIGINT_Prime(const ISC_BIGINT *n, int iter, ISC_BIGINT_POOL *pool, int alg_id);


#else

	ISC_RET_LOADLIB_CRYPTO( ISC_BIGINT_POOL*, ISC_New_BIGINT_Pool, (void), (), NULL );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Free_BIGINT_Pool, (ISC_BIGINT_POOL *pool), (pool), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Clear_BIGINT_Pool, (ISC_BIGINT_POOL *pool), (pool), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Start_BIGINT_Pool, (ISC_BIGINT_POOL *pool), (pool), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Finish_BIGINT_Pool, (ISC_BIGINT_POOL *pool), (pool), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_BIGINT*, ISC_Get_BIGINT_Pool, (ISC_BIGINT_POOL *pool), (pool), NULL );
	ISC_RET_LOADLIB_CRYPTO( ISC_BIGINT*, ISC_New_BIGINT, (void), (), NULL );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Free_BIGINT, (ISC_BIGINT *bInt), (bInt), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Init_BIGINT, (ISC_BIGINT *bInt), (bInt), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_VOID_LOADLIB_CRYPTO( void, ISC_Clear_BIGINT, (ISC_BIGINT *bInt), (bInt) );
	ISC_RET_LOADLIB_CRYPTO( ISC_BIGINT*, ISC_HEX_To_BIGINT, (const char *hex_arr), (hex_arr), NULL );
	ISC_RET_LOADLIB_CRYPTO( char*, ISC_BIGINT_To_HEX, (const ISC_BIGINT *bInt), (bInt), NULL );
	ISC_RET_LOADLIB_CRYPTO( char*, ISC_BIGINT_To_DEC, (const ISC_BIGINT *bInt), (bInt), NULL );
	ISC_RET_LOADLIB_CRYPTO( int, ISC_Get_BIGINT_Bits_Length, (const ISC_BIGINT *bInt), (bInt), (-1) );
	ISC_RET_LOADLIB_CRYPTO( int, ISC_Is_BIGINT_Bit_Set, (const ISC_BIGINT *bInt, int n), (bInt, n), (-1) );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Set_BIGINT_Bit, (ISC_BIGINT *bInt, int n), (bInt, n), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Set_BIGINT_Word, (ISC_BIGINT *bInt, uintptr w), (bInt, w), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( uintptr, ISC_Get_BIGINT_Word, (const ISC_BIGINT *bInt), (bInt), 0 );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Copy_BIGINT, (ISC_BIGINT *to, const ISC_BIGINT *from), (to, from), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_VOID_LOADLIB_CRYPTO( void, ISC_Swap_BIGINT, (ISC_BIGINT *a, ISC_BIGINT *b), (a, b) );
	ISC_RET_LOADLIB_CRYPTO( ISC_BIGINT*, ISC_Dup_BIGINT, (const ISC_BIGINT *bInt), (bInt), NULL );
	ISC_RET_LOADLIB_CRYPTO( int, ISC_Cmp_BIGINT, (const ISC_BIGINT *a, const ISC_BIGINT *b), (a, b), 0 );
	ISC_RET_LOADLIB_CRYPTO( ISC_BIGINT*, ISC_Binary_To_BIGINT, (const uint8 *bin, int len, ISC_BIGINT *bInt), (bin, len, bInt), NULL );
	ISC_RET_LOADLIB_CRYPTO( int, ISC_BIGINT_To_Binary_Unsigned, (const ISC_BIGINT *bInt, uint8 *bin), (bInt, bin), 0 );
	ISC_RET_LOADLIB_CRYPTO( int, ISC_BIGINT_To_Binary, (const ISC_BIGINT *bInt, uint8 *bin), (bInt, bin), 0 );
	ISC_RET_LOADLIB_CRYPTO( const ISC_BIGINT*, ISC_Value_One_BIGINT, (void), (), NULL );
	ISC_RET_LOADLIB_CRYPTO( const ISC_BIGINT*, ISC_Value_Zero_BIGINT, (void), (), NULL );
	ISC_VOID_LOADLIB_CRYPTO( void, ISC_Print_BIGINT, (const ISC_BIGINT *bInt), (bInt) );
	ISC_RET_LOADLIB_CRYPTO( char*, ISC_Dump_BIGINT, (const ISC_BIGINT *bInt), (bInt), NULL );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Add_BIGINT, (ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool), (ret, a, b, pool), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Sub_BIGINT, (ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool), (ret, a, b, pool), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Mod_Sub_BIGINT, (ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool), (ret, a, m, pool), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Div_BIGINT, (ISC_BIGINT *div_ret, ISC_BIGINT *rm, const ISC_BIGINT *num, const ISC_BIGINT *divisor, ISC_BIGINT_POOL *pool), (div_ret, rm, num, divisor, pool), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Mtp_BIGINT, (ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool), (ret, a, b, pool), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Sqr_BIGINT, (ISC_BIGINT *ret, const ISC_BIGINT *a, ISC_BIGINT_POOL *pool), (ret, a, pool), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Mod_Exp_BIGINT, (ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *p, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool), (ret, a, p, m, pool), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Mod_Exp_Mont_BIGINT, (ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *p, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool), (ret, a, p, m, pool), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Rand_BIGINT_Ex, (ISC_BIGINT *rnd, int bits, int top, int bottom, ISC_BIGINT_POOL *pool), (rnd, bits, top, bottom, pool), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Rand_BIGINT, (ISC_BIGINT *rnd, int bits, int top, int bottom, ISC_BIGINT_POOL *pool,int alg_id), (rnd, bits, top, bottom, pool, alg_id), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Mod_Mtp_BIGINT, (ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool), (ret, a, b, m, pool), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_VOID_LOADLIB_CRYPTO( uintptr, ISC_Mod_BIGINT_Word, (ISC_BIGINT *a, uintptr w), (a, w) );
	ISC_VOID_LOADLIB_CRYPTO( uintptr, ISC_Div_BIGINT_Word, (ISC_BIGINT *a, uintptr w), (a, w) );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Add_BIGINT_Word, (ISC_BIGINT *a, uintptr w), (a, w), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Sub_BIGINT_Word, (ISC_BIGINT *a, uintptr w), (a, w), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Mtp_BIGINT_Word, (ISC_BIGINT *a, uintptr w), (a, w), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Generate_BIGINT_Prime_Ex, (ISC_BIGINT *prime, int bits, ISC_BIGINT_POOL *pool), (prime, bits, pool), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( ISC_STATUS, ISC_Generate_BIGINT_Prime, (ISC_BIGINT *prime, int bits, ISC_BIGINT_POOL *pool, int alg_id), (prime, bits, pool, alg_id), ISC_ERR_GET_ADRESS_LOADLIBRARY );
	ISC_RET_LOADLIB_CRYPTO( int, ISC_Is_BIGINT_Prime_Ex, (const ISC_BIGINT *n, int iter, ISC_BIGINT_POOL *pool), (n, iter, pool), 0 );
	ISC_RET_LOADLIB_CRYPTO( int, ISC_Is_BIGINT_Prime, (const ISC_BIGINT *n, int iter, ISC_BIGINT_POOL *pool, int alg_id), (n, iter, pool, alg_id), 0 );

#endif

#ifdef  __cplusplus
}
#endif

#endif /*HEADER_BIGINT_H*/
