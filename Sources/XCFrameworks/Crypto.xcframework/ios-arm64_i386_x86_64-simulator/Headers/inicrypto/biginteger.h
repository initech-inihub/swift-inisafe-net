
/*!
* \file biginteger.h
* \brief
* POSITIVE INTEGER를 다루는 Big Integer 타입과 관련 연산을 정의
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

#define ISC_BIGINT_POOL_SIZE 8 /*!<  ISC_BIGINT_POOL 초기 할당 갯수 */

	/*!
	* \brief
	* BigInteger 구조체
	*/
	struct isc_big_integer_st
	{
		uintptr *data; /*!< Big Integer 데이터*/
		int index;   /*!< Big Integer Array의 Index*/
		int length;  /*!< Big Integer Array의 길이*/
		int status;  /*!< Big Integer 구조체의 현재 상태*/
	};

	/*!
	* \brief
	* BigInteger Montgomery multiplication algorithms 구조체
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
	* BigInteger Pool Item 구조체
	*/
	struct isc_big_integer_pool_item_st
	{
		ISC_BIGINT vals[ISC_BIGINT_POOL_SIZE + 1];
		struct isc_big_integer_pool_item_st *prev, *next;
	};

	/*!
	* \brief
	* BigInteger Pool 구조체
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
	* ISC_BIGINT_POOL 에서 사용된 ISC_BIGINT 반환
	* \param pool
	* 사용할 ISC_BIGINT_POOL
	* \param num
	* 반환될 ISC_BIGINT 갯수
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/
ISC_INTERNAL ISC_STATUS isc_Release_BIGINT_POOL(ISC_BIGINT_POOL *pool, unsigned int num);


#define ISC_BIGINT_NEW			0x01  /*!<  ISC_BIGINT가 메모리 할당 됨*/
#define ISC_BIGINT_HAS_DATA		0x02  /*!<  ISC_BIGINT가 실제 데이터를 저장하고 있음*/
#define ISC_BIGINT_INIT			0x04  /*!<  ISC_BIGINT가 초기화 됨*/

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
	* ISC_BIGINT의 바이트 배열 길이를 구함
	* \param bInt
	* 바이트 배열의 길이를 구할 ISC_BIGINT
	* \returns
	* 바이트 배열의 길이
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
	* 입력 구조체를 입력받은 워드까지 확장 후 1로 만드는 함수
	* ISC_BIGINT 구조체
	* \param words
	* 확장할 워드 길이
	* \returns
	* -# ISC_BIGINT 구조체 : 성공
	* -# NULL : 실패
	*/
ISC_INTERNAL ISC_BIGINT *isc_Set_BIGINT_One_Ex(ISC_BIGINT *ret, int words);

	/*!
	* \brief
	* 입력 구조체를 입력받은 워드까지 확장 후 0으로 만드는 함수
	* \param ret
	* ISC_BIGINT 구조체
	* \param words
	* 확장할 워드 길이
	* \returns
	* -# ISC_BIGINT 구조체 : 성공
	* -# NULL : 실패
	*/
ISC_INTERNAL ISC_BIGINT *isc_Set_BIGINT_Zero_Ex(ISC_BIGINT *ret, int words);

	/*!
	* \brief
	* ISC_BIGINT_MONT 구조체의 메모리 할당
	* \returns
	* ISC_BIGINT_MONT 구조체
	*/
ISC_INTERNAL ISC_BIGINT_MONT *isc_New_BIGINT_MONT();

	/*!
	* \brief
	* ISC_BIGINT_MONT 구조체를 Reset
	* \param mont
	* Reset할 ISC_BIGINT_MONT
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/
ISC_INTERNAL ISC_STATUS isc_Init_BIGINT_MONT(ISC_BIGINT_MONT *mont);

	/*!
	* \brief
	* ISC_BIGINT_MONT 메모리 해제 함수
	* \param mont
	* 메모리 해제할 ISC_BIGINT_MONT
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/

ISC_INTERNAL ISC_STATUS isc_Free_BIGINT_MONT(ISC_BIGINT_MONT *mont);
ISC_INTERNAL int isc_Get_BIGINT_Bits_Word(uintptr l);

ISC_INTERNAL int isc_Cmp_BIGINT_Words(const uintptr *a, const uintptr *b, int n);
	/*!
	* \brief
	* ISC_BIGINT a와 b의 최대공약수(GCD)를 구함
	* \param ret
	* 결과값(최대공약수) ISC_BIGINT 구조체 포인터
	* \param a
	* ISC_BIGINT 구조체 포인터 a
	* \param b
	* ISC_BIGINT 구조체 포인터 b
	* \param pool
	* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/
ISC_INTERNAL ISC_STATUS isc_Gcd_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT n 상에서의 ISC_BIGINT a의 역원(inverse)를 구함, ret이 NULL경우 내부적으로 메모리 할당
	* \param ret
	* 결과값(역원) ISC_BIGINT 구조체 포인터
	* \param a
	* 역원을 구하고자 하는 ISC_BIGINT 구조체 포인터
	* \param n
	* Modulas ISC_BIGINT 구조체 포인터
	* \param pool
	* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/
ISC_API ISC_STATUS ISC_Mod_Inverse_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *n, ISC_BIGINT_POOL *pool);
	/*!
	* \brief
	* ISC_BIGINT a와 ISC_BIGINT b의 Divide 연산 (rem = m % d)
	* \param ret
	* 결과가 저장될 ISC_BIGINT 구조체 포인터, 메모리 할당이 되어 있어야 함
	* \param m
	* 나누어 질 값
	* \param d
	* 나눌 수* \param pool
	* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
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
	* ISC_BIGINT_POOL 초기화 함수
	* \param pool
	* 초기화할 ISC_BIGINT_POOL
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/
ISC_INTERNAL ISC_STATUS isc_Init_BIGINT_Pool(ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT_POOL 구조체의 메모리 할당
	* \returns
	* ISC_BIGINT_POOL 구조체
	*/
	ISC_API ISC_BIGINT_POOL* ISC_New_BIGINT_Pool();

	/*!
	* \brief
	* ISC_BIGINT_POOL 메모리 해제 함수
	* \param pool
	* 메모리 해제할 ISC_BIGINT_POOL
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/
	ISC_API ISC_STATUS ISC_Free_BIGINT_Pool(ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT_POOL의 데이터를 0으로 초기화
	* \param pool
	* 초기화할 ISC_BIGINT_POOL
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/
	ISC_API ISC_STATUS ISC_Clear_BIGINT_Pool(ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT_POOL 사용 시작 명령 함수
	* 함수가 호출된 이후에 ISC_Get_BIGINT_Pool() 함수를 사용하고 ISC_Finish_BIGINT_Pool(pool) 함수를 통해 반환한다
	* \param pool
	* 사용할 ISC_BIGINT_POOL
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_START_BIGINT_POOL^ISC_ERR_NULL_INPUT : NULL 입력값 입력
	*/
	ISC_API ISC_STATUS ISC_Start_BIGINT_Pool(ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT_POOL 사용 종료 명령 함수
	* ISC_Start_BIGINT_Pool(pool) 호출 이후로 ISC_Get_BIGINT_Pool()를 통해 얻은 객체를 Pool에 반환한다.
	* \param pool
	* 사용할 ISC_BIGINT_POOL
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_FINISH_BIGINT_POOL^ISC_ERR_NULL_INPUT : NULL 입력값 입력
	*/
	ISC_API ISC_STATUS ISC_Finish_BIGINT_Pool(ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT_POOL 에서 ISC_BIGINT를 얻는다
	* \param pool
	* 사용할 ISC_BIGINT_POOL
	* \returns
	* ISC_BIGINT 구조체
	*/
	ISC_API ISC_BIGINT* ISC_Get_BIGINT_Pool(ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT_POOL 에서 사용된 ISC_BIGINT 반환
	* \param pool
	* 사용할 ISC_BIGINT_POOL
	* \param num
	* 반환될 ISC_BIGINT 갯수
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/

	/*!
	* \brief
	* ISC_BIGINT 구조체의 메모리 할당
	* \returns
	* ISC_BIGINT 구조체
	*/
	ISC_API ISC_BIGINT *ISC_New_BIGINT(void);

	/*!
	* \brief
	* ISC_BIGINT 메모리 해제 함수
	* \param bInt
	* 메모리 해제할 ISC_BIGINT
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/
	ISC_API ISC_STATUS ISC_Free_BIGINT(ISC_BIGINT *bInt);


	/*!
	* \brief
	* ISC_BIGINT 구조체를 Reset
	* \param bInt
	* Reset할 ISC_BIGINT
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/
	ISC_API ISC_STATUS ISC_Init_BIGINT(ISC_BIGINT *bInt);

	/*!
	* \brief
	* ISC_BIGINT의 데이터를 0으로 초기화
	* \param bInt
	* 초기화 할 ISC_BIGINT
	*/
	ISC_API void ISC_Clear_BIGINT(ISC_BIGINT *bInt);

	/*!
	* \brief
	* 헥사 스트링의 char 배열을 입력하여, ISC_BIGINT 구조체를 생성
	* \param hex_arr
	* 변환될 헥사 스트링의 char 배열
	* \returns
	* -# 생성된 ISC_BIGINT 구조체 포인터 : Success
	* -# NULL : 실패
	*/
	ISC_API ISC_BIGINT* ISC_HEX_To_BIGINT(const char *hex_arr);

	/*!
	* \brief
	* ISC_BIGINT의 내용을 헥사 스트링의 char 배열로 변환
	* \param bInt
	* 변환될 ISC_BIGINT 구조체 포인터
	* \returns
	* -# 데이터가 저장될 헥사 스트링의 char 배열 포인터 : Success
	* -# NULL : 실패
	*/
	ISC_API char* ISC_BIGINT_To_HEX(const ISC_BIGINT *bInt);

	/*!
	* \brief
	* ISC_BIGINT의 내용을 10진수의 char 배열로 변환
	* \param bInt
	* 변환될 ISC_BIGINT 구조체 포인터
	* \returns
	* -# 데이터가 저장될 10진수 스트링의 char 배열 포인터 : Success
	* -# NULL : 실패
	*/
	ISC_API char* ISC_BIGINT_To_DEC(const ISC_BIGINT *bInt);

	/*!
	* \brief
	* ISC_BIGINT 데이터의 bits 단위 길이를 구함
	* \param bInt
	* ISC_BIGINT 구조체 포인터
	* \returns
	* -# bits 단위 길이
	*/
	ISC_API int ISC_Get_BIGINT_Bits_Length(const ISC_BIGINT *bInt);
	
	/*!
	* \brief
	* ISC_BIGINT 데이터의 n번째 비트가 1인지 판단
	* \param bInt
	* ISC_BIGINT 구조체 포인터
	* \param n
	* Bits Index
	* \returns
	* -# 1 : n번째 비트가 1
	* -# 0 : n번째 비트가 0
	*/
	ISC_API int ISC_Is_BIGINT_Bit_Set(const ISC_BIGINT *bInt, int n);

	/*!
	* \brief
	* ISC_BIGINT 데이터의 n 번째 비트를 1로 설정
	* \param bInt
	* ISC_BIGINT 구조체 포인터
	* \param n
	* 비트를 설정할 인덱스
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_SET_BIGINT_BIT^ISC_ERR_NULL_INPUT : NULL 입력값 입력
	* -# LOCATION^ISC_F_SET_BIGINT_BIT^ISC_ERR_EXPAND_BIGINT_WORD : EXPAND BIGINT WORD 연산 실패
	*/
	ISC_API ISC_STATUS ISC_Set_BIGINT_Bit(ISC_BIGINT *bInt, int n);

	/*!
	* \brief
	* ISC_BIGINT 데이터에 unsigned long 타입 자료를 입력
	* \param bInt
	* ISC_BIGINT 구조체 포인터
	* \param w
	* 입력할 데이터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/
	ISC_API ISC_STATUS	ISC_Set_BIGINT_Word(ISC_BIGINT *bInt, uintptr w);

	/*!
	* \brief
	* ISC_BIGINT 데이터의 실제 정수를 반환
	* \param bInt
	* ISC_BIGINT 구조체 포인터
	* \returns
	* -# 4 bytes : 길이의 데이터
	* -# 0xFFFFFFFF : ISC_BIGINT가 4 바이트 이상의 데이터를 담고 있을 경우
	* -# 0 : Fail
	*/
	ISC_API uintptr ISC_Get_BIGINT_Word(const ISC_BIGINT *bInt);

ISC_INTERNAL ISC_STATUS isc_Left_Shift_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, int n);
ISC_INTERNAL ISC_STATUS isc_Right_Shift_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, int n);

	/*!
	* \brief
	* ISC_BIGINT from 의 정보와 데이터를 ISC_BIGINT to에 복사
	* \param to
	* ISC_BIGINT 구조체 포인터 Destination
	* \param from
	* ISC_BIGINT 구조체 포인터 Source
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/
	ISC_API ISC_STATUS ISC_Copy_BIGINT(ISC_BIGINT *to, const ISC_BIGINT *from);

	/*!
	* \brief
	* ISC_BIGINT a와 b의 내용을 Swap
	* \param a
	* ISC_BIGINT 구조체 포인터
	* \param b
	* ISC_BIGINT 구조체 포인터
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	ISC_API void ISC_Swap_BIGINT(ISC_BIGINT *a, ISC_BIGINT *b);

	/*!
	* \brief
	* ISC_BIGINT bInt의 정보와 데이터가 복사된 새로운 ISC_BIGINT 포인터 반환
	* \param bInt
	* ISC_BIGINT 구조체 포인터
	* \returns
	* -# 메모리 할당된 ISC_BIGINT 구조체 포인터
	* -# NULL(0) : Fail
	*/
	ISC_API ISC_BIGINT *ISC_Dup_BIGINT(const ISC_BIGINT *bInt);

	/*!
	* \brief
	* 두개의 ISC_BIGINT 의 크기를 비교
	* \param a
	* ISC_BIGINT 구조체 포인터
	* \param b
	* ISC_BIGINT 구조체 포인터
	* \returns
	* -# 1 : a > b
	* -# 0 : a = b
	* -# -1 : a < b
	*/
	ISC_API int ISC_Cmp_BIGINT(const ISC_BIGINT *a, const ISC_BIGINT *b);

	/*!
	* \brief
	* 바이너리 데이터를 ISC_BIGINT로 변환. 입력될 bInt가 NULL일 경우 새롭게 포인터를 메모리 할당 후 반환
	* \param bin
	* Bianry 데이터
	* \param len
	* Binary 데이터의 길이
	* \param bInt
	* ISC_BIGINT 구조체 포인터
	* Binary
	* 데이터가 저장될 ISC_BIGINT, NULL일 경우 내부적으로 메모리 할당
	* \returns
	* -# 결과가 저장된 ISC_BIGINT 구조체 포인터
	* -# NULL(0) : Fail
	*/
	ISC_API ISC_BIGINT *ISC_Binary_To_BIGINT(const uint8 *bin, int len, ISC_BIGINT *bInt);

	/*!
	* \brief
	* ISC_BIGINT 구조체를 uint8형 binary로 변환, uint8형 binary는 메모리가 할당 되어 있어야 함. 2의 보수 처리 됨. binary의 길이는 ISC_GET_BIGINT_BYTES_UNSIGNED_LENGTH(ISC_BIGINT*) 로 구할 수 있음
	* \param bInt
	* ISC_BIGINT 구조체 포인터
	* \param bin
	* Binary 데이터 버퍼
	* \returns
	* -# 결과가 저장된 Binary의 길이
	*/
	ISC_API int ISC_BIGINT_To_Binary_Unsigned(const ISC_BIGINT *bInt, uint8 *bin);

	/*!
	* \brief
	* ISC_BIGINT 구조체를 uint8형 binary로 변환, uint8형 binary는 메모리가 할당 되어 있어야 함. binary의 길이는 ISC_GET_BIGINT_BYTES_LENGTH(ISC_BIGINT*) 로 구할 수 있음
	* \param bInt
	* ISC_BIGINT 구조체 포인터
	* \param bin
	* Binary 데이터 버퍼
	* \returns
	* -# 결과가 저장된 Binary의 길이
	*/
	ISC_API int ISC_BIGINT_To_Binary(const ISC_BIGINT *bInt, uint8 *bin);

	/*!
	* \brief
	* 값이 1로 초기화된 ISC_BIGINT를 구함
	* \returns
	* -# 값이 1로 초기화된 ISC_BIGINT 포인터
	* -# NULL : Fail
	*/
	ISC_API const ISC_BIGINT *ISC_Value_One_BIGINT(void);

	/*!
	* \brief
	* 값이 0로 초기화된 ISC_BIGINT를 구함
	* \returns
	* -# 값이 0로 초기화된 ISC_BIGINT 포인터
	* -# NULL : Fail
	*/
	ISC_API const ISC_BIGINT *ISC_Value_Zero_BIGINT(void);

	/*!
	* \brief
	* ISC_BIGINT 를 Print
	* \param bInt
	* ISC_BIGINT 구조체 포인터
	*/
	ISC_API void ISC_Print_BIGINT(const ISC_BIGINT *bInt);

	/*!
	* \brief
	* ISC_BIGINT 를 dump
	* \param bInt
	* ISC_BIGINT 구조체 포인터
	* \returns
	* -# 결과값이 저장된 문자열 (외부에서 메모리 해제 필요 [ISC_MEM_FREE])
	* -# NULL : Fail
	*/
	ISC_API char* ISC_Dump_BIGINT(const ISC_BIGINT *bInt);

	/*!
	* \brief
	* ISC_BIGINT a와 ISC_BIGINT b의 Addition 연산 (ret = a + b)
	* \param ret
	* 결과가 저장될 ISC_BIGINT 구조체 포인터, 메모리 할당이 되어 있어야 함
	* \param a
	* ISC_BIGINT 구조체 포인터
	* \param b
	* ISC_BIGINT 구조체 포인터
	* \param pool
	* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/
	ISC_API ISC_STATUS ISC_Add_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT a와 ISC_BIGINT b의 Subtraction 연산(ret = a - b), 반드시 a는 b보다 커야 함(크기 비교 연산인 ISC_Cmp_BIGINT() 참조)
	* \param ret
	* 결과가 저장될 ISC_BIGINT 구조체 포인터, 메모리 할당이 되어 있어야 함
	* \param a
	* ISC_BIGINT 구조체 포인터
	* \param b
	* ISC_BIGINT 구조체 포인터
	* \param pool
	* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/
	ISC_API ISC_STATUS ISC_Sub_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT 그룹 내에서의 a와 ISC_BIGINT b의 Subtraction 연산(ret = (a - b) mod m), 항상 양수를 리턴함 예) (1 - 2) mod 7 = 6
	* \param ret
	* 결과가 저장될 ISC_BIGINT 구조체 포인터, 메모리 할당이 되어 있어야 함
	* \param a
	* ISC_BIGINT 구조체 포인터
	* \param b
	* ISC_BIGINT 구조체 포인터
	* \param m
	* ISC_BIGINT 구조체 포인터
	* \param pool
	* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_MOD_SUB_BIGINT^ISC_ERR_NULL_INPUT : NULL 입력값 입력
	* -# LOCATION^ISC_F_MOD_SUB_BIGINT^ISC_ERR_MALLOC : 동적 메모리 할당 실패
	*/
	ISC_API ISC_STATUS ISC_Mod_Sub_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT a와 ISC_BIGINT b의 Divide 연산 (num = divisor x dir_ret + rm)
	* \param div_ret
	* 몫이 저장될 ISC_BIGINT 구조체 포인터
	* \param rm
	* 나머지 값이 저장될 ISC_BIGINT 구조체 포인터
	* \param num
	* 나누어 질 값
	* \param divisor
	* 나눌 수
	* \param pool
	* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_DIV_BIGINT^ISC_ERR_INTERNAL : 내부연산 실패
	* -# LOCATION^ISC_F_DIV_BIGINT^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL 연산 실패
	* -# LOCATION^ISC_F_DIV_BIGINT^ISC_ERR_MALLOC : 동적 메모리 할당 실패
	* -# LOCATION^ISC_F_DIV_BIGINT^ISC_ERR_LEFT_SHIFT_BIGINT_FAIL : LEFT SHIFT BIGINT 연산 실패
	*/
	ISC_API ISC_STATUS ISC_Div_BIGINT(ISC_BIGINT *div_ret, ISC_BIGINT *rm, const ISC_BIGINT *num, const ISC_BIGINT *divisor, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT a와 ISC_BIGINT b의 Multiplication 연산 (ret = a x b)
	* \param ret
	* 결과가 저장될 ISC_BIGINT 구조체 포인터, 메모리 할당이 되어 있어야 함
	* \param a
	* ISC_BIGINT 구조체 포인터
	* \param b
	* ISC_BIGINT 구조체 포인터
	* \param pool
	* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/
	ISC_API ISC_STATUS ISC_Mtp_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT a와 ISC_BIGINT b의 Sqaure 연산 (ret = a^2)
	* \param ret
	* 결과가 저장될 ISC_BIGINT 구조체 포인터, 메모리 할당이 되어 있어야 함
	* \param a
	* ISC_BIGINT 구조체 포인터
	* \param pool
	* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_SQR_BIGINT^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL 연산 실패
	* -# LOCATION^ISC_F_SQR_BIGINT^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL 연산 실패
	* -# LOCATION^ISC_F_SQR_BIGINT^ISC_ERR_EXPAND_BIGINT_WORD : EXPAND BIGINT WORD 연산 실패
	* -# LOCATION^ISC_F_SQR_BIGINT^ISC_ERR_COPY_BIGINT_FAIL : COPY BIGINT 연산 실패
	*/
	ISC_API ISC_STATUS ISC_Sqr_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT a와 ISC_BIGINT b의 m 상에서의 지수승(Exponent) 연산 (ret = a^p mod m)
	* \param ret
	* 결과가 저장될 ISC_BIGINT 구조체 포인터, 메모리 할당이 되어 있어야 함
	* \param a
	* Base ISC_BIGINT 구조체 포인터
	* \param p
	* Exponent ISC_BIGINT 구조체 포인터
	* \param m
	* m ISC_BIGINT 구조체 포인터
	* \param pool
	* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_SET_BIGINT_FAIL : SET BIGINT 연산 실패
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT 연산 실패
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_MOD_BIGINT_FAIL : MOD_BIGINT 연산 실패
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_MOD_MTP_BIGINT_FAIL : MOD MTP BIGINT 연산 실패
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL 연산 실패
	*/
	ISC_API ISC_STATUS ISC_Mod_Exp_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *p, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* 몽고메리 알고리즘을 이용한 ISC_BIGINT a와 ISC_BIGINT b의 m 상에서의 지수승(Exponent) 연산 (ret = a^p mod m)
	* \param ret
	* 결과가 저장될 ISC_BIGINT 구조체 포인터, 메모리 할당이 되어 있어야 함
	* \param a
	* Base ISC_BIGINT 구조체 포인터
	* \param p
	* Exponent ISC_BIGINT 구조체 포인터
	* \param m
	* m ISC_BIGINT 구조체 포인터
	* \param pool
	* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_MOD_EXP_MONT_BIGINT^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL 연산 실패
	* -# LOCATION^ISC_F_MOD_EXP_MONT_BIGINT^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL 연산 실패
	* -# LOCATION^ISC_F_MOD_EXP_MONT_BIGINT^ISC_ERR_MALLOC : 동적 메모리 할당 실패
	* -# LOCATION^ISC_F_MOD_EXP_MONT_BIGINT^ISC_ERR_SET_BIGINT_FAIL : SET BIGINT 연산 실패
	* -# LOCATION^ISC_F_MOD_EXP_MONT_BIGINT^ISC_ERR_MOD_BIGINT_FAIL : MOD BIGINT 연산 실패
	* -# LOCATION^ISC_F_MOD_EXP_MONT_BIGINT^ISC_ERR_BIGINT_TO_MONTGOMERY_FAIL : BIGINT TO MONTGOMERY 연산 실패
	* -# LOCATION^ISC_F_MOD_EXP_MONT_BIGINT^ISC_ERR_MOD_MUL_BIGINT_MONTGOMERY_FAIL : MOD MUL BIGINT MONTGOMERY 연산 실패
	* -# LOCATION^ISC_F_MOD_EXP_MONT_BIGINT^ISC_ERR_BIGINT_FROM_MONTGOMERY_FAIL : BIGINT FROM MONTGOMERY 연산 실패
	*/
	ISC_API ISC_STATUS ISC_Mod_Exp_Mont_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *p, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* Fixed-Windows 매커니즘이 적용된 ISC_BIGINT a와 ISC_BIGINT b의 m 상에서의 지수승(Exponent) 연산 (ret = a^p mod m)
	* \param ret
	* 결과가 저장될 ISC_BIGINT 구조체 포인터, 메모리 할당이 되어 있어야 함
	* \param a
	* Base ISC_BIGINT 구조체 포인터
	* \param p
	* Exponent ISC_BIGINT 구조체 포인터
	* \param m
	* m ISC_BIGINT 구조체 포인터
	* \param pool
	* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_SET_BIGINT_FAIL : SET BIGINT 연산 실패
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT 연산 실패
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_MOD_BIGINT_FAIL : MOD_BIGINT 연산 실패
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_MOD_MTP_BIGINT_FAIL : MOD MTP BIGINT 연산 실패
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL 연산 실패
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_MALLOC : 동적 메모리 할당 실패
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_COPY_BIGINT_FAIL : COPY BIGINT 연산 실패
	* -# LOCATION^ISC_F_MOD_EXP_BIGINT^ISC_ERR_MOD_MUL_BIGINT_MONTGOMERY_FAIL : MOD MUL BIGINT MONTGOMERY 연산 실패
	*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Exp_Mont_BIGINT_FixedWindow(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *p, const ISC_BIGINT *m, ISC_BIGINT_POOL *in_pool);

	/*!
	* \brief
	* 난수 ISC_BIGINT 를 생성 (DRBG 사용)
	* \param rnd
	* 난수로 생성된 ISC_BIGINT 구조체 포인터
	* \param bits
	* 생성된 ISC_BIGINT의 bit size
	* \param top
	* 최상위 비트을 값을 설정하는 값
	* -# -1 : 난수 그대로 둔다. (최상위 비트가 0이 될수도 있다.)
	* -# 0 : 최상위 비트를 1로 설정
	* -# 1 : 최상위 2비트를 1로 설정
	* \param bottom
	* 생성할 난수 ISC_BIGINT의 홀수 여부
	* \param pool
	* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_RAND_BIGINT_EX^ISC_ERR_MEM_ALLOC : 동적 메모리 할당 실패
	* -# LOCATION^ISC_F_RAND_BIGINT_EX^ISC_ERR_GET_RAND_FAIL : 난수생성 실패
	* -# LOCATION^ISC_F_RAND_BIGINT_EX^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY -> BIGINT 변환 실패
	*/
	ISC_API ISC_STATUS ISC_Rand_BIGINT_Ex(ISC_BIGINT *rnd, int bits, int top, int bottom, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* 난수 ISC_BIGINT 를 생성 (PRNG 사용)
	* \param rnd
	* 난수로 생성된 ISC_BIGINT 구조체 포인터
	* \param bits
	* 생성된 ISC_BIGINT의 bit size
	* \param top
	* 최상위 비트을 값을 설정하는 값
	* -# -1 : 난수 그대로 둔다. (최상위 비트가 0이 될수도 있다.)
	* -# 0 : 최상위 비트를 1로 설정
	* -# 1 : 최상위 2비트를 1로 설정
	* \param bottom
	* 생성할 난수 ISC_BIGINT의 홀수 여부
	* \param pool
	* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
	* \param alg_id
	* random generator(prng)에서 사용될 알고리즘
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/
	ISC_API ISC_STATUS ISC_Rand_BIGINT(ISC_BIGINT *rnd, int bits, int top, int bottom, ISC_BIGINT_POOL *pool,int alg_id);

	/*!
	* \brief
	* ISC_BIGINT a와 ISC_BIGINT b의 m 상에서의 Multiplication 연산 (ret = a x b mod m)
	* \param ret
	* 결과가 저장될 ISC_BIGINT 구조체 포인터, 메모리 할당이 되어 있어야 함
	* \param a
	* ISC_BIGINT 구조체 포인터
	* \param b
	* ISC_BIGINT 구조체 포인터
	* \param m
	* m ISC_BIGINT 구조체 포인터
	* \param pool
	* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/
	ISC_API ISC_STATUS ISC_Mod_Mtp_BIGINT(ISC_BIGINT *ret, const ISC_BIGINT *a, const ISC_BIGINT *b, const ISC_BIGINT *m, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* ISC_BIGINT a와 uintptr w의 Divide 연산 (rem = m % d)
	* \param a
	* 나누어 질 값
	* \param w
	* 나눌 수
	* \returns
	* -# 몫 값 : Success
	* -# -1 : 실패
	*/
	ISC_API uintptr ISC_Mod_BIGINT_Word(ISC_BIGINT *a, uintptr w);

	/*!
	* \brief
	* ISC_BIGINT a와 uintptr w의 Divide 연산 (num = divisor x dir_ret + rm)
	* \param a
	* 나누어 질 값
	* \param w
	* 나눌 수
	* \returns
	* -# 나머지 값 : Success
	* -# -1 : 실패
	*/
	ISC_API uintptr ISC_Div_BIGINT_Word(ISC_BIGINT *a, uintptr w);

	/*!
	* \brief
	* ISC_BIGINT a와 uintptr w의 Addition 연산 (ret = a + b)
	* \param a
	* ISC_BIGINT 구조체 포인터 (결과값)
	* \param w
	* 더해질 값
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/
	ISC_API ISC_STATUS ISC_Add_BIGINT_Word(ISC_BIGINT *a, uintptr w);

	/*!
	* \brief
	* ISC_BIGINT a와 uintptr w의 Subtraction 연산(ret = a - b)
	* \param a
	* ISC_BIGINT 구조체 포인터 (결과값)
	* \param w
	* 밸 값
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/
	ISC_API ISC_STATUS ISC_Sub_BIGINT_Word(ISC_BIGINT *a, uintptr w);

	/*!
	* \brief
	* ISC_BIGINT a와 uintptr w의 Multiplication 연산 (ret = a x b)
	* \param a
	* ISC_BIGINT 구조체 포인터 (결과값)
	* \param w
	* 곱해질 값
	* \returns
	* -# ISC_SUCCESS : Success
	* -# others : 실패 (에러코드)
	*/
	ISC_API ISC_STATUS ISC_Mtp_BIGINT_Word(ISC_BIGINT *a, uintptr w);

	/*!
	* \brief
	* bits 수 만큼의 prime number를 생성
	* \param prime
	* 결과가 저장될 ISC_BIGINT 구조체 포인터, 메모리 할당이 되어 있어야 함
	* \param bits
	* prime의 비트 수
	* \param pool
	* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_GENERATE_BIGINT_PRIME^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL 연산 실패
	* -# LOCATION^ISC_F_GENERATE_BIGINT_PRIME^ISC_ERR_RAND_BIGINT_FAIL : RAND BIGINT 연산 실패
	* -# LOCATION^ISC_F_GENERATE_BIGINT_PRIME^ISC_ERR_ADD_BIGINT_FAIL : ADD BIGINT 연산 실패
	* -# LOCATION^ISC_F_GENERATE_BIGINT_PRIME^ISC_ERR_RIGHT_SHIFT_BIGINT_FAIL : RIGHT SHIFT BIGINT 연산 실패
	*/
	ISC_API ISC_STATUS ISC_Generate_BIGINT_Prime_Ex(ISC_BIGINT *prime, int bits, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* bits 수 만큼의 prime number를 생성
	* \param prime
	* 결과가 저장될 ISC_BIGINT 구조체 포인터, 메모리 할당이 되어 있어야 함
	* \param bits
	* prime의 비트 수
	* \param pool
	* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
	* \param alg_id
	* random generator(prng)에서 사용될 알고리즘
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_GENERATE_BIGINT_PRIME^ISC_ERR_START_BIGINT_POOL_FAIL : START BIGINT POOL 연산 실패
	* -# LOCATION^ISC_F_GENERATE_BIGINT_PRIME^ISC_ERR_GET_BIGINT_POOL_FAIL : GET BIGINT POOL 연산 실패
	* -# LOCATION^ISC_F_GENERATE_BIGINT_PRIME^ISC_ERR_RAND_BIGINT_FAIL : RAND BIGINT 연산 실패
	* -# LOCATION^ISC_F_GENERATE_BIGINT_PRIME^ISC_ERR_ADD_BIGINT_FAIL : ADD BIGINT 연산 실패
	* -# LOCATION^ISC_F_GENERATE_BIGINT_PRIME^ISC_ERR_RIGHT_SHIFT_BIGINT_FAIL : RIGHT SHIFT BIGINT 연산 실패
	*/
	ISC_API ISC_STATUS ISC_Generate_BIGINT_Prime(ISC_BIGINT *prime, int bits, ISC_BIGINT_POOL *pool, int alg_id);

	/*!
	* \brief
	* 입력된 ISC_BIGINT n이 소수 인지 판정하는 함수(Miller-Rabin Test)
	* \param n
	* 소수인 지 판정할 ISC_BIGINT
	* \param iter
	* prime의 비트 수,  Miller-Rabin의 Error 확률 ~ 1/(4^iter)
	* \param pool
	* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
	* \returns
	* -# 1 : Prime
	* -# 0 : Fail
	* -# -1 : Composite
	*/
	ISC_API int ISC_Is_BIGINT_Prime_Ex(const ISC_BIGINT *n, int iter, ISC_BIGINT_POOL *pool);

	/*!
	* \brief
	* 입력된 ISC_BIGINT n이 소수 인지 판정하는 함수(Miller-Rabin Test)
	* \param n
	* 소수인 지 판정할 ISC_BIGINT
	* \param iter
	* prime의 비트 수,  Miller-Rabin의 Error 확률 ~ 1/(4^iter)
	* \param pool
	* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
	* \param alg_id
	* random generator(prng)에서 사용될 알고리즘
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
