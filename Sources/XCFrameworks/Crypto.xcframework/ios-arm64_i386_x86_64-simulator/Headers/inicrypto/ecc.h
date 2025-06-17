/*!
* \file ecc.h
* \brief ecc 헤더파일(ecc 알고리즘)
* \author
* Copyright (c) 2013 by \<INITech\>
*/

#ifndef HEADER_ECC_H
#define HEADER_ECC_H

#ifdef ISC_NO_ECC
#error ECC is disabled.
#endif /* ISC_NO_ECC */

#include "biginteger.h"
#include "digest.h"
#include "foundation.h"
#include "ecpoint.h"
#include "ecurve.h"

struct isc_ecc_key_st
{
	ISC_ECURVE *curve;				/*!< curve 값 */
	ISC_ECPOINT *y;					/*!< 공개 파라미터 y = g^x*/
	ISC_BIGINT *x;					/*!< 개인키 x */
	int is_private;					/*!< 예약됨. 사용안함 */
};	

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_ECC_KEY_UNIT 구조체의 메모리 할당
* \returns
* ISC_ECC_KEY_UNIT 구조체
*/
ISC_API ISC_ECC_KEY_UNIT *ISC_New_ECC_Key(void);

/*!
* \brief
* ISC_ECC_KEY_UNIT 메모리 해제 함수
* \param unit
* 메모리 해제할 ISC_ECC_KEY_UNIT
*/
ISC_API void ISC_Free_ECC_Key(ISC_ECC_KEY_UNIT *unit);

/*!
* \brief
* ISC_ECC_KEY_UNIT 메모리 초기화 함수
* \param unit
* 초기화 할 ISC_ECC_KEY_UNIT
*/
ISC_API void ISC_Clean_ECC_Key(ISC_ECC_KEY_UNIT *unit);

/*!
* \brief
* ISC_ECC_KEY_UNIT 파라메터 셋팅 함수
* \param unit
* 도메인을 설정할 ISC_ECC_KEY_UNIT 구조체 포인터
* \param field_id
* 입력값 curve id (ISC_ECC_P_224, ISC_ECC_P_256, ISC_ECC_K_233, ISC_ECC_K_283)
* \param x
* 입력값 개인키
* \param y
* 입력값 공개키
* \returns
* -# INI_SUCCES : 성공
* -# ISC_L_ECC^ISC_F_SET_ECC_KEY_PRAMS_EX^ISC_ERR_NULL_INPUT : NULL값 입력
* -# ISC_L_ECC^ISC_F_SET_ECC_KEY_PRAMS_EX^ISC_ERR_SET_ECC_KEY_PARAMS_EX : 커브 파라메터 설정 에러
* -# ISC_L_ECC^ISC_F_SET_ECC_KEY_PRAMS_EX^ISC_ERR_MEM_ALLOC : 메모리 동적 할당 에러
* -# ISC_L_ECC^ISC_F_SET_ECC_KEY_PRAMS_EX^ISC_ERR_COPY_BIGINT_FAIL : COPY BIGINT 에러
*/
ISC_API ISC_STATUS ISC_Set_ECC_Key_Params(ISC_ECC_KEY_UNIT *unit, const int field_id, const ISC_BIGINT* x, const ISC_ECPOINT* y);

/*!
* \brief
* ISC_ECC_KEY_UNIT 파라메터 셋팅 함수
* \param unit
* 도메인을 설정할 ISC_ECC_KEY_UNIT 구조체 포인터
* \param curve
* 입력값 curve
* \param x
* 입력값 개인키
* \param y
* 입력값 공개키
* \returns
* INI_SUCCES : 성공
* ISC_F_SET_ECC_KEY_PRAMS^ISC_ERR_NULL_INPUT
*/
ISC_API ISC_STATUS ISC_Set_ECC_Key_Params_Ex(ISC_ECC_KEY_UNIT *unit, const ISC_ECURVE* curve, const ISC_BIGINT* x, const ISC_ECPOINT* y);

/*!
* \brief
* 타원곡선의 도메인을 이용한 공개키 검증 (TTA 표준 준수)
* \param key
* 입력되는 도메인 변수(커브)는 설정되어 있어야함. 공개키가 유효한지 검증함.
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_API ISC_STATUS ISC_Validate_ECC_Pub_Key(ISC_ECURVE *curve, ISC_ECPOINT *Q);

/*
* \brief
* ISC_ECC_KEY_UNIT b를 a에 복사
* \param a
* target ISC_ECC_KEY_UNIT
* \param b
* source ISC_ECC_KEY_UNIT
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_INTERNAL ISC_STATUS isc_Copy_ECC_Key(ISC_ECC_KEY_UNIT *a, const ISC_ECC_KEY_UNIT *b);

/*!
* \brief
* 타원곡선 정보를 이용한 Fixed-base comb ECSM 연산 함수
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param x
* 타원곡선상에서 곱셈 연산할 biginteger
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Mtp_ECC_Fbc(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_BIGINT *x);

/*!
* \brief
* 타원곡선 정보를 이용한 Double-and-Add ECSM 연산 함수
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
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Mtp_ECC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* 타원곡선 정보를 이용한 Montgomery ladder ECSM 연산 함수
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
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Mtp_ECC_Mont(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_BIGINT *x);

/*!
* \brief
* 타원곡선 정보를 이용한 General ECADD 연산 함수
* \param out
* 리턴될 좌표
* \param curve
* 타원곡선
* \param a
* 타원곡선상에서 덧셈 연산할 좌표
* \param x
* 타원곡선상에서 덧셈 연산할 좌표
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Add_ECC(ISC_ECPOINT *out, ISC_ECURVE *curve, ISC_ECPOINT *a, ISC_ECPOINT *b);

/*!
* \brief
* 타원곡선 정보를 이용한 유한체 역원 연산 함수
* \param out
* 리턴될 biginteger
* \param curve
* 타원곡선
* \param a
* 역원 연산할 biginteger
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Inverse_ECC(ISC_BIGINT *out, ISC_ECURVE *curve, ISC_BIGINT *a, ISC_BIGINT_POOL *pool);

/*!
* \brief
* 타원곡선 정보를 이용한 유한체 곱셈 연산 함수
* \param out
* 리턴될 biginteger
* \param curve
* 타원곡선
* \param a
* 곱셈 연산할 biginteger
* \param b
* 곱셈 연산할 biginteger
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Mtp_ECC(ISC_BIGINT *out, ISC_ECURVE *curve, ISC_BIGINT *a, ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* 타원곡선 정보를 이용한 유한체 덧셈 연산 함수
* \param out
* 리턴될 biginteger
* \param curve
* 타원곡선
* \param a
* 덧셈 연산할 biginteger
* \param b
* 덧셈 연산할 biginteger
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_Add_ECC(ISC_BIGINT *out, ISC_ECURVE *curve, ISC_BIGINT *a, ISC_BIGINT *b, ISC_BIGINT_POOL *pool);

/*!
* \brief
* 타원곡선 정보를 이용한 유한체 감산 연산 함수
* \param out
* 리턴될 biginteger
* \param curve
* 타원곡선
* \param a
* 감산 연산할 biginteger
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Mod_ECC(ISC_BIGINT *out, ISC_ECURVE *curve, ISC_BIGINT *a, ISC_BIGINT_POOL *pool);

/*!
* \brief
* 타원곡선의 도메인을 이용한 키쌍 생성 (TTA 표준 준수)
* \param key
* 입력되는 도메인 변수(커브)는 설정되어 있어야함. 개인키, 공개키를 생성해서 저장됨
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Generate_ECC_Key_Pair(ISC_ECC_KEY_UNIT *key);

#ifndef ISC_CRYPTO_VS_TEST /* IUT 테스트 할때만 외부함수로 쓴다. */

/*!
* \brief
* 타원곡선의 도메인을 이용한 공개키 생성 (TTA 표준 준수)
* \param curve
* 입력값 curve
* \param d
* 입력값 개인키
* \param in_pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \param out
* 입력된 개인키와 커브를 이용하여 공개키를 생성해서 저장
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Generate_ECC_Pub_Key(ISC_ECURVE *curve, ISC_BIGINT *d, ISC_BIGINT_POOL *in_pool, ISC_ECPOINT *out);
#else

ISC_API ISC_STATUS ISC_Generate_ECC_Pub_Key(ISC_ECURVE *curve, ISC_BIGINT *d, ISC_BIGINT_POOL *in_pool, ISC_ECPOINT *out);

#endif

/*!
* \brief
* 타원곡선의 도메인을 이용한 개인키 생성 (TTA 표준 준수)
* \param curve
* 입력값 curve
* \param hash_id
* 개인키 생성시 사용되는 해시알고리즘
* \param in_oui
* 입력값 optional user input값
* \param in_oui_len 
* 입력값 in_oui의 길이
* \param in_xkey
* 입력값 xkey값
* \param in_xkey_len 
* in_xkey의 길이
* \param in_pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \param out
* 출력값 입력된 커브를 이용하여 개인키를 생성
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS isc_Generate_ECC_Priv_Key(ISC_ECURVE *curve, int hash_id, uint8 *in_oui, int in_oui_len, uint8 *in_xkey, int in_xkey_len, ISC_BIGINT_POOL *in_pool, ISC_BIGINT *out);

/*!
* \brief
* 타원곡선의 도메인을 이용한 키쌍 생성 (NIST 표준 준수)
* \param key
* 입력되는 도메인 변수(커브)는 설정되어 있어야함. 개인키, 공개키를 생성해서 저장됨
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Generate_ECC_Key_Pair_NIST(ISC_ECC_KEY_UNIT *key);

/*!
* \brief
* 타원곡선의 도메인을 이용한 개인키 생성 (NIST 표준 준수)
* \param curve
* 입력값 curve
* \param in_pool
* 연산 효율을 위한 ISC_BIGINT_POOL 구조체 포인터
* \param out
* 출력값 입력된 커브를 이용하여 개인키를 생성
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS isc_Generate_ECC_Priv_Key_NIST(ISC_ECURVE *curve, ISC_BIGINT_POOL *in_pool, ISC_BIGINT *out);

/*!
* \brief
* 타원곡선의 도메인을 이용한 공개키 생성 (TTA 표준 준수)
* \param curve
* 입력값 curve
* \param d
* 입력값 개인키
* \param out
* 입력된 개인키와 커브를 이용하여 공개키를 생성해서 저장
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS ISC_Generate_ECC_Pub_Key_NIST(ISC_ECURVE *curve, ISC_BIGINT *d, ISC_ECPOINT *out);

/*!
* \brief
* 개인키 생성 및 서명에 사용되는 G-Function (TTA 표준 준수)
* \param alg_id
* 입력값 해시알고리즘
* \param seed
* 입력값 seed
* \param seedLen
* 입력값 seed의 길이(byte)
* \param size
* 입력값 출력되어야 할 값의 길이 (bit)
* \param out
* 연산된 결과값
* \returns
* -# ISC_SUCCESS : Success
* -# others : 실패 (에러코드)
*/
ISC_INTERNAL ISC_STATUS isc_ECC_G_Function(int alg_id, uint8* seed, int seedLen, int size, ISC_BIGINT* out);


#else

ISC_RET_LOADLIB_CRYPTO(ISC_ECC_KEY_UNIT*, ISC_New_ECC_Key, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_ECC_Key, (ISC_ECC_KEY_UNIT *unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_ECC_Key, (ISC_ECC_KEY_UNIT *unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_ECC_Key_Params, (ISC_ECC_KEY_UNIT *unit, const int field_id, const ISC_BIGINT* x, const ISC_ECPOINT* y), (unit,field_id,x,y), ISC_ERR_GET_ADRESS_LOADLIBRARY);
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_ECC_Key_Params_Ex, (ISC_ECC_KEY_UNIT *unit, const ISC_ECURVE* curve, const ISC_BIGINT* x, const ISC_ECPOINT* y), (unit,curve,x,y), ISC_ERR_GET_ADRESS_LOADLIBRARY);

#endif /* ISC_WIN_LOADLIBRARY_CRYPTO */

#ifdef __cplusplus
}
#endif

#endif /* HEADER_ECC_H */
